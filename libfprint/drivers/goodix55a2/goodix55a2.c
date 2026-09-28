/*
 * Goodix 27c6:55a2 driver for libfprint (experimental, milestone 0016a)
 *
 * Copyright (C) 2026 JonDGS
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Protocol facts come from the goodix-55a2-linux experiments 0005-0015
 * (https://github.com/JonDGS/goodix-55a2-linux), which build on
 * tlambertz/goodix-fingerprint-reversing and goodix-fp-linux-dev.
 *
 * Safety rules carried over from the reviewed Python pilot:
 *  - Only a fixed allow-list of command frames can be sent (see
 *    goodix55a2_send_cmd); TLS output is sent only as handshake records.
 *  - No PSK, firmware, config, reset or OTP command exists in this file.
 *  - The PSK is read from a root-only file (0016a dev mode) and never logged.
 *  - Every FDT arm (0x32/0x34) is paired with one 0x60 disarm on every exit
 *    path: event, timeout, error and deactivation.
 *  - Pixel data is never logged.
 */

#define FP_COMPONENT "goodix55a2"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "drivers_api.h"

/* 0016a development mode: the Windows-provisioned key, root-only. */
#ifndef GOODIX_55A2_PSK_DIR
#define GOODIX_55A2_PSK_DIR "/root/goodix-psk"
#endif
#define GOODIX_55A2_PSK_NAME "psk.bin"

#define EP_IN (0x02 | FPI_USB_ENDPOINT_IN)
#define EP_OUT (0x01 | FPI_USB_ENDPOINT_OUT)
#define OUT_CHUNK 64
#define IN_BUF 65536
#define MAX_FRAME 16384
#define CMD_TIMEOUT_MS 2000
#define STALE_WINDOW_MS 500
#define IMAGE_TIMEOUT_MS 5000
#define FDT_UP_TIMEOUT_MS 15000
#define HANDSHAKE_MAX_FRAMES 64

#define FLAG_CMD 0xa0
#define FLAG_TLS 0xb0
#define FLAG_TLS_DATA 0xb2

#define CMD_NOP 0x00
#define CMD_GET_IMAGE 0x20
#define CMD_FDT_DOWN 0x32
#define CMD_FDT_UP 0x34
#define CMD_FDT_MANUAL 0x36
#define CMD_SLEEP 0x60
#define CMD_FIRMWARE 0xa8
#define CMD_STATE 0xae
#define CMD_ACK 0xb0
#define CMD_REQUEST_TLS 0xd0
#define CMD_TLS_DONE 0xd4

#define FIRMWARE "GF3206_RTSEC_APP_10063"
#define PSK_LEN 32
#define IMAGE_PLAIN_LEN 14788
#define IMAGE_PACKED_LEN (IMAGE_PLAIN_LEN - 4)
#define IMG_W 176
#define IMG_H 56
#define IMG_PIX (IMG_W * IMG_H)
/* NBIS finds only 1-3 minutiae at native 176x56 (0016a enroll); enlarge
 * before matching, as egis0570 and elanspi do for small sensors. */
#define IMG_SCALE 3

/* Fixed payloads, same bytes as tools/goodix_handshake.py (0010-0014). */
static const guint8 payload_zero2[] = { 0x00, 0x00 };
static const guint8 payload_nop[] = { 0x00, 0x00, 0x00, 0x00 };
static const guint8 payload_state[] = { 0x55 };
static const guint8 payload_one[] = { 0x01, 0x00 };
static const guint8 payload_fdt_manual[] = {
  0x0d, 0x01, 0x80, 0xa0, 0x80, 0x93, 0x80, 0x9b, 0x80, 0x94, 0x80,
  0x90, 0x80, 0x8f, 0x80, 0x94, 0x80, 0x8b, 0x80, 0x8a, 0x80, 0x83
};
static const guint8 payload_fdt_down[] = {
  0x0c, 0x01, 0x80, 0xb9, 0x80, 0xb4, 0x80, 0xb5, 0x80, 0xaf, 0x80,
  0xb4, 0x80, 0xac, 0x80, 0xb2, 0x80, 0xa7, 0x80, 0xab, 0x80, 0xa5
};
static const guint8 payload_fdt_up[] = {
  0x0e, 0x01, 0x80, 0xa0, 0x80, 0x93, 0x80, 0x9b, 0x80, 0x94, 0x80,
  0x90, 0x80, 0x8f, 0x80, 0x94, 0x80, 0x8b, 0x80, 0x8a, 0x80, 0x83
};

struct _FpiDeviceGoodix55a2
{
  FpImageDevice parent;

  GByteArray   *rx;
  SSL_CTX      *ssl_ctx;
  SSL          *ssl;
  BIO          *rbio;       /* owned by ssl */
  BIO          *wbio;       /* owned by ssl */
  guint8        psk[PSK_LEN];
  gboolean      have_psk;
  guint16      *calibration;

  gboolean      up_sent;       /* 0x34 sent since the last disarm */
  gboolean      armed;         /* 0x32 (and maybe 0x34) sent, no 0x60 yet */
  gboolean      wait_pending;  /* async bulk-in outstanding */
  gboolean      waiting_up;    /* the pending wait is for the up event */
  gboolean      deactivating;
  gboolean      scanning;
  GSource      *scan_source;   /* pending start_scan, destroyed on deactivate */
  GCancellable *cancel;
};

G_DECLARE_FINAL_TYPE (FpiDeviceGoodix55a2, fpi_device_goodix55a2, FPI,
                      DEVICE_GOODIX55A2, FpImageDevice);
G_DEFINE_TYPE (FpiDeviceGoodix55a2, fpi_device_goodix55a2, FP_TYPE_IMAGE_DEVICE);

static const FpIdEntry id_table[] = {
  { .vid = 0x27c6, .pid = 0x55a2 },
  { .vid = 0, .pid = 0, .driver_data = 0 },
};

static GError *
proto_error (const char *label)
{
  /* Fixed labels only: never device or key bytes. */
  return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "goodix55a2: %s", label);
}

/* ---- framing -------------------------------------------------------- */

static guint8
sum8 (const guint8 *data, gsize len)
{
  guint8 s = 0;

  for (gsize i = 0; i < len; i++)
    s += data[i];
  return s;
}

static GByteArray *
build_frame (guint8 flag, const guint8 *payload, gsize len)
{
  GByteArray *out = g_byte_array_sized_new (len + 4 + OUT_CHUNK);
  guint8 head[4] = { flag, len & 0xff, (len >> 8) & 0xff, 0 };
  static const guint8 zero[OUT_CHUNK] = { 0 };

  head[3] = sum8 (head, 3);
  g_byte_array_append (out, head, 4);
  g_byte_array_append (out, payload, len);
  if (out->len % OUT_CHUNK)
    g_byte_array_append (out, zero, OUT_CHUNK - out->len % OUT_CHUNK);
  return out;
}

static gboolean
write_frame (FpiDeviceGoodix55a2 *self, GByteArray *frame, GError **error)
{
  for (guint off = 0; off < frame->len; off += OUT_CHUNK)
    {
      g_autoptr(FpiUsbTransfer) t = fpi_usb_transfer_new (FP_DEVICE (self));

      t->short_is_error = TRUE;
      fpi_usb_transfer_fill_bulk_full (t, EP_OUT, frame->data + off, OUT_CHUNK, NULL);
      if (!fpi_usb_transfer_submit_sync (t, CMD_TIMEOUT_MS, error))
        return FALSE;
    }
  return TRUE;
}

/*
 * The only way to send a command. The payload is chosen from the fixed
 * table by command byte; nothing else can be sent as a 0xa0 frame.
 */
static gboolean
goodix55a2_send_cmd (FpiDeviceGoodix55a2 *self, guint8 cmd, GError **error)
{
  const guint8 *payload;
  gsize plen;
  guint8 body[64];
  gsize blen;

  switch (cmd)
    {
    case CMD_NOP: payload = payload_nop; plen = sizeof (payload_nop); break;
    case CMD_FIRMWARE:
    case CMD_REQUEST_TLS:
    case CMD_TLS_DONE: payload = payload_zero2; plen = sizeof (payload_zero2); break;
    case CMD_STATE: payload = payload_state; plen = sizeof (payload_state); break;
    case CMD_GET_IMAGE:
    case CMD_SLEEP: payload = payload_one; plen = sizeof (payload_one); break;
    case CMD_FDT_MANUAL: payload = payload_fdt_manual; plen = sizeof (payload_fdt_manual); break;
    case CMD_FDT_DOWN: payload = payload_fdt_down; plen = sizeof (payload_fdt_down); break;
    case CMD_FDT_UP: payload = payload_fdt_up; plen = sizeof (payload_fdt_up); break;
    default:
      g_propagate_error (error, proto_error ("command_not_allowed"));
      return FALSE;
    }

  body[0] = cmd;
  body[1] = (plen + 1) & 0xff;
  body[2] = ((plen + 1) >> 8) & 0xff;
  memcpy (body + 3, payload, plen);
  blen = 3 + plen;
  body[blen] = cmd == CMD_NOP ? 0x88 : (guint8) (0xaa - sum8 (body, blen));
  blen++;

  g_autoptr(GByteArray) frame = build_frame (FLAG_CMD, body, blen);
  fp_dbg ("send cmd 0x%02x", cmd);
  if (cmd == CMD_FDT_DOWN || cmd == CMD_FDT_UP)
    self->armed = TRUE;
  if (cmd == CMD_FDT_UP)
    self->up_sent = TRUE;   /* both set before the write: a failed write still gets a 0x60 */
  return write_frame (self, frame, error);
}

static gboolean
validate_tls_records (const guint8 *data, gsize len)
{
  gsize off = 0;

  if (len == 0 || len > MAX_FRAME)
    return FALSE;
  while (off < len)
    {
      if (len - off < 5 || (data[off] != 20 && data[off] != 22))
        return FALSE;
      if (data[off + 1] != 3 || (data[off + 2] != 1 && data[off + 2] != 3))
        return FALSE;
      gsize size = (data[off + 3] << 8) | data[off + 4];
      if (size == 0)
        return FALSE;
      off += 5 + size;
      if (off > len)
        return FALSE;
    }
  return TRUE;
}

/* Pop one complete frame from rx. Returns TRUE and fills out if complete. */
static gboolean
pop_frame (FpiDeviceGoodix55a2 *self, guint8 *flag, GByteArray **payload, GError **error)
{
  GByteArray *rx = self->rx;
  guint size;

  if (rx->len < 4)
    return FALSE;
  size = rx->data[1] | (rx->data[2] << 8);
  if ((rx->data[0] != FLAG_CMD && rx->data[0] != FLAG_TLS && rx->data[0] != FLAG_TLS_DATA) ||
      rx->data[3] != sum8 (rx->data, 3) || size < 1 || size > MAX_FRAME)
    {
      g_propagate_error (error, proto_error ("invalid_usb_frame_header"));
      return FALSE;
    }
  if (rx->len < size + 4)
    return FALSE;
  *flag = rx->data[0];
  *payload = g_byte_array_sized_new (size);
  g_byte_array_append (*payload, rx->data + 4, size);
  g_byte_array_remove_range (rx, 0, size + 4);
  /* optional zero padding at the end of a USB transfer */
  gboolean all_zero = TRUE;
  for (guint i = 0; i < rx->len && all_zero; i++)
    all_zero = rx->data[i] == 0;
  if (all_zero)
    g_byte_array_set_size (rx, 0);
  return TRUE;
}

static gboolean
append_rx (FpiDeviceGoodix55a2 *self, const guint8 *data, gsize len, GError **error)
{
  if (len == 0 || self->rx->len + len > IN_BUF)
    {
      g_propagate_error (error, proto_error ("invalid_usb_read_size"));
      return FALSE;
    }
  g_byte_array_append (self->rx, data, len);
  return TRUE;
}

/*
 * Synchronous read of one frame. timeout_ms bounds each USB read.
 * Returns FALSE with *error NULL on a clean timeout when allow_timeout.
 */
static gboolean
read_frame (FpiDeviceGoodix55a2 *self, guint timeout_ms, gboolean allow_timeout,
            guint8 *flag, GByteArray **payload, GError **error)
{
  for (int i = 0; i < 64; i++)
    {
      GError *local = NULL;

      if (pop_frame (self, flag, payload, &local))
        return TRUE;
      if (local)
        {
          g_propagate_error (error, local);
          return FALSE;
        }

      g_autoptr(FpiUsbTransfer) t = fpi_usb_transfer_new (FP_DEVICE (self));
      t->short_is_error = FALSE;
      fpi_usb_transfer_fill_bulk (t, EP_IN, IN_BUF);
      if (!fpi_usb_transfer_submit_sync (t, timeout_ms, &local))
        {
          if (allow_timeout && self->rx->len == 0 &&
              g_error_matches (local, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT))
            {
              g_error_free (local);
              return FALSE;
            }
          if (self->rx->len && g_error_matches (local, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT))
            {
              g_error_free (local);
              g_propagate_error (error, proto_error ("partial_frame_timeout"));
              return FALSE;
            }
          g_propagate_error (error, local);
          return FALSE;
        }
      if (!append_rx (self, t->buffer, t->actual_length, error))
        return FALSE;
    }
  g_propagate_error (error, proto_error ("read_loop_limit"));
  return FALSE;
}

static gboolean
read_cmd_frame (FpiDeviceGoodix55a2 *self, guint timeout_ms, guint8 *cmd,
                GByteArray **body, GError **error)
{
  guint8 flag;
  g_autoptr(GByteArray) payload = NULL;

  if (!read_frame (self, timeout_ms, FALSE, &flag, &payload, error))
    return FALSE;
  if (flag != FLAG_CMD || payload->len < 4)
    {
      g_propagate_error (error, proto_error ("expected_command_frame"));
      return FALSE;
    }
  guint size = payload->data[1] | (payload->data[2] << 8);
  if (size < 1 || payload->len != size + 3 || sum8 (payload->data, payload->len) != 0xaa)
    {
      g_propagate_error (error, proto_error ("invalid_command_checksum_or_length"));
      return FALSE;
    }
  *cmd = payload->data[0];
  *body = g_byte_array_sized_new (size - 1);
  g_byte_array_append (*body, payload->data + 3, size - 1);
  return TRUE;
}

static gboolean
is_ack_for (guint8 cmd, GByteArray *body, guint8 expected)
{
  return cmd == CMD_ACK && body->len == 2 && body->data[0] == expected && (body->data[1] & 1);
}

static gboolean
expect_ack (FpiDeviceGoodix55a2 *self, guint8 expected, GError **error)
{
  guint8 cmd;
  g_autoptr(GByteArray) body = NULL;

  if (!read_cmd_frame (self, CMD_TIMEOUT_MS, &cmd, &body, error))
    return FALSE;
  if (!is_ack_for (cmd, body, expected))
    {
      g_propagate_error (error, proto_error ("invalid_command_ack"));
      return FALSE;
    }
  return TRUE;
}

static gboolean
cmd_with_reply (FpiDeviceGoodix55a2 *self, guint8 cmd, gsize expect_len,
                GByteArray **body_out, GError **error)
{
  guint8 rcmd;
  g_autoptr(GByteArray) body = NULL;

  if (!goodix55a2_send_cmd (self, cmd, error) || !expect_ack (self, cmd, error))
    return FALSE;
  if (!read_cmd_frame (self, CMD_TIMEOUT_MS, &rcmd, &body, error))
    return FALSE;
  if (rcmd != cmd || (expect_len && body->len != expect_len))
    {
      g_propagate_error (error, proto_error ("unexpected_reply"));
      return FALSE;
    }
  if (body_out)
    *body_out = g_steal_pointer (&body);
  return TRUE;
}

/* ---- PSK (0016a: Windows key from a root-only file) --------------------- */

static gboolean
load_psk (FpiDeviceGoodix55a2 *self, GError **error)
{
  struct stat ds, fs;
  int dfd = -1, fd = -1;
  gssize n;
  guint8 extra;
  gboolean ok = FALSE;

  dfd = open (GOODIX_55A2_PSK_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (dfd < 0 || fstat (dfd, &ds) != 0 || ds.st_uid != geteuid () || (ds.st_mode & 077))
    goto out;
  fd = openat (dfd, GOODIX_55A2_PSK_NAME, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0 || fstat (fd, &fs) != 0 || !S_ISREG (fs.st_mode) || fs.st_uid != geteuid () ||
      (fs.st_mode & 077) || fs.st_nlink != 1)
    goto out;
  n = read (fd, self->psk, PSK_LEN);
  if (n != PSK_LEN || read (fd, &extra, 1) != 0)
    goto out;
  ok = TRUE;

out:
  if (fd >= 0)
    close (fd);
  if (dfd >= 0)
    close (dfd);
  if (!ok)
    {
      OPENSSL_cleanse (self->psk, PSK_LEN);
      g_propagate_error (error, proto_error ("psk_file_missing_or_not_private"));
      return FALSE;
    }
  self->have_psk = TRUE;
  return TRUE;
}

/* ---- TLS (in-memory BIOs, no sockets or threads) ------------------------ */

static unsigned int
psk_server_cb (SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_len)
{
  FpiDeviceGoodix55a2 *self = SSL_get_app_data (ssl);

  if (!self || !self->have_psk || max_len < PSK_LEN)
    return 0;
  memcpy (psk, self->psk, PSK_LEN);
  return PSK_LEN;
}

static void
tls_free (FpiDeviceGoodix55a2 *self)
{
  g_clear_pointer (&self->ssl, SSL_free);   /* frees both BIOs */
  self->rbio = self->wbio = NULL;
  g_clear_pointer (&self->ssl_ctx, SSL_CTX_free);
  OPENSSL_cleanse (self->psk, PSK_LEN);
  self->have_psk = FALSE;
}

static gboolean
tls_new (FpiDeviceGoodix55a2 *self, GError **error)
{
  self->ssl_ctx = SSL_CTX_new (TLS_server_method ());
  if (!self->ssl_ctx ||
      !SSL_CTX_set_min_proto_version (self->ssl_ctx, TLS1_2_VERSION) ||
      !SSL_CTX_set_max_proto_version (self->ssl_ctx, TLS1_2_VERSION) ||
      !SSL_CTX_set_cipher_list (self->ssl_ctx,
                                "PSK-AES128-CBC-SHA256:PSK-AES128-CBC-SHA:PSK-AES256-CBC-SHA:"
                                "PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384"))
    goto fail;
  SSL_CTX_set_options (self->ssl_ctx, SSL_OP_NO_TICKET);
  SSL_CTX_set_psk_server_callback (self->ssl_ctx, psk_server_cb);
  self->ssl = SSL_new (self->ssl_ctx);
  self->rbio = BIO_new (BIO_s_mem ());
  self->wbio = BIO_new (BIO_s_mem ());
  if (!self->ssl || !self->rbio || !self->wbio)
    goto fail;
  SSL_set_bio (self->ssl, self->rbio, self->wbio);
  SSL_set_app_data (self->ssl, self);
  SSL_set_accept_state (self->ssl);
  return TRUE;

fail:
  ERR_clear_error ();
  /* Only reached before SSL_set_bio, so the BIOs are still ours. */
  if (self->rbio)
    BIO_free (self->rbio);
  if (self->wbio)
    BIO_free (self->wbio);
  self->rbio = self->wbio = NULL;
  tls_free (self);
  g_propagate_error (error, proto_error ("tls_setup_failed"));
  return FALSE;
}

static gboolean
tls_handshake (FpiDeviceGoodix55a2 *self, GError **error)
{
  for (int i = 0; i < HANDSHAKE_MAX_FRAMES; i++)
    {
      guint8 flag;
      g_autoptr(GByteArray) payload = NULL;
      int ret;

      if (!read_frame (self, CMD_TIMEOUT_MS, FALSE, &flag, &payload, error))
        return FALSE;
      if (flag != FLAG_TLS)
        {
          g_propagate_error (error, proto_error ("expected_tls_frame"));
          return FALSE;
        }
      if (BIO_write (self->rbio, payload->data, payload->len) != (int) payload->len)
        goto tls_fail;
      ret = SSL_do_handshake (self->ssl);
      if (ret != 1 && SSL_get_error (self->ssl, ret) != SSL_ERROR_WANT_READ)
        goto tls_fail;

      gsize pending = BIO_ctrl_pending (self->wbio);
      if (pending)
        {
          if (pending > MAX_FRAME)
            goto tls_fail;
          g_autofree guint8 *out = g_malloc (pending);
          if (BIO_read (self->wbio, out, pending) != (int) pending ||
              !validate_tls_records (out, pending))
            goto tls_fail;
          g_autoptr(GByteArray) frame = build_frame (FLAG_TLS, out, pending);
          if (!write_frame (self, frame, error))
            return FALSE;
        }
      if (ret == 1)
        {
          fp_dbg ("TLS established: %s %s", SSL_get_version (self->ssl),
                  SSL_get_cipher_name (self->ssl));
          /* The key is no longer needed in this struct. */
          OPENSSL_cleanse (self->psk, PSK_LEN);
          self->have_psk = FALSE;
          return TRUE;
        }
    }
  g_propagate_error (error, proto_error ("handshake_frame_limit"));
  return FALSE;

tls_fail:
  {
    unsigned long e = ERR_peek_last_error ();
    const char *reason = e ? ERR_reason_error_string (e) : NULL;
    fp_warn ("TLS handshake failed: %s", reason ? reason : "unknown");
    ERR_clear_error ();
  }
  g_propagate_error (error, proto_error ("tls_handshake_rejected"));
  return FALSE;
}

/* ---- image ------------------------------------------------------------- */

static void
unpack_pixels (const guint8 *data, guint16 *out)
{
  for (gsize i = 0, p = 0; i < IMAGE_PACKED_LEN; i += 6)
    {
      const guint8 *b = data + i;
      out[p++] = ((b[0] & 0xf) << 8) | b[1];
      out[p++] = (b[3] << 4) | (b[0] >> 4);
      out[p++] = ((b[5] & 0xf) << 8) | b[2];
      out[p++] = (b[4] << 4) | (b[5] >> 4);
    }
}

/* Send 0x20, receive the 0xb2 reply and decrypt it into pixels. */
static gboolean
get_image (FpiDeviceGoodix55a2 *self, guint16 *pixels, GError **error)
{
  guint8 flag;
  g_autoptr(GByteArray) payload = NULL;
  g_autofree guint8 *plain = NULL;
  int total = 0;

  if (!goodix55a2_send_cmd (self, CMD_GET_IMAGE, error) || !expect_ack (self, CMD_GET_IMAGE, error))
    return FALSE;
  if (!read_frame (self, IMAGE_TIMEOUT_MS, FALSE, &flag, &payload, error))
    return FALSE;
  if (flag != FLAG_TLS_DATA)
    {
      g_propagate_error (error, proto_error ("unexpected_image_reply_flag"));
      return FALSE;
    }

  static const gsize skips[] = { 9, 0 };
  for (guint k = 0; k < G_N_ELEMENTS (skips); k++)
    {
      gsize skip = skips[k];
      if (payload->len < skip + 5)
        continue;
      const guint8 *rec = payload->data + skip;
      if (rec[0] == 21 && rec[1] == 3 && rec[2] == 3)
        {
          g_propagate_error (error, proto_error ("tls_alert_in_image_reply"));
          return FALSE;
        }
      if (rec[0] != 23 || rec[1] != 3 || rec[2] != 3)
        continue;

      gsize rlen = payload->len - skip;
      if (BIO_write (self->rbio, rec, rlen) != (int) rlen)
        break;
      plain = g_malloc (MAX_FRAME + 1);
      for (int i = 0; i < 8 && total <= MAX_FRAME; i++)
        {
          int n = SSL_read (self->ssl, plain + total, MAX_FRAME + 1 - total);
          if (n <= 0)
            {
              if (SSL_get_error (self->ssl, n) == SSL_ERROR_WANT_READ)
                break;
              ERR_clear_error ();
              OPENSSL_cleanse (plain, MAX_FRAME + 1);
              g_propagate_error (error, proto_error ("image_not_decrypted"));
              return FALSE;
            }
          total += n;
        }
      if (BIO_ctrl_pending (self->rbio) || SSL_pending (self->ssl) || total != IMAGE_PLAIN_LEN)
        {
          fp_dbg ("image plaintext length %d", total);
          OPENSSL_cleanse (plain, MAX_FRAME + 1);
          g_propagate_error (error, proto_error ("image_unexpected_length"));
          return FALSE;
        }
      unpack_pixels (plain, pixels);
      OPENSSL_cleanse (plain, MAX_FRAME + 1);
      return TRUE;
    }
  g_propagate_error (error, proto_error ("image_reply_not_tls_record"));
  return FALSE;
}



static int
cmp_int (const void *a, const void *b)
{
  gint x = *(const gint *) a, y = *(const gint *) b;

  return (x > y) - (x < y);
}

/* nofinger - finger, stretched 1st-99th percentile to 0..255 (experiment
 * 0015). Ridges come out bright, so the image is flagged COLORS_INVERTED.
 * Pixels that read 0 in either frame (808 fixed ones on this sensor) carry
 * no signal; they are set to the median so they add no false features.
 * Layout is the Lambertz orientation, flipud(reshape(176,56).T), which is
 * again 176 wide and 56 high. */
static FpImage *
build_image (const guint16 *calibration, const guint16 *finger)
{
  g_autofree gint *diff = g_new (gint, IMG_PIX);
  g_autofree gint *sorted = g_new (gint, IMG_PIX);
  FpImage *img = fp_image_new (IMG_W, IMG_H);
  gint lo, hi, median;
  int n = 0;

  for (int i = 0; i < IMG_PIX; i++)
    {
      diff[i] = (gint) calibration[i] - (gint) finger[i];
      if (calibration[i] && finger[i])
        sorted[n++] = diff[i];
    }
  if (n == 0)
    n = 1, sorted[0] = 0;
  qsort (sorted, n, sizeof (gint), cmp_int);
  lo = sorted[(n - 1) / 100];
  hi = sorted[(n - 1) * 99 / 100];
  median = sorted[(n - 1) / 2];
  for (int i = 0; i < IMG_PIX; i++)
    {
      gint d = (calibration[i] && finger[i]) ? diff[i] : median;
      gint v = hi > lo ? (d - lo) * 255 / (hi - lo) : 0;
      int r = i / IMG_H, c = i % IMG_H;          /* reshape(176, 56) */

      img->data[(IMG_H - 1 - c) * IMG_W + r] = CLAMP (v, 0, 255);
    }
  img->flags = FPI_IMAGE_COLORS_INVERTED;
  memset (diff, 0, IMG_PIX * sizeof (gint));
  memset (sorted, 0, IMG_PIX * sizeof (gint));
  return img;
}

static void
clear_calibration (FpiDeviceGoodix55a2 *self)
{
  if (self->calibration)
    memset (self->calibration, 0, IMG_PIX * sizeof (guint16));
  g_clear_pointer (&self->calibration, g_free);
}

/* ---- device sequences ---------------------------------------------------- */

/* 0x60 disarm, tolerating up to two late FDT events (as the Python pilot). */
static gboolean
disarm (FpiDeviceGoodix55a2 *self, GError **error)
{
  if (!self->armed)
    return TRUE;
  self->armed = FALSE;
  self->up_sent = FALSE;
  g_byte_array_set_size (self->rx, 0);   /* drop any partial frame */
  if (!goodix55a2_send_cmd (self, CMD_SLEEP, error))
    return FALSE;
  for (int i = 0; i < 3; i++)
    {
      guint8 cmd;
      g_autoptr(GByteArray) body = NULL;

      if (!read_cmd_frame (self, CMD_TIMEOUT_MS, &cmd, &body, error))
        return FALSE;
      if ((cmd == CMD_FDT_DOWN || (cmd == CMD_FDT_UP && self->up_sent)) && body->len == 24)
        {
          fp_dbg ("late FDT event 0x%02x before disarm ACK", cmd);
          continue;
        }
      if (is_ack_for (cmd, body, CMD_SLEEP))
        return TRUE;
      break;
    }
  g_propagate_error (error, proto_error ("sleep_ack_missing"));
  return FALSE;
}

/* Best effort: never leave the reader armed; keeps the caller's error. */
static void
disarm_quiet (FpiDeviceGoodix55a2 *self)
{
  g_autoptr(GError) err = NULL;

  if (self->armed && !disarm (self, &err))
    fp_warn ("disarm failed: %s", err->message);
}

static gboolean
query_state (FpiDeviceGoodix55a2 *self, GError **error)
{
  g_autoptr(GByteArray) body = NULL;

  if (!cmd_with_reply (self, CMD_STATE, 0, &body, error))
    return FALSE;
  fp_dbg ("mcu state reply length %u", body->len);
  return TRUE;
}

static gboolean
activate_sequence (FpiDeviceGoodix55a2 *self, GError **error)
{
  guint8 flag;
  g_autoptr(GByteArray) stale = NULL;
  g_autoptr(GByteArray) fw = NULL;
  g_autoptr(GByteArray) payload = NULL;
  GError *local = NULL;

  g_byte_array_set_size (self->rx, 0);

  /* Pre-send listen: any frame now was not asked for (stuck reader). */
  if (read_frame (self, STALE_WINDOW_MS, TRUE, &flag, &stale, &local))
    {
      g_propagate_error (error, proto_error ("stale_reader_frame"));
      return FALSE;
    }
  if (local)
    {
      g_propagate_error (error, local);
      return FALSE;
    }

  if (!load_psk (self, error) || !tls_new (self, error))
    return FALSE;

  /* NOP: no ACK is normal on this reader; a clean timeout is accepted. */
  if (!goodix55a2_send_cmd (self, CMD_NOP, error))
    return FALSE;
  if (read_frame (self, CMD_TIMEOUT_MS, TRUE, &flag, &payload, &local))
    {
      if (flag != FLAG_CMD || payload->len != 6 || payload->data[0] != CMD_ACK ||
          (payload->data[1] | (payload->data[2] << 8)) != 3 ||
          sum8 (payload->data, payload->len) != 0xaa ||
          payload->data[3] != CMD_NOP || !(payload->data[4] & 1))
        {
          g_propagate_error (error, proto_error ("invalid_nop_ack"));
          return FALSE;
        }
    }
  else if (local)
    {
      g_propagate_error (error, local);
      return FALSE;
    }

  if (!cmd_with_reply (self, CMD_FIRMWARE, 0, &fw, error))
    return FALSE;
  {
    gsize n = fw->len;
    while (n && fw->data[n - 1] == 0)
      n--;
    if (n != strlen (FIRMWARE) || memcmp (fw->data, FIRMWARE, n) != 0)
      {
        g_propagate_error (error, proto_error ("unexpected_firmware"));
        return FALSE;
      }
  }

  if (!goodix55a2_send_cmd (self, CMD_REQUEST_TLS, error) || !expect_ack (self, CMD_REQUEST_TLS, error))
    return FALSE;
  if (!tls_handshake (self, error))
    return FALSE;
  g_usleep (20000);   /* prior work waits after the final server flight */
  if (!goodix55a2_send_cmd (self, CMD_TLS_DONE, error) || !expect_ack (self, CMD_TLS_DONE, error))
    return FALSE;

  /* Experiment 0013 order: A.7, then one 2.0 with no finger = calibration. */
  if (!query_state (self, error))
    return FALSE;
  clear_calibration (self);
  self->calibration = g_new0 (guint16, IMG_PIX);
  if (!get_image (self, self->calibration, error))
    return FALSE;
  return TRUE;
}

/* Experiment 0014 order: A.7, 3.3 (24-byte reply), A.7, 3.1 (ACK). */
static gboolean
arm_sequence (FpiDeviceGoodix55a2 *self, GError **error)
{
  g_autoptr(GByteArray) body = NULL;

  if (!query_state (self, error) ||
      !cmd_with_reply (self, CMD_FDT_MANUAL, 24, &body, error) ||
      !query_state (self, error))
    return FALSE;
  if (!goodix55a2_send_cmd (self, CMD_FDT_DOWN, error))
    return FALSE;
  return expect_ack (self, CMD_FDT_DOWN, error);
}

static void wait_event (FpiDeviceGoodix55a2 *self, gboolean up);
static void handle_event_frames (FpiDeviceGoodix55a2 *self, gboolean up);

static void
finish_deactivate (FpiDeviceGoodix55a2 *self)
{
  disarm_quiet (self);
  self->scanning = FALSE;
  self->deactivating = FALSE;
  tls_free (self);
  clear_calibration (self);
  fpi_image_device_deactivate_complete (FP_IMAGE_DEVICE (self), NULL);
}

static void
scan_failed (FpiDeviceGoodix55a2 *self, GError *error)
{
  disarm_quiet (self);
  self->scanning = FALSE;
  if (self->deactivating)
    {
      g_error_free (error);
      finish_deactivate (self);
      return;
    }
  fpi_image_device_session_error (FP_IMAGE_DEVICE (self), error);
}

static void
on_down_event (FpiDeviceGoodix55a2 *self)
{
  GError *error = NULL;
  g_autofree guint16 *pixels = g_new0 (guint16, IMG_PIX);
  FpImage *img;

  /* Image right after the down event while still armed (0014), then 3.2
   * (0012) so the up event marks the finger lift; 6.0 follows the lift. */
  if (!get_image (self, pixels, &error) ||
      !goodix55a2_send_cmd (self, CMD_FDT_UP, &error) ||
      !expect_ack (self, CMD_FDT_UP, &error))
    {
      memset (pixels, 0, IMG_PIX * sizeof (guint16));
      scan_failed (self, error);
      return;
    }
  {
    g_autoptr(FpImage) small = build_image (self->calibration, pixels);

    img = fpi_image_resize (small, IMG_SCALE, IMG_SCALE);
    memset (small->data, 0, IMG_PIX);
  }
  memset (pixels, 0, IMG_PIX * sizeof (guint16));

  fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (self), TRUE);
  fpi_image_device_image_captured (FP_IMAGE_DEVICE (self), img);
  wait_event (self, TRUE);
}

static void
on_up_event (FpiDeviceGoodix55a2 *self)
{
  GError *error = NULL;

  if (!disarm (self, &error))
    {
      scan_failed (self, error);
      return;
    }
  self->scanning = FALSE;
  fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (self), FALSE);
}

static void
wait_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (dev);
  gboolean up = self->waiting_up;
  GError *local = NULL;

  self->wait_pending = FALSE;

  if (self->deactivating)
    {
      if (error)
        g_error_free (error);
      finish_deactivate (self);
      return;
    }
  if (error)
    {
      if (up && g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT) &&
          self->rx->len == 0)
        {
          /* No up event in time: disarm and treat the finger as lifted. */
          fp_dbg ("finger-up wait timed out");
          g_error_free (error);
          on_up_event (self);
          return;
        }
      scan_failed (self, error);
      return;
    }
  if (transfer->actual_length == 0)
    {
      wait_event (self, up);   /* empty read: keep waiting */
      return;
    }
  if (!append_rx (self, transfer->buffer, transfer->actual_length, &local))
    {
      scan_failed (self, local);
      return;
    }
  handle_event_frames (self, up);
}

/* Process a complete event frame already in rx, or keep waiting. */
static void
handle_event_frames (FpiDeviceGoodix55a2 *self, gboolean up)
{
  guint8 flag;
  g_autoptr(GByteArray) payload = NULL;
  GError *local = NULL;

  if (!pop_frame (self, &flag, &payload, &local))
    {
      if (local)
        scan_failed (self, local);
      else
        wait_event (self, up);   /* partial frame: keep reading */
      return;
    }
  if (flag != FLAG_CMD || payload->len != 24 + 4 ||
      payload->data[0] != (up ? CMD_FDT_UP : CMD_FDT_DOWN) ||
      (payload->data[1] | (payload->data[2] << 8)) != 25 ||
      sum8 (payload->data, payload->len) != 0xaa)
    {
      scan_failed (self, proto_error (up ? "unexpected_fdt_up_event" : "unexpected_fdt_down_event"));
      return;
    }
  fp_dbg ("%s event, touch flag %02x%02x", up ? "up" : "down",
          payload->data[6], payload->data[5]);
  if (up)
    on_up_event (self);
  else
    on_down_event (self);
}

static void
wait_event (FpiDeviceGoodix55a2 *self, gboolean up)
{
  FpiUsbTransfer *t;

  /* An event may already sit in rx behind the last sync ACK read. */
  if (self->rx->len >= 4 && self->rx->len >= 4u + (self->rx->data[1] | (self->rx->data[2] << 8)))
    {
      handle_event_frames (self, up);
      return;
    }
  t = fpi_usb_transfer_new (FP_DEVICE (self));
  self->waiting_up = up;
  self->wait_pending = TRUE;
  t->short_is_error = FALSE;
  fpi_usb_transfer_fill_bulk (t, EP_IN, IN_BUF);
  /* Finger-down waits as long as libfprint wants (cancelled on deactivate). */
  fpi_usb_transfer_submit (t, up ? FDT_UP_TIMEOUT_MS : 0, self->cancel, wait_cb, NULL);
}

static void
start_scan (FpDevice *dev, gpointer user_data)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (dev);
  GError *error = NULL;

  self->scan_source = NULL;
  if (self->deactivating || self->scanning)
    return;
  self->scanning = TRUE;
  if (!arm_sequence (self, &error))
    {
      scan_failed (self, error);
      return;
    }
  wait_event (self, FALSE);
}

/* ---- FpImageDevice vfuncs ---------------------------------------------- */

static void
dev_open (FpImageDevice *img_dev)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (img_dev);
  GError *error = NULL;

  self->rx = g_byte_array_new ();
  g_usb_device_claim_interface (fpi_device_get_usb_device (FP_DEVICE (img_dev)), 0, 0, &error);
  fpi_image_device_open_complete (img_dev, error);
}

static void
dev_close (FpImageDevice *img_dev)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (img_dev);
  GError *error = NULL;

  tls_free (self);
  clear_calibration (self);
  g_clear_pointer (&self->rx, g_byte_array_unref);
  g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (img_dev)), 0, 0, &error);
  fpi_image_device_close_complete (img_dev, error);
}

static void
dev_activate (FpImageDevice *img_dev)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (img_dev);
  GError *error = NULL;

  self->armed = self->scanning = self->deactivating = self->wait_pending = FALSE;
  g_clear_object (&self->cancel);
  self->cancel = g_cancellable_new ();
  if (!activate_sequence (self, &error))
    {
      tls_free (self);
      clear_calibration (self);
    }
  fpi_image_device_activate_complete (img_dev, error);
}

static void
dev_change_state (FpImageDevice *img_dev, FpiImageDeviceState state)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (img_dev);

  if (state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON && !self->scan_source)
    self->scan_source = fpi_device_add_timeout (FP_DEVICE (img_dev), 0, start_scan, NULL, NULL);
}

static void
dev_deactivate (FpImageDevice *img_dev)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (img_dev);

  self->deactivating = TRUE;
  if (self->scan_source)
    g_clear_pointer (&self->scan_source, g_source_destroy);
  if (self->wait_pending)
    {
      g_cancellable_cancel (self->cancel);   /* wait_cb finishes deactivation */
      return;
    }
  finish_deactivate (self);
}

static void
fpi_device_goodix55a2_init (FpiDeviceGoodix55a2 *self)
{
}

static void
fpi_device_goodix55a2_finalize (GObject *object)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (object);

  tls_free (self);
  clear_calibration (self);
  g_clear_pointer (&self->rx, g_byte_array_unref);
  g_clear_object (&self->cancel);
  G_OBJECT_CLASS (fpi_device_goodix55a2_parent_class)->finalize (object);
}

static void
fpi_device_goodix55a2_class_init (FpiDeviceGoodix55a2Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *img_class = FP_IMAGE_DEVICE_CLASS (klass);

  G_OBJECT_CLASS (klass)->finalize = fpi_device_goodix55a2_finalize;

  dev_class->id = "goodix55a2";
  dev_class->full_name = "Goodix 55a2 (experimental, TLS)";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = 10;

  img_class->img_open = dev_open;
  img_class->img_close = dev_close;
  img_class->activate = dev_activate;
  img_class->deactivate = dev_deactivate;
  img_class->change_state = dev_change_state;
  img_class->img_width = IMG_W * IMG_SCALE;
  img_class->img_height = IMG_H * IMG_SCALE;
}
