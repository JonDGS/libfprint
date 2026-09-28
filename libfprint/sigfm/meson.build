
sigfm_sources = ['sigfm.cpp']

opencv = dependency('opencv4', required: true)

libsigfm = static_library('sigfm',
        sigfm_sources,
        dependencies: [opencv],
)

# doctest is only needed for the standalone sigfm tests. Fedora ships it
# with CMake config only, so look for the header instead of pkg-config.
doctest = dependency('doctest', required: false)
if not doctest.found()
    doctest = declare_dependency()
    if not meson.get_compiler('cpp').has_header('doctest/doctest.h')
        doctest = disabler()
    endif
endif
sigfm_tests = executable('sigfm-tests', ['./tests.cpp'],
        dependencies: [doctest, opencv],
        link_with: [libsigfm],
        build_by_default: false,
)
