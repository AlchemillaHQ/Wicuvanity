project(
    'wicuvanity-tests',
    'cpp',
    default_options: ['cpp_std=c++20', 'buildtype=debugoptimized', 'warning_level=2']
)

regression = executable('regression', 'regression.cpp', dependencies: dependency('libcrypto'))
test('regression', regression)
