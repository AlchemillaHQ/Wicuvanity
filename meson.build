project('wicuvanity', 'cuda', version: '1.2', license: 'MIT')

executable(
    meson.project_name(),
    sources: 'main.cu',
    cuda_args: ['-arch=native', '-maxrregcount=168'],
    dependencies: [
        dependency('cxxopts'),
        dependency('CUDAToolkit')
    ],
    override_options: ['cuda_std=c++20'],
    install: true
)
