sysdep_supported_options = {
    'posix': true,
    'linux': false,
    'glibc': true,
    'bsd': true,
}

internal_conf.set10('MLIBC_MAP_DSO_SEGMENTS', true)
internal_conf.set10('MLIBC_MMAP_ALLOCATE_DSO', true)
internal_conf.set10('MLIBC_MAP_FILE_WINDOWS', true)

if not headers_only
    hydrogen = dependency('hydrogen')

    rtld_deps += hydrogen
    libc_deps += hydrogen
endif

rtld_include_dirs += include_directories('include')
libc_include_dirs += include_directories('include')

subdir('generic')
subdir('include')
subdir(host_machine.cpu_family())
