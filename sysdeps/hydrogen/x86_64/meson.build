rtld_sources += files('sysdeps.cpp', 'sysdeps.S')
libc_sources += files('sysdeps.cpp', 'sysdeps.S')

if headers_only
    subdir_done()
endif

crt_args = []

if get_option('debug')
    crt_args += '-g'
endif

foreach name : ['crt1', 'crti', 'crtn', 'gcrt1', 'grcrt1', 'rcrt1', 'Scrt1']
    custom_target(
        name,
        build_by_default: true,
        command: c_compiler.cmd_array() + ['-c', '-o', '@OUTPUT@', '@INPUT@'] + crt_args,
        input: name + '.S',
        output: name + '.o',
        install: true,
        install_dir: get_option('libdir'),
        install_tag: 'devel',
    )
endforeach
