# Attention, emacs, please use -*- mode: python -*-
# (even though this isn't actually Python code)

libfuse_sources = ['fuse.c', 'fuse_i.h', 'fuse_loop.c', 'fuse_loop_mt.c',
                   'fuse_lowlevel.c', 'fuse_misc.h', 'fuse_opt.c',
                   'fuse_signals.c', 'buffer.c', 'cuse_lowlevel.c',
	           'helper.c', 'modules/subdir.c' ]

if host_machine.system().startswith('linux')
   libfuse_sources += [ 'mount.c', 'mount_util.c' ]
else
   libfuse_sources += [ 'mount_bsd.c' ]
endif

if cfg.has('HAVE_ICONV')
   libfuse_sources += [ 'modules/iconv.c' ]
endif

deps = [ thread_dep ]
libdl = meson.get_compiler('c').find_library('dl')
if libdl.found()
   deps += [ libdl ]
endif

if host_machine.system().startswith('netbsd')
   deps += [ cc.find_library('perfuse'),
             cc.find_library('puffs') ]
endif

fusermount_path = join_paths(get_option('prefix'), get_option('bindir'))
libfuse = library('fuse3', libfuse_sources, version: '3.0.0', install: true,
                  soversion: '3', include_directories: include_dirs,
                  dependencies: deps,
                  link_depends: 'fuse_versionscript',
                  c_args: [ '-DFUSE_USE_VERSION=30',
                            '-DFUSERMOUNT_DIR="{}"'.format(fusermount_path) ],
                  link_args: ['-Wl,--version-script,' + meson.current_source_dir()
                              + '/fuse_versionscript' ])

pkg = import('pkgconfig')
pkg.generate(libraries: [ libfuse, '-lpthread' ],
             libraries_private: '-ldl',
             version: meson.project_version(),
             name: 'fuse3',
             description: 'Filesystem in Userspace',
             subdirs: 'fuse3')
             
