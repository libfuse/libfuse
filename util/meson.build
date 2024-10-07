fuseconf_path = join_paths(get_option('prefix'), get_option('sysconfdir'), 'fuse.conf')

executable('fusermount3', ['fusermount.c', '../lib/mount_util.c', '../lib/util.c'],
           include_directories: include_dirs,
           install: true,
           install_dir: get_option('bindir'),
           c_args: '-DFUSE_CONF="@0@"'.format(fuseconf_path))

executable('mount.fuse3', ['mount.fuse.c'],
           include_directories: include_dirs,
           link_with: [ libfuse ],
           install: true,
           install_dir: get_option('sbindir'),
           c_args: '-DFUSE_USE_VERSION=317')


udevrulesdir = get_option('udevrulesdir')
if udevrulesdir == ''
  udev = dependency('udev', required: false)
  if udev.found()
     udevrulesdir = join_paths(udev.get_variable(pkgconfig: 'udevdir'), 'rules.d')
  endif
endif

if udevrulesdir == ''
  warning('could not determine udevdir, udev.rules will not be installed')
endif

meson.add_install_script('install_helper.sh',
                         join_paths(get_option('prefix'), get_option('sysconfdir')),
                         join_paths(get_option('prefix'), get_option('bindir')),
                         udevrulesdir,
                         '@0@'.format(get_option('useroot')),
                         get_option('initscriptdir'))
