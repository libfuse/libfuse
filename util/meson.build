fuseconf_path = join_paths(get_option('prefix'), get_option('sysconfdir'), 'fuse.conf')

executable('fusermount3', ['fusermount.c', '../lib/mount_util.c', '../lib/util.c', 'fuser_conf.c'],
           include_directories: include_dirs,
           install: true,
           install_dir: get_option('bindir'),
           c_args: '-DFUSE_CONF="@0@"'.format(fuseconf_path))

mount_service_sources = []
mount_service_cflags = []
if private_cfg.get('HAVE_SERVICEMOUNT', false)
  mount_service_sources += ['mount_service.c', '../lib/mount_util.c', 'fuser_conf.c']
  mount_service_cflags += ['-DFUSE_CONF="@0@"'.format(fuseconf_path)]
  fuservicemount_path = join_paths(get_option('prefix'), get_option('sbindir'))
  mount_service_cflags += ['-DFUSERVICEMOUNT_DIR="@0@"'.format(fuservicemount_path)]
  executable('fuservicemount3', ['fuservicemount.c'] + mount_service_sources,
             include_directories: include_dirs,
             link_with: [ libfuse ],
             install: true,
             install_dir: get_option('sbindir'),
             c_args: ['-DFUSE_USE_VERSION=319'] + mount_service_cflags)
endif

executable('mount.fuse3', ['mount.fuse.c'] + mount_service_sources,
           include_directories: include_dirs,
           link_with: [ libfuse ],
           install: true,
           install_dir: get_option('sbindir'),
           c_args: ['-DFUSE_USE_VERSION=319'] + mount_service_cflags)


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
                         get_option('initscriptdir'),
                         join_paths(get_option('prefix'), get_option('sbindir')))
