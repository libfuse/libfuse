# we re-use mount_util.c from the library, but do want to keep ourself
# as stand-alone as possible. in order to make an out-of-source build
# possible, we "generate" the file from its original location by
# copying it over.
mount_util_c = custom_target('mount_util',
  input : '../lib/mount_util.c',
  output : 'mount_util.c',
  command : ['cp', '-a', '@INPUT@', '@OUTPUT@'],
)

executable('fusermount3', ['fusermount.c', mount_util_c],
           include_directories: include_dirs,
           install: true,
           install_dir: get_option('bindir'))

executable('mount.fuse3', ['mount.fuse.c'], 
           include_directories: include_dirs,
           install: true,
           install_dir: get_option('sbindir'))


udevrulesdir = get_option('udevrulesdir')
if udevrulesdir == ''
  udev = dependency('udev')
  udevrulesdir = join_paths(udev.get_pkgconfig_variable('udevdir'), 'rules.d')
endif

meson.add_install_script('install_helper.sh', get_option('sysconfdir'),
                         get_option('bindir'), udevrulesdir)


