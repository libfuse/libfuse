libfuse_headers = [ 'fuse.h', 'fuse_common.h', 'fuse_lowlevel.h',
	            'fuse_opt.h', 'cuse_lowlevel.h', 'fuse_log.h',
	            'fuse_daemonize.h', 'fuse_uring.h' ]

if private_cfg.get('HAVE_SERVICEMOUNT', false)
  libfuse_headers += [ 'fuse_service.h' ]
endif

install_headers(libfuse_headers, subdir: 'fuse3')
install_data(libfuse_headers,
             install_dir: join_paths(get_option('includedir'), 'fuse3'),
             install_tag: 'headers')
