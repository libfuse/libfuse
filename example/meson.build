examples = [ 'passthrough', 'passthrough_fh',
             'hello', 'hello_ll', 'printcap',
             'ioctl_client', 'poll_client', 'ioctl',
             'cuse', 'cuse_client' ]

if not platform.endswith('bsd')
    examples += 'passthrough_ll'

    # According to Conrad Meyer <cem@freebsd.org>, FreeBSD doesn't
    # support mounting files, This is enforced in vfs_domount_first()
    # with the v_type != VDIR check.
    examples += [ 'null' ]
endif

threaded_examples = [ 'notify_inval_inode',
                      'invalidate_path',
                      'notify_store_retrieve',
                      'notify_inval_entry',
                      'poll' ]

foreach ex : examples
    executable(ex, ex + '.c',
               include_directories: include_dirs,
               link_with: [ libfuse ],
               install: false)
endforeach


foreach ex : threaded_examples
    executable(ex, ex + '.c',
               include_directories: include_dirs,
               link_with: [ libfuse ],
               dependencies: thread_dep,
               install: false)
endforeach

# TODO: Link passthrough_fh with ulockmgr if available
