# Attention, emacs, please use -*- mode: python -*-
# (even though this isn't actually Python code)

examples = [ 'passthrough', 'passthrough_fh',
             'null', 'hello', 'hello_ll', 'printcap',
             'ioctl', 'ioctl_client', 'poll_client',
             'cuse', 'cuse_client' ]

if not platform.endswith('bsd')
  examples += 'passthrough_ll'
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
