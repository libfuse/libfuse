# Attention, emacs, please use -*- mode: python -*-
# (even though this isn't actually Python code)

examples = [ 'passthrough', 'passthrough_fh', 'null', 'hello', 'hello_ll',
             'ioctl', 'ioctl_client', 'poll_client',
             'passthrough_ll', 'cuse', 'cuse_client' ]

threaded_examples = [ 'notify_inval_inode',
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
