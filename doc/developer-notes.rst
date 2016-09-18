=================
 Developer Notes
=================

If you are working on libfuse itself (rather than using it for a
different project) this file should be of interest to you. Otherwise
you should ignore it entirely.

Channel Interface
=================

From the API, it may appear as if every fuse session (`struct
fuse_session`) is associated with a single fuse channel (`struct
fuse_chan`) that is created by `fuse_mount()` and assigned to the
session in `fuse_session_add_chan()`. Therefore, one may wonder why
there are two separate structs in the first place, and why the channel
structure has a reference counter and mutex.

The answer is that when using the multi-threaded session loop with the
*clone_fd* option enabled, there are actually multiple channel objects
per session. The session only holds a reference to the first one, and
the additional channel objects don't actually hold references to the
session object -- but they still exist. The additional channels are
created by duplicating the fd (in `fuse_clone_chan()`, called by
`fuse_loop_start_thread`). When processing a request,
`fuse_session_process_buf()` records the active channel in the request
object (`struct fuse_req`) so that it can be retrieved by e.g.  the
``fuse_reply_*`` functions. Since the request object can potentially
live longer than the worker thread that created it, we need to keep a
reference count for the channel.

The reason for not having references to the session object from the
extra channels is not clear, but with the current implementation this
would not work because `fuse_session_remove_chan` always attempts to
remove the channel from the session.
