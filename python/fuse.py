#@+leo-ver=4
#@+node:@file fuse.py
#
#    Copyright (C) 2001  Jeff Epler  <jepler@unpythonic.dhs.org>
#
#    This program can be distributed under the terms of the GNU GPL.
#    See the file COPYING.
#


#@@language python
#@+others
#@+node:imports
# suppress version mismatch warnings
try:
    import warnings
    warnings.filterwarnings('ignore',
                            'Python C API version mismatch',
                            RuntimeWarning,
                            )
except:
    pass
 
from _fuse import main, DEBUG
import os, sys
from errno import *

#@-node:imports
#@+node:class ErrnoWrapper
class ErrnoWrapper:
    #@	@+others
    #@+node:__init__
    def __init__(self, func):
    	self.func = func
    #@-node:__init__
    #@+node:__call__
    def __call__(self, *args, **kw):
    	try:
    		return apply(self.func, args, kw)
    	except (IOError, OSError), detail:
    		# Sometimes this is an int, sometimes an instance...
    		if hasattr(detail, "errno"): detail = detail.errno
    		return -detail
    #@-node:__call__
    #@-others
#@-node:class ErrnoWrapper
#@+node:class Fuse
class Fuse:

    #@	@+others
    #@+node:attribs
    _attrs = ['getattr', 'readlink', 'getdir', 'mknod', 'mkdir',
    	  'unlink', 'rmdir', 'symlink', 'rename', 'link', 'chmod',
    	  'chown', 'truncate', 'utime', 'open', 'read', 'write', 'release',
          'statfs', 'fsync']
    
    flags = 0
    multithreaded = 0
    
    #@-node:attribs
    #@+node:__init__
    def __init__(self, *args, **kw):
    
        # default attributes
        self.optlist = []
        self.optdict = {}
        self.mountpoint = None
    
        # grab arguments, if any
        argv = sys.argv
        argc = len(argv)
        if argc > 1:
            # we've been given the mountpoint
            self.mountpoint = argv[1]
        if argc > 2:
            # we've received mount args
            optstr = argv[2]
            opts = optstr.split(",")
            for o in opts:
                try:
                    k, v = o.split("=", 1)
                    self.optdict[k] = v
                except:
                    self.optlist.append(o)
    #@-node:__init__
    #@+node:main
    def main(self):
    	d = {'flags': self.flags}
    	d['multithreaded'] = self.multithreaded
    	for a in self._attrs:
    		if hasattr(self,a):
    			d[a] = ErrnoWrapper(getattr(self, a))
    	apply(main, (), d)
    #@-node:main
    #@-others
#@-node:class Fuse
#@-others
#@-node:@file fuse.py
#@-leo
