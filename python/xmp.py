#!/usr/bin/env python
#@+leo-ver=4
#@+node:@file xmp.py
#@@first #!/usr/bin/env python
#
#    Copyright (C) 2001  Jeff Epler  <jepler@unpythonic.dhs.org>
#
#    This program can be distributed under the terms of the GNU GPL.
#    See the file COPYING.
#

#@+others
#@+node:imports

from fuse import Fuse
import os
from errno import *
from stat import *

import thread
#@-node:imports
#@+node:class Xmp
class Xmp(Fuse):

    #@	@+others
    #@+node:__init__
    def __init__(self, *args, **kw):
    
        Fuse.__init__(self, *args, **kw)
    
        if 1:
            print "mountpoint: %s" % repr(self.mountpoint)
            print "unnamed mount options: %s" % self.optlist
            print "named mount options: %s" % self.optdict
    
        # do stuff to set up your filesystem here, if you want
        #thread.start_new_thread(self.mythread, ())
        pass
    #@-node:__init__
    #@+node:mythread
    def mythread(self):
    
        """
        The beauty of the FUSE python implementation is that with the python interp
        running in foreground, you can have threads
        """    
        print "mythread: started"
        #while 1:
        #    time.sleep(120)
        #    print "mythread: ticking"
    
    #@-node:mythread
    #@+node:attribs
    flags = 1
    
    #@-node:attribs
    #@+node:getattr
    def getattr(self, path):
    	return os.lstat(path)
    #@-node:getattr
    #@+node:readlink
    def readlink(self, path):
    	return os.readlink(path)
    #@-node:readlink
    #@+node:getdir
    def getdir(self, path):
    	return map(lambda x: (x,0), os.listdir(path))
    #@-node:getdir
    #@+node:unlink
    def unlink(self, path):
    	return os.unlink(path)
    #@-node:unlink
    #@+node:rmdir
    def rmdir(self, path):
    	return os.rmdir(path)
    #@-node:rmdir
    #@+node:symlink
    def symlink(self, path, path1):
    	return os.symlink(path, path1)
    #@-node:symlink
    #@+node:rename
    def rename(self, path, path1):
    	return os.rename(path, path1)
    #@-node:rename
    #@+node:link
    def link(self, path, path1):
    	return os.link(path, path1)
    #@-node:link
    #@+node:chmod
    def chmod(self, path, mode):
    	return os.chmod(path, mode)
    #@-node:chmod
    #@+node:chown
    def chown(self, path, user, group):
    	return os.chown(path, user, group)
    #@-node:chown
    #@+node:truncate
    def truncate(self, path, size):
    	f = open(path, "w+")
    	return f.truncate(size)
    #@-node:truncate
    #@+node:mknod
    def mknod(self, path, mode, dev):
    	""" Python has no os.mknod, so we can only do some things """
    	if S_ISREG(mode):
    		open(path, "w")
    	else:
    		return -EINVAL
    #@-node:mknod
    #@+node:mkdir
    def mkdir(self, path, mode):
    	return os.mkdir(path, mode)
    #@-node:mkdir
    #@+node:utime
    def utime(self, path, times):
    	return os.utime(path, times)
    #@-node:utime
    #@+node:open
    def open(self, path, flags):
        #print "open: %s" % path
    	os.close(os.open(path, flags))
    	return 0
    
    #@-node:open
    #@+node:read
    def read(self, path, len, offset):
        #print "read: %s" % path
    	f = open(path, "r")
    	f.seek(offset)
    	return f.read(len)
    
    #@-node:read
    #@+node:write
    def write(self, path, buf, off):
        #print "write: %s" % path
    	f = open(path, "r+")
    	f.seek(off)
    	f.write(buf)
    	return len(buf)
    
    #@-node:write
    #@+node:release
    def release(self, path):
        #print "release: %s" % path
        return 0
    
    #@-node:release
    #@-others
#@-node:class Xmp
#@+node:mainline

if __name__ == '__main__':

	server = Xmp()
	server.flags = 0
	server.multithreaded = 1;
	server.main()
#@-node:mainline
#@-others
#@-node:@file xmp.py
#@-leo
