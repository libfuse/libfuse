#!/usr/bin/env python
#
#    Copyright (C) 2001  Jeff Epler  <jepler@unpythonic.dhs.org>
#
#    This program can be distributed under the terms of the GNU GPL.
#    See the file COPYING.
#

from _fuse import main, DEBUG
import os
from stat import *
from errno import *

class ErrnoWrapper:
	def __init__(self, func):
		self.func = func

	def __call__(self, *args, **kw):
		try:
			return apply(self.func, args, kw)
		except (IOError, OSError), detail:
			# Sometimes this is an int, sometimes an instance...
			if hasattr(detail, "errno"): detail = detail.errno
			return -detail
			
class Fuse:
	_attrs = ['getattr', 'readlink', 'getdir', 'mknod', 'mkdir',
		  'unlink', 'rmdir', 'symlink', 'rename', 'link', 'chmod',
		  'chown', 'truncate', 'utime', 'open', 'read', 'write']

	flags = 0
	multithreaded = 0
	def main(self):
		d = {'flags': self.flags}
		d['multithreaded'] = self.multithreaded
		for a in self._attrs:
			if hasattr(self,a):
				d[a] = ErrnoWrapper(getattr(self, a))
		apply(main, (), d)

class Xmp(Fuse):
	flags = 1

	def getattr(self, path):
		return os.lstat(path)

	def readlink(self, path):
		return os.readlink(path)

	def getdir(self, path):
		return map(lambda x: (x,0), os.listdir(path))

	def unlink(self, path):
		return os.unlink(path)

	def rmdir(self, path):
		return os.rmdir(path)

	def symlink(self, path, path1):
		return os.symlink(path, path1)

	def rename(self, path, path1):
		return os.rename(path, path1)

	def link(self, path, path1):
		return os.link(path, path1)

	def chmod(self, path, mode):
		return os.chmod(path, mode)

	def chown(self, path, user, group):
		return os.lchown(path, user, group)

	def truncate(self, path, size):
		f = open(path, "w+")
		return f.truncate(size)

	def mknod(self, path, mode, dev):
		""" Python has no os.mknod, so we can only do some things """
		if S_ISREG(mode):
			open(path, "w")
		else:
			return -EINVAL

	def mkdir(self, path, mode):
		return os.mkdir(path, mode)

	def utime(self, path, times):
		return os.utime(path, times)

	def open(self, path, flags):
		os.close(os.open(path, flags))
		return 0

	def read(self, path, len, offset):
		f = open(path, "r")
		f.seek(offset)
		return f.read(len)

	def write(self, path, buf, off):
		f = open(path, "r+")
		f.seek(off)
		f.write(buf)
		return len(buf)

if __name__ == '__main__':
	server = Xmp()
	server.flags = DEBUG
	server.multithreaded = 1;
	server.main()
