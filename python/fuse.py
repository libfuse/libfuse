#
#    Copyright (C) 2001  Jeff Epler  <jepler@unpythonic.dhs.org>
#
#    This program can be distributed under the terms of the GNU GPL.
#    See the file COPYING.
#

from _fuse import main, DEBUG
import os
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

