## Process this file with automake to produce Makefile.in

bin_PROGRAMS = fusermount

fusermount_SOURCES = fusermount.c

install-exec-hook:
	-chown root $(DESTDIR)$(bindir)/fusermount
	-chmod u+s $(DESTDIR)$(bindir)/fusermount

EXTRA_DIST = 		\
	mount.fuse
