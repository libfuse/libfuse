## Process this file with automake to produce Makefile.in

bin_PROGRAMS = fusermount fuse_ioslave

fusermount_SOURCES = fusermount.c
fuse_ioslave_SOURCES = fuse_ioslave.c

install-exec-hook:
	-chown root $(DESTDIR)$(bindir)/fusermount
	-chmod u+s $(DESTDIR)$(bindir)/fusermount
