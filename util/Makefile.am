## Process this file with automake to produce Makefile.in

bin_PROGRAMS = fusermount

fusermount_SOURCES = fusermount.c

install-exec-hook:
	-chown root $(DESTDIR)$(bindir)/fusermount
	-chmod u+s $(DESTDIR)$(bindir)/fusermount
	@if test ! -e $(DESTDIR)/dev/fuse; then \
		$(mkdir_p) $(DESTDIR)/dev; \
		echo "mknod $(DESTDIR)/dev/fuse -m 0666 c 10 229"; \
		mknod $(DESTDIR)/dev/fuse -m 0666 c 10 229; \
	fi

EXTRA_DIST = mount.fuse

install-exec-local:
	$(INSTALL_PROGRAM) $(srcdir)/mount.fuse $(DESTDIR)/sbin/mount.fuse

uninstall-local:
	rm -f $(DESTDIR)/sbin/mount.fuse
