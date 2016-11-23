## Process this file with automake to produce Makefile.in

bin_PROGRAMS = fusermount3
noinst_PROGRAMS = mount.fuse3

# we re-use mount_util.c from the library, but do want to keep ourself
# as stand-alone as possible. in order to make an out-of-source build
# possible, we "generate" the file from its original location by
# copying it over.
fusermount3_SOURCES = fusermount.c mount_util.c
fusermount3_CPPFLAGS = -I$(top_srcdir)/lib
BUILT_SOURCES = mount_util.c
mount_util.c: $(top_srcdir)/lib/mount_util.c
	@cp $(top_srcdir)/lib/mount_util.c .

mount_fuse3_SOURCES = mount.fuse.c

install-exec-hook:
	-chmod u+s $(DESTDIR)$(bindir)/fusermount3
	@if test ! -e $(DESTDIR)/dev/fuse; then \
		$(MKDIR_P) $(DESTDIR)/dev; \
		echo "mknod $(DESTDIR)/dev/fuse -m 0666 c 10 229 || true"; \
		mknod $(DESTDIR)/dev/fuse -m 0666 c 10 229 || true; \
	fi

EXTRA_DIST = udev.rules init_script

MOUNT_FUSE_PATH = @MOUNT_FUSE_PATH@
UDEV_RULES_PATH = @UDEV_RULES_PATH@
INIT_D_PATH = @INIT_D_PATH@

install-exec-local:
	$(MKDIR_P) $(DESTDIR)$(MOUNT_FUSE_PATH)
	$(INSTALL_PROGRAM) $(builddir)/mount.fuse3 $(DESTDIR)$(MOUNT_FUSE_PATH)/mount.fuse3
	$(MKDIR_P) $(DESTDIR)$(INIT_D_PATH)
	$(INSTALL_SCRIPT) $(srcdir)/init_script $(DESTDIR)$(INIT_D_PATH)/fuse3
	@if test -x /usr/sbin/update-rc.d; then \
		echo "/usr/sbin/update-rc.d fuse start 34 S . start 41 0 6 . || true"; \
		/usr/sbin/update-rc.d fuse start 34 S . start 41 0 6 . || true; \
	fi

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(UDEV_RULES_PATH)
	$(INSTALL_DATA) $(srcdir)/udev.rules $(DESTDIR)$(UDEV_RULES_PATH)/99-fuse3.rules

uninstall-local:
	rm -f $(DESTDIR)$(MOUNT_FUSE_PATH)/mount.fuse3
	rm -f $(DESTDIR)$(UDEV_RULES_PATH)/99-fuse.rules
	rm -f $(DESTDIR)$(INIT_D_PATH)/fuse
	@if test -x /usr/sbin/update-rc.d; then \
		echo "/usr/sbin/update-rc.d fuse remove || true"; \
		/usr/sbin/update-rc.d fuse remove || true; \
	fi
