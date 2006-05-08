## Process this file with automake to produce Makefile.in

AM_CPPFLAGS = -I$(top_srcdir)/include -DFUSERMOUNT_DIR=\"$(bindir)\"
lib_LTLIBRARIES = libfuse.la

if BSD
mount_source = mount_bsd.c
else
mount_source = mount.c
endif

libfuse_la_SOURCES = 		\
	fuse.c			\
	fuse_i.h		\
	fuse_kern_chan.c	\
	fuse_loop.c		\
	fuse_loop_mt.c		\
	fuse_lowlevel.c		\
	fuse_mt.c		\
	fuse_opt.c		\
	fuse_session.c		\
	fuse_signals.c		\
	helper.c		\
	$(mount_source)

libfuse_la_LDFLAGS = $(libfuse_libs) -version-number 2:6:0 \
	-Wl,--version-script,$(srcdir)/fuse_versionscript

EXTRA_DIST = fuse_versionscript
