## Process this file with automake to produce Makefile.in

AM_CPPFLAGS = -I$(top_srcdir)/include -DFUSERMOUNT_DIR=\"$(bindir)\" \
 -D_FILE_OFFSET_BITS=64 -D_REENTRANT -DFUSE_USE_VERSION=26

lib_LTLIBRARIES = libfuse.la libulockmgr.la

if BSD
mount_source = mount_bsd.c
else
mount_source = mount.c mount_util.c mount_util.h
endif

if ICONV
iconv_source = modules/iconv.c
else
iconv_source =
endif

libfuse_la_SOURCES = 		\
	fuse.c			\
	fuse_i.h		\
	fuse_kern_chan.c	\
	fuse_loop.c		\
	fuse_loop_mt.c		\
	fuse_lowlevel.c		\
	fuse_misc.h		\
	fuse_mt.c		\
	fuse_opt.c		\
	fuse_session.c		\
	fuse_signals.c		\
	buffer.c		\
	cuse_lowlevel.c		\
	helper.c		\
	modules/subdir.c	\
	$(iconv_source)		\
	$(mount_source)

libfuse_la_LDFLAGS = -pthread @libfuse_libs@ -version-number 2:9:2 \
	-Wl,--version-script,$(srcdir)/fuse_versionscript

if NETBSD
libfuse_la_LIBADD = -lperfuse -lpuffs
endif

libulockmgr_la_SOURCES = ulockmgr.c
libulockmgr_la_LDFLAGS = -pthread -version-number 1:0:1

EXTRA_DIST = fuse_versionscript
