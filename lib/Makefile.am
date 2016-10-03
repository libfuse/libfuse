## Process this file with automake to produce Makefile.in

AM_CPPFLAGS = -I$(top_srcdir)/include -DFUSERMOUNT_DIR=\"$(bindir)\" \
 -D_REENTRANT -DFUSE_USE_VERSION=30

lib_LTLIBRARIES = libfuse3.la

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

libfuse3_la_SOURCES =		\
	fuse.c			\
	fuse_i.h		\
	fuse_loop.c		\
	fuse_loop_mt.c		\
	fuse_lowlevel.c		\
	fuse_misc.h		\
	fuse_opt.c		\
	fuse_signals.c		\
	buffer.c		\
	cuse_lowlevel.c		\
	helper.c		\
	modules/subdir.c	\
	$(iconv_source)		\
	$(mount_source)

libfuse3_la_LDFLAGS = -pthread @libfuse_libs@ -version-number 3:0:0 \
	-Wl,--version-script,$(srcdir)/fuse_versionscript

if NETBSD
libfuse3_la_LIBADD = -lperfuse -lpuffs
endif

EXTRA_DIST = fuse_versionscript
