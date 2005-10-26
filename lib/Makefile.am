## Process this file with automake to produce Makefile.in

lib_LTLIBRARIES = libfuse.la

libfuse_la_SOURCES = 		\
	fuse.c			\
	fuse_i.h		\
	fuse_kern_chan.c	\
	fuse_loop.c		\
	fuse_loop_mt.c		\
	fuse_lowlevel.c		\
	fuse_mt.c		\
	fuse_session.c		\
	helper.c		\
	mount.c

libfuse_la_LDFLAGS = -lpthread -version-number 2:5:0 \
	-Wl,--version-script,fuse_versionscript

EXTRA_DIST = fuse_versionscript
