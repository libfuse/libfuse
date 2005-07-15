## Process this file with automake to produce Makefile.in

lib_LTLIBRARIES = libfuse.la

libfuse_la_SOURCES = 		\
	fuse.c			\
	fuse_mt.c		\
	fuse_lowlevel.c		\
	fuse_lowlevel_mt.c	\
	helper.c		\
	mount.c			\
	fuse_lowlevel_i.h

libfuse_la_LDFLAGS = -lpthread -version-number 2:3:1 \
	-Wl,--version-script,fuse_versionscript

EXTRA_DIST = fuse_versionscript
