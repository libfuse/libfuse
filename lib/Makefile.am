## Process this file with automake to produce Makefile.in

lib_LTLIBRARIES = libfuse.la

libfuse_la_SOURCES = 	\
	fuse.c		\
	fuse_mt.c	\
	fuse_lowlevel.c	\
	helper.c	\
	mount.c		\
	fuse_i.h	\
	fuse_kernel_compat5.h

libfuse_la_LDFLAGS = -lpthread -version-number 2:3:1 \
	-Wl,--version-script,fuse_versionscript

EXTRA_DIST = fuse_versionscript
