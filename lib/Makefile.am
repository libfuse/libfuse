## Process this file with automake to produce Makefile.in

lib_LTLIBRARIES = libfuse.la

libfuse_la_SOURCES = 	\
	fuse.c		\
	fuse_mt.c	\
	helper.c	\
	mount.c		\
	fuse_i.h

libfuse_la_LDFLAGS = -lpthread -version-number 3:0:0
