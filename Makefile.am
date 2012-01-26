## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = @subdirs2@ doc

EXTRA_DIST =			\
	fuse.pc.in		\
	README*			\
	Filesystems		\
	FAQ

pkgconfigdir = @pkgconfigdir@
pkgconfig_DATA = fuse.pc

$(pkgconfig_DATA): config.status
