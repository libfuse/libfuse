## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = @subdirs2@ doc

EXTRA_DIST =			\
	fuse3.pc.in		\
	README*

pkgconfigdir = @pkgconfigdir@
pkgconfig_DATA = fuse3.pc

$(pkgconfig_DATA): config.status
