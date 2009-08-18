## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = @subdirs2@

EXTRA_DIST =			\
	fuse.pc.in		\
	README*			\
	Filesystems		\
	FAQ			\
	doc/how-fuse-works	\
	doc/kernel.txt		\
	doc/Doxyfile

pkgconfigdir = @pkgconfigdir@
pkgconfig_DATA = fuse.pc

$(pkgconfig_DATA): config.status
