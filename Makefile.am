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

man_MANS = doc/fusermount.1 doc/mount.fuse.8 doc/ulockmgr_server.1

pkgconfigdir = @pkgconfigdir@
pkgconfig_DATA = fuse.pc

$(pkgconfig_DATA): config.status
