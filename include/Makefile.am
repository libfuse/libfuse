## Process this file with automake to produce Makefile.in

fuseincludedir=$(includedir)/fuse
fuseinclude_HEADERS = fuse.h
noinst_HEADERS = fuse_kernel.h

# remove fuse.h from old place to avoid collision with new one
install-data-local:
	@if test -f $(includedir)/fuse.h; then \
		echo "Removing old FUSE header from $(includedir)/fuse.h"; \
		rm -f $(includedir)/fuse.h; \
	fi
