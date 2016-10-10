## Process this file with automake to produce Makefile.in

AM_CPPFLAGS = -I$(top_srcdir)/include -D_REENTRANT
noinst_HEADERS = ioctl.h
noinst_PROGRAMS = passthrough passthrough_fh hello hello_ll \
		  ioctl ioctl_client poll poll_client \
		  passthrough_ll notify_inval_inode \
		  notify_store_retrieve notify_inval_entry \
		  cuse cuse_client

LDADD = ../lib/libfuse3.la
passthrough_fh_LDADD = ../lib/libfuse3.la @passthrough_fh_libs@

ioctl_client_CPPFLAGS =
ioctl_client_LDFLAGS =
ioctl_client_LDADD =
poll_client_CPPFLAGS =
poll_client_LDFLAGS =
poll_client_LDADD =
