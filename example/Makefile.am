## Process this file with automake to produce Makefile.in

AM_CPPFLAGS = -I$(top_srcdir)/include -D_REENTRANT
noinst_HEADERS = fioc.h
noinst_PROGRAMS = fusexmp fusexmp_fh null hello hello_ll fioc fioclient \
		  fsel fselclient cusexmp fuse_lo-plus timefs1 timefs2

LDADD = ../lib/libfuse3.la
fusexmp_fh_LDADD = ../lib/libfuse3.la @fusexmp_fh_libs@

fioclient_CPPFLAGS =
fioclient_LDFLAGS =
fioclient_LDADD =
fselclient_CPPFLAGS =
fselclient_LDFLAGS =
fselclient_LDADD =
