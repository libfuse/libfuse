## Process this file with automake to produce Makefile.in

AM_CPPFLAGS = -I$(top_srcdir)/include -D_REENTRANT
noinst_HEADERS = fioc.h
noinst_PROGRAMS = passthrough passthrough_fh hello hello_ll fioc fioclient \
		  fsel fselclient cusexmp passthrough_ll timefs1 timefs2 \
		  timefs3

LDADD = ../lib/libfuse3.la
passthrough_fh_LDADD = ../lib/libfuse3.la @passthrough_fh_libs@

fioclient_CPPFLAGS =
fioclient_LDFLAGS =
fioclient_LDADD =
fselclient_CPPFLAGS =
fselclient_LDFLAGS =
fselclient_LDADD =
