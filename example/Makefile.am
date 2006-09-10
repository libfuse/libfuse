## Process this file with automake to produce Makefile.in

AM_CPPFLAGS = -I$(top_srcdir)/include
noinst_PROGRAMS = fusexmp fusexmp_fh null hello hello_ll

LDADD = ../lib/libfuse.la -lpthread
fusexmp_fh_LDADD = ../lib/libfuse.la ../lib/libulockmgr.la -lpthread
