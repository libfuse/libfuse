## Process this file with automake to produce Makefile.in

AM_CPPFLAGS = -I$(top_srcdir)/include
noinst_PROGRAMS = fusexmp fusexmp_fh null hello hello_ll

fusexmp_SOURCES = fusexmp.c
fusexmp_fh_SOURCES = fusexmp_fh.c
null_SOURCES = null.c
hello_SOURCES = hello.c

LDADD = ../lib/libfuse.la -lpthread
