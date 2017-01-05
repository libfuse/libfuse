## Process this file with automake to produce Makefile.in

AM_CPPFLAGS = -I$(top_srcdir)/include -D_REENTRANT
noinst_PROGRAMS = test_syscalls test_write_cache test_setattr

test_write_cache_LDADD = ../lib/libfuse3.la
test_setattr_LDADD = ../lib/libfuse3.la

EXTRA_DIST = meson.build wrong_command.c

