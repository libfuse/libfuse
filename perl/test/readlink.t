#!/usr/bin/perl
use test::helper qw($_point $_real);
use Test::More;
plan tests => 4;
chdir($_real);
ok(symlink("abc","def"),"OS supports symlinks");
is(readlink("def"),"abc","OS supports symlinks");
chdir($_point);
ok(-l "def","symlink exists");
is(readlink("def"),"abc","readlink");
unlink("def");
