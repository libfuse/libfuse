#!/usr/bin/perl
use test::helper qw($_point $_real);
use Test::More;
plan tests => 5;
chdir($_point);
ok(symlink("abc","def"),"symlink created");
ok(-l "def","symlink exists");
is(readlink("def"),"abc","it worked");
chdir($_real);
ok(-l "def","symlink really exists");
is(readlink("def"),"abc","really worked");
unlink("def");
