#!/usr/bin/perl
use test::helper qw($_real $_point);
use Test::More;
plan tests => 5;
chdir($_real);
ok(mkdir("dir"),"mkdir");
ok(-d "dir","dir really exists");
chdir($_point);
ok(-d "dir","dir exists");
rmdir("dir");
ok(! -d "dir","dir removed");
chdir($_real);
ok(! -d "dir","dir really removed");
