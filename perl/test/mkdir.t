#!/usr/bin/perl
use test::helper qw($_real $_point);
use Test::More;
plan tests => 3;
chdir($_point);
ok(mkdir("dir"),"mkdir");
ok(-d "dir","dir exists");
chdir($_real);
ok(-d "dir","dir really exists");
chdir($_point);
rmdir("dir");
