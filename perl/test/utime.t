#!/usr/bin/perl
use test::helper qw($_real $_point);
use Test::More;
plan tests => 3;
my (@stat);
chdir($_real);
system("echo frog >file");
chdir($_point);
ok(utime(1,2,"file"),"set utime");
@stat = stat("file");
is($stat[8],1,"atime");
is($stat[9],2,"mtime");
unlink("file");
