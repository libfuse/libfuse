#!/usr/bin/perl
use test::helper qw($_real $_point);
use Test::More;
plan tests => 4;
my (@stat);
chdir($_point);
system("echo frog >file");
ok(chown(0,0,"file"),"set 0,0");
@stat = stat("file");
ok($stat[4] == 0 && $stat[5] == 0,"0,0");
ok(chown(1,1,"file"),"set 1,1");
@stat = stat("file");
ok($stat[4] == 1 && $stat[5] == 1,"1,1");
unlink("file");
