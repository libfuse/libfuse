#!/usr/bin/perl
use test::helper qw($_real $_point);
use Test::More;
plan tests => 5;
chdir($_point);
system("echo hippity >frog");
ok(-f "frog","exists");
ok(!-f "toad","target file doesn't exist");
ok(rename("frog","toad"),"rename");
ok(!-f "frog","old file doesn't exist");
ok(-f "toad","target file exists");
unlink("toad");
