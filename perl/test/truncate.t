#!/usr/bin/perl
use test::helper qw($_real $_point);
use Test::More;
plan tests => 5;
chdir($_point);
system("echo hippity >womble");
ok(-f "womble","exists");
is(-s "womble",8,"right size");
ok(truncate("womble",4),"truncate");
ok(-f "womble","file exists");
is(-s "womble",4,"right size");
unlink("womble");
