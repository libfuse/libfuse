#!/usr/bin/perl
use test::helper qw($_point $_real $_pidfile);
use strict;
use Test::More tests => 1;
system("umount $_point");
ok(1,"unmount");
system("rm -rf $_real $_pidfile");
