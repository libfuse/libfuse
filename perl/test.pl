#!/usr/bin/perl
BEGIN { $ENV{HARNESS_IGNORE_EXITCODE} = 1; }

use Test::Harness qw(&runtests $verbose);
$verbose=0;
die "cannot find test directory!" unless -d "test";
my (@files) = <test/*.t>;
runtests("test/s/mount.t",sort(@files),"test/s/umount.t");
