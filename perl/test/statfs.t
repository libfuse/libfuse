#!/usr/bin/perl
use test::helper qw($_real $_point);
use Test::More;
require 'syscall.ph'; # for SYS_statfs
plan tests => 7;
my ($statfs_data) = "    " x 10;
my ($tmp) = $_point;
ok(!syscall(&SYS_statfs,$tmp,$statfs_data),"statfs");
# FIXME: this is soooooo linux-centric.  perhaps parse the output of /bin/df?
my @list = unpack("LSSL8",$statfs_data);
shift(@list);
is(shift(@list),4096,"block size");
shift(@list);
is(shift(@list),1000000,"blocks");
is(shift(@list),500000,"blocks free");
shift(@list);
is(shift(@list),1000000,"files");
is(shift(@list),500000,"files free");
shift(@list);
shift(@list);
is(shift(@list),255,"namelen");
