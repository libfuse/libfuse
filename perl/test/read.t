#!/usr/bin/perl
use test::helper qw($_real $_point);
use Test::More;
plan tests => 3;
chdir($_real);
system("echo frog >file");
chdir($_point);
ok(open(FILE,"file"),"open");
my ($data) = <FILE>;
close(FILE);
is(length($data),5,"right amount read");
is($data,"frog\n","right data read");
unlink("file");
