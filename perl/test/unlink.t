#!/usr/bin/perl
use test::helper qw($_real $_point);
use Test::More;
plan tests => 4;
chdir($_point);
system("touch file");
ok(-f "file","file exists");
chdir($_real);
ok(-f "file","file really exists");
chdir($_point);
unlink("file");
ok(! -f "file","file unlinked");
chdir($_real);
ok(! -f "file","file really unlinked");
