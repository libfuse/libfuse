#!/usr/bin/perl
use test::helper qw($_point $_real);
use Test::More;
plan tests => 6;
chdir($_point);
ok(symlink("abc","def"),"symlink created");
ok(-l "def","symlink exists");
is(readlink("def"),"abc","it worked");
chdir($_real);
ok(-l "def","symlink really exists");
is(readlink("def"),"abc","really worked");
unlink("def");

# bug: doing a 'cp -a' on a directory which contains a symlink
# reports an error
mkdir("dira");
system("cd dira; touch filea; ln -s filea fileb");
is(system("cp -a dira dirb")>>8,0,"cp -a");
system("rm -rf dira dirb");
