#!/usr/bin/perl
use test::helper qw($_real $_point);
use Test::More;
my (@names) = qw(abc def ghi jkl mno pqr stu jlk sfdaljk  sdfakjlsdfa kjldsf kjl;sdf akjl;asdf klj;asdf lkjsdflkjsdfkjlsdfakjsdfakjlsadfkjl;asdfklj;asdfkjl;asdfklj;asdfkjl;asdfkjlasdflkj;sadf);
@names = sort(@names);
plan tests => 2 * scalar @names;
chdir($_real);

# create entries
map { system("touch \"$_\"") } @names;

# make sure they exist in real dir
opendir(REAL,$_real);
my (@ents) = readdir(REAL);
closedir(REAL);
@ents = sort(@ents);
map {
	shift(@ents) while($ents[0] eq '.' || $ents[0] eq '..');
	is(shift(@ents),$_,"ent $_")
} @names;

# make sure they exist in fuse dir
opendir(POINT,$_point);
@ents = readdir(POINT);
closedir(POINT);
@ents = sort(@ents);
map {
	shift(@ents) while($ents[0] eq '.' || $ents[0] eq '..');
	is(shift(@ents),$_,"ent $_")
} @names;

# remove them
map { unlink } @names;
