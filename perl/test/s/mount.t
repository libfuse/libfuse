#!/usr/bin/perl -w
use test::helper qw($_point $_loop $_real $_pidfile);
use strict;
use Test::More tests => 3;
ok(!(scalar grep(/ on $_point /,`cat /proc/mounts`)),"already mounted");
ok(-f $_loop,"loopback exists");

if(!fork()) {
	#close(STDIN);
	close(STDOUT);
	close(STDERR);
	`echo $$ >test/s/mounted.pid`;
	exec("perl $_loop $_point");
	exit(1);
}
select(undef, undef, undef, 0.5);
my ($success) = `cat /proc/mounts` =~ / $_point /;
ok($success,"mount succeeded");
system("rm -rf $_real");
unless($success) {
	kill('INT',`cat $_pidfile`);
	unlink($_pidfile);
} else {
	mkdir($_real);
}
