#!/usr/bin/perl
package test::helper;
use strict;
use Exporter;
our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);
@ISA = "Exporter";
@EXPORT_OK = qw($_loop $_point $_pidfile $_real);
our($_loop, $_point, $_pidfile, $_real) = ("examples/loopback.pl","/mnt","test/s/mounted.pid","/tmp/fusetest");
if($0 !~ qr|s/u?mount\.t$|) {
	my ($reject) = 1;
	if(-f $_pidfile) {
		unless(system("ps `cat $_pidfile` | grep \"$_loop $_point\" >/dev/null")>>8) {
			if(`mount | grep "on $_point"`) {
				$reject = 0;
			} else {
				system("kill `cat $_pidfile`");
			}
		}
	}
	$reject = 1 if (system("ls $_point >&/dev/null") >> 8);
	die "not properly mounted\n" if $reject;
}
1;
