#!/usr/bin/perl

use Fuse;
use POSIX qw(ENOENT EISDIR EINVAL);

my (%files) = (
	'.' => {
		type => 0040,
		mode => 0755,
		ctime => time()-1000
	},
	a => {
		cont => "File 'a'.\n",
		type => 0100,
		mode => 0755,
		ctime => time()-2000
	},
	b => {
		cont => "This is file 'b'.\n",
		type => 0100,
		mode => 0644,
		ctime => time()-1000
	},
);

sub filename_fixup {
	my ($file) = shift;
	$file =~ s,^/,,;
	$file = '.' unless length($file);
	return $file;
}

sub e_getattr {
	my ($file) = filename_fixup(shift);
	$file =~ s,^/,,;
	$file = '.' unless length($file);
	return -ENOENT() unless exists($files{$file});
	my ($size) = exists($files{$file}{cont}) ? length($files{$file}{cont}) : 0;
	my ($modes) = ($files{$file}{type}<<9) + $files{$file}{mode};
	my ($dev, $ino, $rdev, $blocks, $gid, $uid, $nlink, $blksize) = (0,0,0,1,0,0,1,1024);
	my ($atime, $ctime, $mtime);
	$atime = $ctime = $mtime = $files{$file}{ctime};
	# 2 possible types of return values:
	#return -ENOENT(); # or any other error you care to
	#print(join(",",($dev,$ino,$modes,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks)),"\n");
	return ($dev,$ino,$modes,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks);
}

sub e_getdir {
	# return as many text filenames as you like, followed by the retval.
	print((scalar keys %files)."\n");
	return (keys %files),0;
}

sub e_open {
	# VFS sanity check; it keeps all the necessary state, not much to do here.
	my ($file) = filename_fixup(shift);
	print("open called\n");
	return -ENOENT() unless exists($files{$file});
	return -EISDIR() unless exists($files{$file}{cont});
	print("open ok\n");
	return 0;
}

sub e_read {
	# return an error numeric, or binary/text string.  (note: 0 means EOF, "0" will
	# give a byte (ascii "0") to the reading program)
	my ($file) = filename_fixup(shift);
	my ($buf,$off) = @_;
	return -ENOENT() unless exists($files{$file});
	return -EINVAL() if $off > length($files{$file}{cont});
	return 0 if $off == length($files{$file}{cont});
	return substr($files{$file}{cont},$off,$buf);
}

sub e_statfs { return 255, 1, 1, 1, 1, 2 }

# If you run the script directly, it will run fusermount, which will in turn
# re-run this script.  Hence the funky semantics.
my ($mountpoint) = "";
$mountpoint = shift(@ARGV) if @ARGV;
Fuse::main(
	mountpoint=>$mountpoint,
	getattr=>\&e_getattr,
	getdir=>\&e_getdir,
	open=>\&e_open,
	statfs=>\&e_statfs,
	read=>\&e_read,
	#debug=>1, threaded=>0
);
