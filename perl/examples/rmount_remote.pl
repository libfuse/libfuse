#!/usr/bin/perl

use strict;
use IO::File;
use POSIX qw(ENOENT ENOSYS EEXIST EPERM O_RDONLY O_RDWR O_APPEND O_CREAT);
use Fcntl qw(S_ISBLK S_ISCHR S_ISFIFO SEEK_SET);
use Data::Dumper;
require 'syscall.ph'; # for SYS_mknod and SYS_lchown

my ($rootdir) = @ARGV;

# strip leading and trailing slashes
$rootdir = $1 if($rootdir =~ /^\/?(.*)\/?$/);

sub fixup { return "/$rootdir" . shift }

sub x_getattr {
	my ($file) = fixup(shift);
	my (@list) = lstat($file);
	return -$! unless @list;
	return @list;
}

sub x_getdir {
	my ($dirname) = fixup(shift);
	unless(opendir(DIRHANDLE,$dirname)) {
		return -ENOENT();
	}
	my (@files) = readdir(DIRHANDLE);
	closedir(DIRHANDLE);
	return (@files, 0);
}

sub x_open {
	my ($file) = fixup(shift);
	my ($mode) = shift;
	return -$! unless sysopen(FILE,$file,$mode);
	close(FILE);
	return 0;
}

sub x_read {
	my ($file,$bufsize,$off) = @_;
	my ($rv) = -ENOSYS();
	my ($handle) = new IO::File;
	return -ENOENT() unless -e ($file = fixup($file));
	my ($fsize) = -s $file;
	return -ENOSYS() unless open($handle,$file);
	if(seek($handle,$off,SEEK_SET)) {
		read($handle,$rv,$bufsize);
	}
	return $rv;
}

sub x_write {
	my ($file,$buf,$off) = @_;
	my ($rv);
	return -ENOENT() unless -e ($file = fixup($file));
	my ($fsize) = -s $file;
	return -ENOSYS() unless open(FILE,'+<',$file);
	if($rv = seek(FILE,$off,SEEK_SET)) {
		$rv = print(FILE $buf);
	}
	$rv = -ENOSYS() unless $rv;
	close(FILE);
	return length($buf);
}

sub err { return (-shift || -$!) }

sub x_readlink { return readlink(fixup(shift)                 ); }
sub x_unlink { return unlink(fixup(shift)) ? 0 : -$!;          }
sub x_rmdir { return err(rmdir(fixup(shift))               ); }

sub x_symlink { print "symlink\n"; return symlink(shift,fixup(shift)) ? 0 : -$!; }

sub x_rename {
	my ($old) = fixup(shift);
	my ($new) = fixup(shift);
	my ($err) = rename($old,$new) ? 0 : -ENOENT();
	return $err;
}
sub x_link { return link(fixup(shift),fixup(shift)) ? 0 : -$! }
sub x_chown {
	my ($fn) = fixup(shift);
	print "nonexistent $fn\n" unless -e $fn;
	my ($uid,$gid) = @_;
	# perl's chown() does not chown symlinks, it chowns the symlink's
	# target.  it fails when the link's target doesn't exist, because
	# the stat64() syscall fails.
	# this causes error messages when unpacking symlinks in tarballs.
	my ($err) = syscall(&SYS_lchown,$fn,$uid,$gid,$fn) ? -$! : 0;
	return $err;
}
sub x_chmod {
	my ($fn) = fixup(shift);
	my ($mode) = shift;
	my ($err) = chmod($mode,$fn) ? 0 : -$!;
	return $err;
}
sub x_truncate { return truncate(fixup(shift),shift) ? 0 : -$! ; }
sub x_utime { return utime($_[1],$_[2],fixup($_[0])) ? 0:-$!; }

sub x_mkdir { my ($name, $perm) = @_; return 0 if mkdir(fixup($name),$perm); return -$!; }
sub x_rmdir { return 0 if rmdir fixup(shift); return -$!; }

sub x_mknod {
	# since this is called for ALL files, not just devices, I'll do some checks
	# and possibly run the real mknod command.
	my ($file, $modes, $dev) = @_;
	$file = fixup($file);
	$! = 0;
	syscall(&SYS_mknod,$file,$modes,$dev);
	return -$!;
}

# kludge
sub x_statfs {return 255,1000000,500000,1000000,500000,4096}

$| = 1;
my ($len);
while(read(STDIN,$len,9) == 9) {
	chomp $len;
	my ($data,$VAR1,@args);
	eval {
		$SIG{ALRM} = sub { die "timeout\n"};
		$data = "";
		alarm 5;
		read(STDIN,$data,$len-length($data),length($data))
			while(length($data) < $len);
		alarm 0;
	};
	die $@ if $@;
	eval $data;
	@args = @{$VAR1};
	my $cmd = shift(@args);
	exit 0 if $cmd eq "bye";
	die "cannot find command $cmd\n" unless exists($main::{"x_$cmd"});
	@args = $main::{"x_$cmd"}(@args);
	$cmd = Dumper(\@args)."\n";
	$cmd = sprintf("%08i\n%s",length($cmd),$cmd);
	print $cmd;
}
