#!/usr/bin/perl

use strict;
use Fuse;
use IO::File;
use POSIX qw(ENOENT ENOSYS EEXIST EPERM O_RDONLY O_RDWR O_APPEND O_CREAT);
use Fcntl qw(S_ISBLK S_ISCHR S_ISFIFO);

sub debug {
	print(STDERR join(",",@_),"\n");
}

sub fixup { return "/tmp/test" . shift }

sub x_getattr {
	my ($file) = fixup(shift);
	return -ENOENT() unless -e $file;
	return (lstat($file));
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
	my ($fd) = POSIX::open($file,@_);
	return -ENOSYS() if(!defined($fd));
	return $fd if $fd < 0;
	POSIX::close($fd);
	return 0;
}

sub x_read {
	my ($file,$bufsize,$off) = @_;
	debug("read",@_);
	my ($rv) = -ENOSYS();
	my ($handle) = new IO::File;
	return -ENOENT() unless -e ($file = fixup($file));
	return -ENOSYS() unless open($handle,$file);
	if(seek($handle,$off,0)) {
		read($handle,$rv,$bufsize);
	}
	debug("good");
	return $rv;
}

sub x_write {
	my ($file,$buf,$off) = @_;
	debug("write",@_);
	my ($rv);
	return -ENOENT() unless -e ($file = fixup($file));
	return -ENOSYS() unless sysopen(FILE,$file,O_RDWR()|O_APPEND()|O_CREAT());
	if(sysseek(FILE,$off,0)) { $rv = syswrite(FILE,$buf); }
	$rv = -ENOSYS() unless $rv;
	close(FILE);
	debug("good");
	return $rv;
}

sub err { return (-shift || -$!) }

sub x_readlink { return readlink(fixup(shift)                 ); }
sub x_unlink   { return unlink(fixup(shift)) ? 0 : -$!;          }
sub x_rmdir    { return err(rmdir(fixup(shift))               ); }
sub x_symlink  { return err(symlink(fixup(shift),fixup(shift))); }
sub x_rename   { return err(rename(fixup(shift),fixup(shift)) ); }
sub x_link     { return err(link(fixup(shift),fixup(shift))   ); }
sub x_chmod    { return err(chmod(fixup(shift),shift)         ); }
sub x_chown    { return err(chown(fixup(shift),shift,shift)   ); }
sub x_chmod    { return err(chmod(fixup(shift),shift)         ); }
sub x_truncate { return truncate(fixup(shift),shift) ? 0 : -$! ; }
sub x_utime    { return utime($_[1],$_[2],fixup($_[0])) ? 0:-$!; }

sub x_mkdir { my ($name, $perm) = @_; return 0 if mkdir(fixup($name),$perm); return -$!; }
sub x_rmdir { return 0 if rmdir fixup(shift); return -$!; }

sub x_mknod {
	# since this is called for ALL files, not just devices, I'll do some checks
	# and possibly run the real mknod command.
	my ($file, $modes, $dev) = @_;
	return -EEXIST() if -e ($file = fixup($file));
	return -EPERM() if (system("touch $file 2>/dev/null") >> 8);
	if(S_ISBLK($modes) || S_ISCHR($modes) || S_ISFIFO($modes)) {
		system("rm -f $file 2>/dev/null");
		my ($chr) = 'c';
		my ($omodes) = sprintf("%o",$modes & 0x1ff);
		$chr = 'b' if S_ISBLK($modes);
		if(S_ISFIFO($modes)) {
			$chr = 'p';
			$dev = "";
		} else {
			$dev = (($dev>>8) & 255) . " " . ($dev & 255);
		}
		system("mknod --mode=$omodes '$file' $chr $dev");
	}
}

my ($mountpoint) = "";
$mountpoint = shift(@ARGV) if @ARGV;
Fuse::main(mountpoint=>$mountpoint, getattr=>\&x_getattr, readlink=>\&x_readlink, getdir=>\&x_getdir, mknod=>\&x_mknod,
	mkdir=>\&x_mkdir, unlink=>\&x_unlink, rmdir=>\&x_rmdir, symlink=>\&x_symlink, rename=>\&x_rename, link=>\&x_link,
	chmod=>\&x_chmod, chown=>\&x_chown, truncate=>\&x_truncate, utime=>\&x_utime, open=>\&x_open, read=>\&x_read, write=>\&x_write
);
