package Fuse;

use 5.006;
use strict;
use warnings;
use Errno;
use Carp;

require Exporter;
require DynaLoader;
use AutoLoader;
use Data::Dumper;
our @ISA = qw(Exporter DynaLoader);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Fuse ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	FUSE_DEBUG
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	FUSE_DEBUG
);
our $VERSION = '0.01';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.  If a constant is not found then control is passed
    # to the AUTOLOAD in AutoLoader.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "& not defined" if $constname eq 'constant';
    my $val = constant($constname, @_ ? $_[0] : 0);
    if ($! != 0) {
	if ($!{EINVAL}) {
	    $AutoLoader::AUTOLOAD = $AUTOLOAD;
	    goto &AutoLoader::AUTOLOAD;
	}
	else {
	    croak "Your vendor has not defined Fuse macro $constname";
	}
    }
    {
	no strict 'refs';
	# Fixed between 5.005_53 and 5.005_61
	if ($] >= 5.00561) {
	    *$AUTOLOAD = sub () { $val };
	}
	else {
	    *$AUTOLOAD = sub { $val };
	}
    }
    goto &$AUTOLOAD;
}

bootstrap Fuse $VERSION;

sub main {
	my (@subs) = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
	my (@names) = qw(getattr readlink getdir mknod mkdir unlink rmdir symlink
			 rename link chmod chown truncate utime open read write statfs);
	my ($tmp) = 0;
	my (%mapping) = map { $_ => $tmp++ } (@names);
	my (%otherargs) = (debug=>0, mountpoint=>"");
	while(my $name = shift) {
		my ($subref) = shift;
		if(exists($otherargs{$name})) {
			$otherargs{$name} = $subref;
		} else {
			croak "There is no function $name" unless exists($mapping{$name});
			croak "Usage: Fuse::main(getattr => &my_getattr, ...)" unless $subref;
			croak "Usage: Fuse::main(getattr => &my_getattr, ...)" unless ref($subref);
			croak "Usage: Fuse::main(getattr => &my_getattr, ...)" unless ref($subref) eq "CODE";
			$subs[$mapping{$name}] = $subref;
		}
	}
	perl_fuse_main($otherargs{debug},$otherargs{mountpoint},@subs);
}

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__

=head1 NAME

Fuse - write filesystems in Perl using FUSE

=head1 SYNOPSIS

  use Fuse;
  my ($mountpoint) = "";
  $mountpoint = shift(@ARGV) if @ARGV;
  Fuse::main(mountpoint=>$mountpoint, getattr=>\&my_getattr, getdir=>\&my_getdir, ...);

=head1 DESCRIPTION

This lets you implement filesystems in perl, through the FUSE
(Filesystem in USErspace) kernel/lib interface.

FUSE expects you to implement callbacks for the various functions.

NOTE:  I have only tested the things implemented in example.pl!
It should work, but some things may not.

In the following definitions, "errno" can be 0 (for a success),
-EINVAL, -ENOENT, -EONFIRE, any integer less than 1 really.

You can import standard error constants by saying something like
"use POSIX qw(EDOTDOT ENOANO);".

Every constant you need (file types, open() flags, error values,
etc) can be imported either from POSIX or from Fcntl, often both.
See their respective documentations, for more information.

=head2 EXPORT

None by default.

=head2 EXPORTABLE CONSTANTS

None.

=head2 FUNCTIONS

=head3 Fuse::main

Takes arguments in the form of hash key=>value pairs.  There are
many valid keys.  Most of them correspond with names of callback
functions, as described in section 'FUNCTIONS YOUR FILESYSTEM MAY IMPLEMENT'.
A few special keys also exist:


debug => boolean

=over 1

This turns FUSE call tracing on and off.  Default is 0 (which means off).

=back

mountpoint => string

=over 1

The point at which to mount this filesystem.  There is no default, you must
specify this.  An example would be '/mnt'.

=back

unthreaded => boolean

=over 1

This turns FUSE multithreading off and on.  NOTE: This perlmodule does not
currently work properly in multithreaded mode!  The author is unfortunately
not familiar enough with perl-threads internals, and according to the
documentation available at time of writing (2002-03-08), those internals are
subject to changing anyway.  Note that singlethreaded mode also means that
you will not have to worry about reentrancy, though you will have to worry
about recursive lookups (since the kernel holds a global lock on your
filesystem and blocks waiting for one callback to complete before calling
another).

I hope to add full multithreading functionality later, but for now, I
recommend you leave this option at the default, 1 (which means
unthreaded, no threads will be used and no reentrancy is needed).

=back

=head2 FUNCTIONS YOUR FILESYSTEM MAY IMPLEMENT

=head3 getattr

Arguments:  filename.
Returns a list, very similar to the 'stat' function (see
perlfunc).  On error, simply return a single numeric scalar
value (e.g. "return -ENOENT();").

FIXME: the "ino" field is currently ignored.  I tried setting it to 0
in an example script, which consistently caused segfaults.

Fields (the following was stolen from perlfunc(1) with apologies):

($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
        $atime,$mtime,$ctime,$blksize,$blocks)
                         = getattr($filename);

Here are the meaning of the fields:

 0 dev      device number of filesystem
 1 ino      inode number
 2 mode     file mode  (type and permissions)
 3 nlink    number of (hard) links to the file
 4 uid      numeric user ID of file's owner
 5 gid      numeric group ID of file's owner
 6 rdev     the device identifier (special files only)
 7 size     total size of file, in bytes
 8 atime    last access time in seconds since the epoch
 9 mtime    last modify time in seconds since the epoch
10 ctime    inode change time (NOT creation time!) in seconds
            since the epoch
11 blksize  preferred block size for file system I/O
12 blocks   actual number of blocks allocated

(The epoch was at 00:00 January 1, 1970 GMT.)

=head3 readlink

Arguments:  link pathname.
Returns a scalar: either a numeric constant, or a text string.

This is called when dereferencing symbolic links, to learn the target.

example rv: return "/proc/self/fd/stdin";

=head3 getdir

Arguments:  Containing directory name.
Returns a list: 0 or more text strings (the filenames), followed by a numeric errno (usually 0).

This is used to obtain directory listings.  Its opendir(), readdir(), filldir() and closedir() all in one call.

example rv: return ('.', 'a', 'b', 0);

=head3 mknod

Arguments:  Filename, numeric modes, numeric device
Returns an errno (0 upon success, as usual).

This function is called for all non-directory, non-symlink nodes,
not just devices.

=head3 mkdir

Arguments:  New directory pathname, numeric modes.
Returns an errno.

Called to create a directory.

=head3 unlink

Arguments:  Filename.
Returns an errno.

Called to remove a file, device, or symlink.

=head3 rmdir

Arguments:  Pathname.
Returns an errno.

Called to remove a directory.

=head3 symlink

Arguments:  Existing filename, symlink name.
Returns an errno.

Called to create a symbolic link.

=head3 rename

Arguments:  old filename, new filename.
Returns an errno.

Called to rename a file, and/or move a file from one directory to another.

=head3 link

Arguments:  Existing filename, hardlink name.
Returns an errno.

Called to create hard links.

=head3 chmod

Arguments:  Pathname, numeric modes.
Returns an errno.

Called to change permissions on a file/directory/device/symlink.

=head3 chown

Arguments:  Pathname, numeric uid, numeric gid.
Returns an errno.

Called to change ownership of a file/directory/device/symlink.

=head3 truncate

Arguments:  Pathname, numeric offset.
Returns an errno.

Called to truncate a file, at the given offset.

=head3 utime

Arguments:  Pathname, numeric actime, numeric modtime.
Returns an errno.

Called to change access/modification times for a file/directory/device/symlink.

=head3 open

Arguments:  Pathname, numeric flags (which is an OR-ing of stuff like O_RDONLY
and O_SYNC, constants you can import from POSIX).
Returns an errno.

No creation, or trunctation flags (O_CREAT, O_EXCL, O_TRUNC) will be passed to open().
Your open() method needs only check if the operation is permitted for the given flags, and return 0 for success.

=head3 read

Arguments:  Pathname, numeric requestedsize, numeric offset.
Returns a numeric errno, or a string scalar with up to $requestedsize bytes of data.

Called in an attempt to fetch a portion of the file.

=head3 write

Arguments:  Pathname, scalar buffer, numeric offset.  You can use length($buffer) to
find the buffersize.
Returns an errno.

Called in an attempt to write (or overwrite) a portion of the file.  Be prepared because $buffer could contain random binary data with NULLs and all sorts of other wonderful stuff.

=head3 statfs

Arguments:  none
Returns any of the following:

-ENOANO()

or

$namelen, $files, $files_free, $blocks, $blocks_avail, $blocksize

or

-ENOANO(), $namelen, $files, $files_free, $blocks, $blocks_avail, $blocksize

=head1 AUTHOR

Mark Glines, E<lt>mark@glines.orgE<gt>

=head1 SEE ALSO

L<perl>, the FUSE documentation.

=cut
