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
	my (@subs) = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
	my (@names) = qw(getattr readlink getdir mknod mkdir unlink rmdir symlink rename link chmod chown truncate utime open read write);
	my ($tmp) = 0;
	my (%mapping) = map { $_ => $tmp++ } (@names);
	my (%otherargs) = (debug=>0, threaded=>1, mountpoint=>"");
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
	perl_fuse_main($0,$otherargs{threaded},$otherargs{debug},$otherargs{mountpoint},@subs);
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
  Fuse::main(mountpoint=>$mountpoint,getattr=>\&my_getattr,getdir=>\&my_getdir, ...);

=head1 DESCRIPTION

This lets you implement filesystems in perl, through the FUSE (Filesystem in USErspace) kernel/lib interface.

FUSE expects you to implement callbacks for the various functions.

NOTE:  I have only tested the things implemented in example.pl!  It should work, but some things may not.

In the following definitions, "errno" can be 0 (for a success), -EINVAL, -ENOENT, -EONFIRE, any integer less than 1 really.
You can import standard error constants by saying something like "use POSIX qw(EDOTDOT ENOANO);".

=head2 FUNCTIONS

=head3 getattr

Arguments:  filename.
Returns a list, one of the following 4 possibilities:

$errno or

($blocks,$size,$gid,$uid,$nlink,$modes,$time) or

($errno,$blocks,$size,$gid,$uid,$nlink,$modes,$time) or

($errno,$blksize,$blocks,$size,$gid,$uid,$nlink,$modes,$time)

B<FIXME>: device numeric, for filesystems that implement mknod?

=head3 readlink

Arguments:  link pathname.
Returns a scalar: either a numeric constant, or a text string.

=head3 getdir

Arguments:  Containing directory name.
Returns a list: 0 or more text strings (the filenames), followed by errno (usually 0).

=head3 mknod

Arguments:  Filename, numeric modes, numeric device
Returns an errno (0 upon success, as usual).

=head3 mkdir

Arguments:  New directory pathname, numeric modes.
Returns an errno.

=head3 unlink

Arguments:  Filename.
Returns an errno.

=head3 rmdir

Arguments:  Pathname.
Returns an errno.

=head3 symlink

Arguments:  Existing filename, symlink name.
Returns an errno.

=head3 rename

Arguments:  old filename, new filename.
Returns an errno.

=head3 link

Arguments:  Existing filename, hardlink name.
Returns an errno.

=head3 chmod

Arguments:  Pathname, numeric modes.
Returns an errno.

=head3 chown

Arguments:  Pathname, numeric uid, numeric gid.
Returns an errno.

=head3 truncate

Arguments:  Pathname, numeric offset.
Returns an errno.

=head3 utime

Arguments:  Pathname, numeric actime, numeric modtime.
Returns an errno.

=head3 open

Arguments:  Pathname, numeric flags (which is an OR-ing of stuff like O_RDONLY and O_SYNC, constants you can import from POSIX).
Returns an errno.

=head3 read

Arguments:  Pathname, numeric requestedsize, numeric offset.
Returns a numeric errno, or a string scalar with up to $requestedsize bytes of data.

=head3 write

Arguments:  Pathname, scalar buffer, numeric offset.  You can use length($buffer) to find the buffersize.
Returns an errno.

=head2 EXPORT

None by default.

=head2 Exportable constants

None.

=head1 AUTHOR

Mark Glines, E<lt>mark@glines.orgE<gt>

=head1 SEE ALSO

L<perl>, the FUSE documentation.

=cut
