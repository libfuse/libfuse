%define kernelversion %(uname -r)
%define fusemoduledir /lib/modules/%{kernelversion}/kernel/fs/fuse

%define kernelrel %(uname -r | sed -e s/-/_/)

Name: fuse
Version: 1.0
Release: kernel_%{kernelrel}_3
Summary: Filesystem in Userspace
Source: %{name}-%{version}.tar.gz
Copyright: GPL
Group: Utilities/System
URL: http://sourceforge.net/projects/avf
Buildroot: %{_tmppath}/%{name}-root
Prefix: /usr
Packager: Achim Settelmeier <fuse-rpm@sirlab.de>

%description
FUSE (Filesystem in Userspace) is a simple interface for userspace
programs to export a virtual filesystem to the linux kernel.  FUSE
also aims to provide a secure method for non privileged users to
create and mount their own filesystem implementations.


%clean
case "$RPM_BUILD_ROOT" in *-root) rm -rf $RPM_BUILD_ROOT ;; esac

%prep
%setup

%build
./configure \
	--with-kernel=/usr/src/linux-%{kernelversion}\
	--prefix=%{prefix}
make
make check

%install
case "$RPM_BUILD_ROOT" in *-root) rm -rf $RPM_BUILD_ROOT ;; esac
make install \
	prefix=$RPM_BUILD_ROOT%{prefix} \
	fusemoduledir=$RPM_BUILD_ROOT%{fusemoduledir}

install -d $RPM_BUILD_ROOT%{prefix}/lib/fuse/example
install -s -m 755 example/{fusexmp,hello,null} $RPM_BUILD_ROOT%{prefix}/lib/fuse/example/

# remove binaries form example folder so we can include it 
# as a form of documentation into the package
make -C example clean
rm -rf example/.deps/

%post
/sbin/depmod -a

%postun
/sbin/depmod -a

%files
%defattr(-,root,root)
%doc README TODO NEWS INSTALL ChangeLog AUTHORS COPYING COPYING.LIB
%doc example/

%{fusemoduledir}
%{prefix}/lib/libfuse.a
%{prefix}/include/fuse.h
%{prefix}/lib/fuse/

# you want to install fusermount SUID root? 
# Then uncomment the "%attr()"-line in favour of the line after it.
#%attr(4500,root,root) %{prefix}/bin/fusermount
%{prefix}/bin/fusermount

