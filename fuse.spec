%define kernelversion %(uname -r)
%define fusemoduledir /lib/modules/%{kernelversion}/kernel/fs/fuse

%define kernelrel %(uname -r | sed -e s/-/_/g)
%define real_release 6

Name: fuse
Version: 1.0
Release: kernel_%{kernelrel}_%{real_release}
Summary: Filesystem in Userspace
Source: %{name}-%{version}.tar.gz
Copyright: GPL
Group: Utilities/System
URL: http://sourceforge.net/projects/avf
Buildroot: %{_tmppath}/%{name}-root
Prefix: /usr
Packager: Achim Settelmeier <fuse-rpm@sirlab.de>
# some parts of this specfile are taken from Ian Pilcher's specfile

# don't restrict to RedHat kernels but also allow compilation with 
# vanilla kernels, too.
#Requires: kernel = %{kernelrel}, redhat-release >= 7
#BuildRequires: kernel-source = %{kernelrel}


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
# invoke configure with the --with-kernel option in case we attempt to
# compile for a different kernel and hope the path is right :-)
if [ "%{kernelversion}" != $(uname -r) ]; then
	for dir in /lib/modules/%{kernelversion}/build   \
		 /usr/src/linux-%{kernelversion}         \
		 /usr/local/src/linux-%{kernelversion}   ; do 
		if [ -d "$dir" ]; then
			WITH_KERNEL="--with-kernel=$dir"
			break
		fi
	done
fi

./configure \
	--prefix=%{prefix} \
	$WITH_KERNEL
make
make check

## Now build the library as a shared object
#cd lib
#gcc -fPIC -DHAVE_CONFIG_H -I../include -Wall -W -g -O2 -c *.c
#gcc -shared -Wl,-soname,libfuse.so.%{major_ver} -o libfuse.so.%{version} *.o
#cd ..


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
/sbin/depmod -aq

%preun
/sbin/modprobe -r fuse

%postun
/sbin/depmod -aq



%files
%defattr(-,root,root)
%doc README TODO NEWS INSTALL ChangeLog AUTHORS COPYING COPYING.LIB
%doc example/ 
%doc patch/

%{fusemoduledir}
%{prefix}/lib/libfuse.a
%{prefix}/include/fuse.h
%{prefix}/lib/fuse/

# you want to install fusermount SUID root? 
# Then uncomment the "%attr()"-line in favour of the line after it.
#%attr(4500,root,root) %{prefix}/bin/fusermount
%{prefix}/bin/fusermount



%changelog

* Sun May 25 2003 Achim Settelmeier <fuse-rpm@sirlab.de>
- don't add --with-kernel in case we compile for the standard kernel

* Tue Mar 04 2003 Achim Settelmeier <fuse-rpm@sirlab.de>
- "Merged" the specfile by Ian Pilcher (Ian Pilcher <pilchman@attbi.com>) 
  and this specfile into one. Both are provided by fuse-1.0.tar.gz.

* Mon Mar 03 2003 Achim Settelmeier <fuse-rpm@sirlab.de>
- Updated specfile for RedHat 8.0 systems

