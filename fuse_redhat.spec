%define major_ver   0
%define minor_ver   95

%define spec_ver    1

%define kver %(rpm -q --queryformat %{VERSION} kernel)
%define krel %(rpm -q --queryformat %{RELEASE} kernel)
%define kverrel %{kver}-%{krel}

Name: fuse
Summary: Filesystem in USErspace
Version: %{major_ver}.%{minor_ver}
Release: %{spec_ver}
Source: http://prdownloads.sourceforge.net/avf/fuse-%{version}.tar.gz
URL: http://sourceforge.net/projects/avf
License: GPL
Group: System Environment/Kernel
Vendor: Miklos Szeredi <mszeredi@users.sourceforge.net>
Packager: Ian Pilcher <pilchman@attbi.com>
Requires: kernel = %{kverrel}, redhat-release >= 7
BuildRequires: kernel-source = %{kverrel}
BuildRoot: /var/tmp/fuser-%{version}

%description
FUSE (Filesystem in USErspace) is a simple interface for userspace
programs to export a virtual filesystem to the linux kernel.  FUSE
also aims to provide a secure method for non privileged users to
create and mount their own filesystem implementations.

%prep
%setup

%build
./configure --with-kernel=/usr/src/linux-%{kverrel}
make
# Now build the library as a shared object
cd lib
gcc -fPIC -DHAVE_CONFIG_H -I../include -Wall -W -g -O2 -c *.c
gcc -shared -Wl,-soname,libfuse.so.%{major_ver} -o libfuse.so.%{version} *.o
cd ..

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/include/
cp include/fuse.h $RPM_BUILD_ROOT/usr/include/
mkdir -p $RPM_BUILD_ROOT/lib/modules/fuse/
cp kernel/fuse.o $RPM_BUILD_ROOT/lib/modules/fuse/
mkdir -p $RPM_BUILD_ROOT/usr/lib/
cp lib/libfuse.a lib/libfuse.so.%{version} $RPM_BUILD_ROOT/usr/lib/
ln -s libfuse.so.%{version} $RPM_BUILD_ROOT/usr/lib/libfuse.so
mkdir -p $RPM_BUILD_ROOT/sbin/
cp util/fusermount $RPM_BUILD_ROOT/sbin/

%files
%attr(0644,root,root) /usr/include/fuse.h
%attr(0644,root,root) /lib/modules/fuse/fuse.o
%attr(0644,root,root) /usr/lib/libfuse.a
%attr(0755,root,root) /usr/lib/libfuse.so*
%attr(0744,root,root) /sbin/fusermount
%doc AUTHORS ChangeLog NEWS README TODO example/ patch/

%clean
rm -rf $RPM_BUILD_ROOT

%post
for a in /lib/modules/%{kverrel}*; do
    mkdir $a/kernel/fs/fuse
    ln -s /lib/modules/fuse/fuse.o $a/kernel/fs/fuse/fuse.o
done
/sbin/ldconfig
/sbin/depmod -aq

%preun
/sbin/modprobe -r fuse
for a in /lib/modules/%{kverrel}*; do
    rm -rf $a/kernel/fs/fuse
done

%postun
/sbin/ldconfig
/sbin/depmod -aq

%changelog

* Wed Feb 27 2002 Ian Pilcher <pilchman@attbi.com>
- initial SPEC file

