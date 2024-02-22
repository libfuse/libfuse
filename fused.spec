Name:          fused
Version:       1.0.0
Release:       1%{?relval}%{?dist}
Summary:       DAOS File System in Userspace Library

License:       LGPLv2+
URL:           https://github.com/daos-stack/fused
Source0:       https://github.com/daos-stack/%{name}/archive/refs/tags/v%{version}.tar.gz

Requires:	which
Conflicts:	filesystem < 3
BuildRequires:	libselinux-devel
BuildRequires:	autoconf, automake, libtool, gettext-devel
BuildRequires:	meson, ninja-build, systemd-udev

%description
This package builds on FUSE but implements a completely custom file
system intended for use with the DAOS file system.

%package fused-devel
Summary:	DAOS File System in Userspace based on (FUSE) v3 libraries
Group:		System Environment/Libraries
License:	LGPLv2+
Conflicts:	filesystem < 3

%description fused-devel
Provides a static user space library and headers for DAOS specific FUSE filesystem

%global debug_package %{nil}

%prep
%autosetup
find . -type f -name "*" -exec sed -i 's/fuse3/fused/g' {} ';'

%build
%meson -Ddisable-mtab=True -Dutils=False --default-library static
%meson_build

%install
export MESON_INSTALL_DESTDIR_PREFIX=%{buildroot}/usr %meson_install
find %{buildroot} .
find %{buildroot} -type f -name "*.la" -exec rm -f {} ';'

%files
%{_libdir}/libfused.a
%{_includedir}/fused/
%exclude %{_libdir}/pkgconfig

%changelog
* Mon Feb 12 2024 Jeff Olivier <jeffolivier@google.com> - 1.0.0-1.0
- Initial packaging for fused, a DAOS file system adaptation of libfuse3
