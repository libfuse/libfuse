#!/bin/sh
#
# Don't call this script. It is used internally by the Meson
# build system. Thank you for your cooperation.
#

set -e

sysconfdir="$1"
bindir="$2"
udevrulesdir="$3"
prefix="${MESON_INSTALL_DESTDIR_PREFIX}"

chown root:root "${prefix}/${bindir}/fusermount3"
chmod u+s "${prefix}/${bindir}/fusermount3"

if test ! -e "${DESTDIR}/dev/fuse"; then
    mkdir -p "${DESTDIR}/dev"
    mknod "${DESTDIR}/dev/fuse" -m 0666 c 10 229
fi

install -D -m 644 "${MESON_SOURCE_ROOT}/util/udev.rules" \
        "${DESTDIR}/${udevrulesdir}/udev/rules.d/99-fuse3.rules"

install -D -m 755 "${MESON_SOURCE_ROOT}/util/init_script" \
        "${DESTDIR}/etc/init.d/fuse3"

if test -x /usr/sbin/update-rc.d && test -z "${DESTDIR}"; then
    /usr/sbin/update-rc.d fuse3 start 34 S . start 41 0 6 . || /bin/true
else
    echo "== FURTHER ACTION REQUIRED =="
    echo "Make sure that your init system will start the ${DESTDIR}/etc/init.d/fuse3 init script"
fi


