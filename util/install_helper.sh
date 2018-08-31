#!/bin/sh
#
# Don't call this script. It is used internally by the Meson
# build system. Thank you for your cooperation.
#

set -e

sysconfdir="$1"
bindir="$2"
udevrulesdir="$3"

# Both sysconfdir and bindir are absolute paths (since they are joined
# with --prefix in meson.build), but need to be interpreted relative
# to DESTDIR (if specified).

if [ -z "${DESTDIR}" ]; then
    # Prevent warnings about uninitialized variable
    DESTDIR=""
else
    # Get rid of duplicate slash
    DESTDIR="${DESTDIR%/}"
fi

chown root:root "${DESTDIR}${bindir}/fusermount3"
chmod u+s "${DESTDIR}${bindir}/fusermount3"

install -D -m 644 "${MESON_SOURCE_ROOT}/util/fuse.conf" \
	"${DESTDIR}${sysconfdir}/fuse.conf"


if test ! -e "${DESTDIR}/dev/fuse"; then
    mkdir -p "${DESTDIR}/dev"
    mknod "${DESTDIR}/dev/fuse" -m 0666 c 10 229
fi

install -D -m 644 "${MESON_SOURCE_ROOT}/util/udev.rules" \
        "${DESTDIR}${udevrulesdir}/99-fuse3.rules"

install -D -m 755 "${MESON_SOURCE_ROOT}/util/init_script" \
        "${DESTDIR}${sysconfdir}/init.d/fuse3"


if test -x /usr/sbin/update-rc.d && test -z "${DESTDIR}"; then
    /usr/sbin/update-rc.d fuse3 start 34 S . start 41 0 6 . || /bin/true
else
    echo "== FURTHER ACTION REQUIRED =="
    echo "Make sure that your init system will start the ${sysconfdir}/init.d/fuse3 init script"
fi


