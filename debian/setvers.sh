#!/bin/sh

# setvers.sh - extract version numbers from the changelog and kernel
#	source and build the control file and prerm script for the
#	pcmcia-modules package

# KSRC is expected to be passed through the environment

# adapted for fuse by Roland Bauerschmidt <rb@debian.org>

set -e
umask 022

# define some sed scripts for extracting the upstream version number
# and Debian revision number from a Debian changelog
up_vers_sed='
	1{
	  s/^[^(]*(//
	  s/)[^)]*$//
	  /-[A-Za-z0-9.+]*$/{
	    s///
	    b enddeb
	  }
	  /-/q
	  :enddeb
	  /^[A-Za-z0-9.+:-]\{1,\}$/p
	  q
	}'
fuse_vers_sed='
	/AM_INIT_AUTOMAKE(fuse, \([.0-9]*\))/{
	  s//\1/p
	  q
	}'
deb_rev_sed='
	1{
	  s/^[^(]*(//
	  s/)[^)]*$//
	  s/^.*-\([A-Za-z0-9.+]*\)$/\1/p
	  q
	}'
test "$KVERS" || \
	KVERS=`sed -ne '/UTS_RELEASE=/{
			 s///
			 p
			 q
			}' config.mk`

# extract the upstream version number and debian revision number
UPVERS=`sed -ne "$fuse_vers_sed" configure.in`
DEBREV=`sed -ne "$deb_rev_sed" debian/changelog`
NEXTVERS=${UPVERS%.*}.`expr ${UPVERS##*.} + 1`

# determine the version numbers for the kernel source
# use a Debian changelog if it exists, otherwise use the kernel version
# number determined by the PCMCIA configure script
if [ "$KDREV" ]; then
	case "$KDREV" in
	*-*)	KDEBREV=${KDREV##*-} ;;
	*)	KDEBREV="" ;;
	esac
	KVERSDEB=${KDREV%-*}
elif test -r "$KSRC/debian/changelog"; then
	KDEBREV=`sed -ne "$deb_rev_sed" "$KSRC/debian/changelog"`
	KVERSDEB=`sed -ne "$up_vers_sed" "$KSRC/debian/changelog"`
else
	KDEBREV=""
	KVERSDEB="$KVERS"
fi

# remove the epoch number (if any)
KVERSDEBNE="${KVERSDEB##*:}"

# test whether we have successfully determined the version numbers
test "$KVERS" -a "$UPVERS" -a "$DEBREV" || exit 1

echo "$KVERS" > debian/KVERS
if [ "${KVERS%%-*}" = "$KVERSDEBNE" ]; then
	MODVERS="$UPVERS-${DEBREV}${KDEBREV:+k$KDEBREV}"
else
	MODVERS="$UPVERS-${DEBREV}+"`echo "$KVERSDEBNE" | tr - +`${KDEBREV:+"+$KDEBREV"}
fi
echo "$MODVERS" > debian/MODVERS

# Generate a correct control file and prerm script for the modules package
#for script in preinst postinst prerm config templates; do
#    sed -e 's/\${kvers}/'"$KVERS"'/g
#	 s/\${kversdeb}/'"$KVERSDEB"'/g' \
#    	debian/pcmcia-modules.$script.in > debian/tmp-modules/DEBIAN/$script
#    chmod +x debian/tmp-modules/DEBIAN/$script
#done

cat debian/source.control > debian/control.tmp
filter='s/\${kvers}/'"$KVERS"'/g
	s/\${kversdeb}/'"$KVERSDEB${KDEBREV:+-$KDEBREV}"'/g'
if ! [ "${KVERS%%-*}" = "$KVERSDEBNE" -a "$KDEBREV" ]; then
    filter="$filter"'
	s/Depends: kernel-image[^)]*),/Depends:/'
fi
sed -e "$filter" debian/fuse-module.control | \
    tee -a debian/control >> debian/control.tmp

mkdir -p debian/fuse-module-$KVERS/DEBIAN
dpkg-gencontrol	-isp -v"$MODVERS" \
	-Vcurvers="$UPVERS" -Vnextvers="$NEXTVERS" \
	-p"fuse-module-$KVERS" -Pdebian/fuse-module-$KVERS \
	-cdebian/control.tmp

for i in postinst prerm; do
	sed -e "$filter" debian/fuse-module.$i > \
		debian/fuse-module-$KVERS.$i
done

exit 0
