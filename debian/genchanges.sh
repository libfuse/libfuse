#!/bin/sh
# genchanges.sh - generate a changes file for a deb file generated via
#	the make-kpkg utility

# KSRC KMAINT and KEMAIL are expected to be passed through the environment

set -e
umask 022

KVERS=`cat debian/KVERS`
MODVERS=`cat debian/MODVERS`
ARCH=`dpkg --print-architecture`

{ head -2 debian/changelog
  echo "  * Built for kernel-image-${KVERS}."
  echo
  sed -ne '/^ -- / { p; q; }' debian/changelog
} > debian/changelog.tmp

# determine the maintainer's name
for name in "$KMAINT" "$DEBFULLNAME" "$DEBNAME"
    do test -n "$name" && break; done
for email in "$KEMAIL" "$DEBEMAIL"
    do test -n "$email" && break; done
if [ "$name" -a "$email" ]; then maint="$name <$email>"
elif [ "$email" ]; then maint="$email"
else maint=""; fi
    
# the changes file's name
chfile="$KSRC/../fuse-module-${KVERS}_${MODVERS}_${ARCH}.changes"

dpkg-genchanges -b ${maint:+-e"$maint"} -u"$KSRC/.." \
	-ldebian/changelog.tmp \
	-cdebian/control.tmp > "$chfile.pt"
if test -e "${GNUPGHOME:-$HOME/.gnupg/secring.gpg}" && test -x /usr/bin/gpg; then
    gpg -ast ${email:+-u"$email"} \
	--clearsign < "$chfile.pt" > "$chfile"
elif test -x /usr/bin/pgp; then
    pgp -fast ${email:+-u"$email"} +clearsig=on \
	< "$chfile.pt" > "$chfile"
fi
rm debian/changelog.tmp
rm "$chfile.pt"
