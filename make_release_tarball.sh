#!/bin/sh
#
# Create tarball from Git tag, removing and adding
# some files.
#

set -e

if [ -z "$1" ]; then
    TAG="$(git tag --list 'fuse-3*' --sort=-creatordate | head -1)"
else
    TAG="$1"
fi
PREV_TAG="$(git tag --list 'fuse-3*' --sort=-creatordate --merged "${TAG}^"| head -1)"
MAJOR_REV=${TAG%.*}

echo "Creating release tarball for ${TAG}..."

git checkout -q "${TAG}"
doxygen doc/Doxyfile

mkdir "${TAG}"

git archive --format=tar "${TAG}" | tar -x "--directory=${TAG}"
find "${TAG}" -name .gitignore -delete
rm -r "${TAG}/make_release_tarball.sh" \
      "${TAG}/.github" \
      "${TAG}/.cirrus.yml"
cp -a doc/html "${TAG}/doc/"
tar -czf "${TAG}.tar.gz" "${TAG}/"

signify-openbsd -S -s signify/$MAJOR_REV.sec -m $TAG.tar.gz


echo "Contributors from ${PREV_TAG} to ${TAG}:"
git log --pretty="format:%an <%aE>" "${PREV_TAG}..${TAG}" | sort -u

