#! /bin/sh

echo Running libtoolize...
libtoolize --automake -c

if test ! -z "`which autoreconf`"; then
    echo Running autoreconf...
    autoreconf -i
else
    echo Running aclocal...
    aclocal
    echo Running autoheader...
    autoheader
    echo Running autoconf...
    autoconf
    echo Running automake...
    automake -a -c
fi

rm -f config.cache config.status
echo "To compile run './configure', and then 'make'."
