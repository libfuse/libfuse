#! /bin/sh

echo Running autoheader...
autoheader
echo Running autoconf...
autoconf

rm -f config.cache config.status
echo "To compile run './configure', and then 'make'."
