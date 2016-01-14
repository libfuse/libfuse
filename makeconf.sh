#! /bin/sh

echo "Running libtoolize..."
libtoolize -c

# We use iconv directly rather than via gettext, so
# we need to manually copy config.rpath.
CONFIG_RPATH=/usr/share/gettext/config.rpath
if ! [ -f $CONFIG_RPATH ]; then
    CONFIG_RPATH=/usr/local/share/gettext/config.rpath
fi
if ! [ -f $CONFIG_RPATH ]; then
    if  [ -f config.rpath ]; then
        CONFIG_RPATH=
    else
        echo "config.rpath not found! - is gettext installed?" >&2
        exit 1
    fi
fi
if ! [ -z "$CONFIG_RPATH" ]; then
    cp "$CONFIG_RPATH" .
fi

echo "Running autoreconf..."
autoreconf -i

