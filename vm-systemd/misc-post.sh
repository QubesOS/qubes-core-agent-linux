#!/bin/sh

# Source Qubes library.
# shellcheck source=init/functions
. /usr/lib/qubes/init/functions

/usr/lib/qubes/update-proxy-configs

if [ -n "$(ls -A /usr/local/lib 2>/dev/null)" ] || \
     [ -n "$(ls -A /usr/local/lib64 2>/dev/null)" ]; then
    ldconfig
fi

if [ -x /rw/config/rc.local ] ; then
    /rw/config/rc.local
fi
