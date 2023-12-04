#!/bin/sh

# Source Qubes library.
# shellcheck source=init/functions
. /usr/lib/qubes/init/functions

/usr/lib/qubes/update-proxy-configs

if [ -n "$(ls -A /usr/local/lib 2>/dev/null)" ] || \
     [ -n "$(ls -A /usr/local/lib64 2>/dev/null)" ]; then
    ldconfig
fi

for rc in /rw/config/rc.local.d/*.rc /rw/config/rc.local; do
    [ -f "${rc}" ] || continue
    [ -x "${rc}" ] || continue
    "${rc}"
done
unset rc
