#!/bin/sh

# Source Qubes library.
# shellcheck source=init/functions
. /usr/lib/qubes/init/functions

/usr/lib/qubes/update-proxy-configs

if [ -n "$(ls -A /usr/local/lib 2>/dev/null)" ] || \
     [ -n "$(ls -A /usr/local/lib64 2>/dev/null)" ]; then
    ldconfig
fi

# Set IP address again (besides action in udev rules); this is needed by
# DispVM (to override DispVM-template IP) and in case when qubes-ip was
# called by udev before loading evtchn kernel module - in which case
# qubesdb-read fails
INTERFACE=eth0 /usr/lib/qubes/setup-ip

if [ -x /rw/config/rc.local ] ; then
    /rw/config/rc.local
fi
