#!/bin/sh

/usr/lib/qubes/update-proxy-configs

# Set IP address again (besides action in udev rules); this is needed by
# DispVM (to override DispVM-template IP) and in case when qubes-ip was
# called by udev before loading evtchn kernel module - in which case
# qubesdb-read fails
INTERFACE=eth0 /usr/lib/qubes/setup-ip

[ -x /rw/config/rc.local ] && /rw/config/rc.local

# Start services which haven't own proper systemd unit:

if [ ! -f /usr/lib/systemd/system/cups.service ]; then
    if [ -f /var/run/qubes-service/cups ]; then
        /usr/sbin/service cups start
    fi
fi

exit 0
