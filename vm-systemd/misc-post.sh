#!/bin/sh

if [ -f /var/run/qubes-service/yum-proxy-setup -o -f /var/run/qubes-service/updates-proxy-setup ]; then
    if [ -d /etc/apt/apt.conf.d ]; then
        echo 'Acquire::http::Proxy "http://10.137.255.254:8082/";' > /etc/apt/apt.conf.d/01qubes-proxy
    fi
    if [ -d /etc/yum.conf.d ]; then
        echo proxy=http://10.137.255.254:8082/ > /etc/yum.conf.d/qubes-proxy.conf
    fi
else
    if [ -d /etc/apt/apt.conf.d ]; then
        rm -f /etc/apt/apt.conf.d/01qubes-proxy
    fi
    if [ -d /etc/yum.conf.d ]; then
        echo > /etc/yum.conf.d/qubes-proxy.conf
    fi
fi

if [ -n "`ls -A /usr/local/lib 2>/dev/null`" -o \
     -n "`ls -A /usr/local/lib64 2>/dev/null`" ]; then
    ldconfig
fi

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
