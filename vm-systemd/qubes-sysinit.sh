#!/bin/bash

# Source Qubes library.
# shellcheck source=init/functions
. /usr/lib/qubes/init/functions

# List of services enabled by default (in case of absence of qubesdb entry)
DEFAULT_ENABLED_NETVM="network-manager qubes-network qubes-update-check qubes-updates-proxy"
DEFAULT_ENABLED_PROXYVM="qubes-network qubes-firewall qubes-update-check"
DEFAULT_ENABLED_APPVM="cups qubes-update-check"
DEFAULT_ENABLED_TEMPLATEVM="$DEFAULT_ENABLED_APPVM updates-proxy-setup"
DEFAULT_ENABLED=""

# devices emulated by qemu, first list of vendor IDs then list of device IDs:
qemu_devices="0x8086
0x8086
0x8086
0x8086
0x8086
0x5853
0x1013
0x1237
0x7000
0x7010
0x7020
0x7113
0x0001
0x00b8
"
if [ -z "$(ls /sys/bus/pci/devices/)" ] || \
        [ "$(cat /sys/bus/pci/devices/*/{vendor,device})" != "$qemu_devices" ]; then
    # do not enable meminfo-writer (so qmemman for this domain) when any real PCI
    # device is present
    DEFAULT_ENABLED="$DEFAULT_ENABLED meminfo-writer"
    DEFAULT_ENABLED_APPVM="$DEFAULT_ENABLED_APPVM meminfo-writer"
    DEFAULT_ENABLED_PROXYVM="$DEFAULT_ENABLED_PROXYVM meminfo-writer"
    DEFAULT_ENABLED_TEMPLATEVM="$DEFAULT_ENABLED_TEMPLATEVM meminfo-writer"
fi


if systemd_version_changed ; then
    # Ensure we're running right version of systemd (the one started by initrd may be different)
    systemctl daemon-reexec
fi

# Wait for xenbus initialization
while [ ! -e /dev/xen/xenbus ] && [ -e /proc/xen/xenbus ]; do
  sleep 0.1
done

mkdir -p /var/run/qubes
chgrp qubes /var/run/qubes
chmod 0775 /var/run/qubes
mkdir -p /var/run/qubes-service
mkdir -p /var/run/xen-hotplug

# Set permissions to /proc/xen/xenbus, so normal user can talk to xenstore, to
# open vchan connection. Note that new code uses /dev/xen/xenbus (which have
# permissions set by udev), so this probably can go away soon
chmod 666 /proc/xen/xenbus

# Set permissions to /proc/xen/privcmd, so a user in qubes group can access
chmod 660 /proc/xen/privcmd
chgrp qubes /proc/xen/privcmd

[ -e /proc/u2mfn ] || modprobe u2mfn
# Set permissions to files needed by gui-agent
chmod 666 /proc/u2mfn

# Set default services depending on VM type
is_appvm && DEFAULT_ENABLED=$DEFAULT_ENABLED_APPVM && touch /var/run/qubes/this-is-appvm
is_netvm && DEFAULT_ENABLED=$DEFAULT_ENABLED_NETVM && touch /var/run/qubes/this-is-netvm
is_proxyvm && DEFAULT_ENABLED=$DEFAULT_ENABLED_PROXYVM && touch /var/run/qubes/this-is-proxyvm
is_templatevm && DEFAULT_ENABLED=$DEFAULT_ENABLED_TEMPLATEVM && touch /var/run/qubes/this-is-templatevm

# Enable default services
for srv in $DEFAULT_ENABLED; do
    touch "/var/run/qubes-service/$srv"
done

# Enable services
for srv in $(qubesdb-multiread /qubes-service/ 2>/dev/null |grep ' = 1'|cut -f 1 -d ' '); do
    touch "/var/run/qubes-service/$srv"
done

# Disable services
for srv in $(qubesdb-multiread /qubes-service/ 2>/dev/null |grep ' = 0'|cut -f 1 -d ' '); do
    rm -f "/var/run/qubes-service/$srv"
done

# Prepare environment for other services
echo > /var/run/qubes-service-environment

debug_mode=$(qubesdb-read /qubes-debug-mode 2> /dev/null)
if [ -n "$debug_mode" ] && [ "$debug_mode" -gt 0 ]; then
    echo "GUI_OPTS=-vv" >> /var/run/qubes-service-environment
fi

exit 0
