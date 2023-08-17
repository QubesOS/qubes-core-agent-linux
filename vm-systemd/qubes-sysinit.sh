#!/bin/bash --
set -euf

# Source Qubes library.
# shellcheck source=init/functions
. /usr/lib/qubes/init/functions

# List of services enabled by default (in case of absence of qubesdb entry)
DEFAULT_ENABLED_NETVM="network-manager qubes-network qubes-update-check qubes-updates-proxy meminfo-writer qubes-firewall"
DEFAULT_ENABLED_PROXYVM="qubes-network qubes-firewall qubes-update-check meminfo-writer"
DEFAULT_ENABLED_APPVM="qubes-update-check meminfo-writer tracker evolution-data-server"
DEFAULT_ENABLED_TEMPLATEVM="$DEFAULT_ENABLED_APPVM updates-proxy-setup"
DEFAULT_ENABLED="meminfo-writer"

# Wait for xenbus initialization
while [ ! -e /dev/xen/xenbus ]; do
  sleep 0.1
done

[ -d /sys/fs/selinux ] && selinux_flag=Z || selinux_flag=

mkdir "-p$selinux_flag" /run/qubes /run/qubes-service /run/xen-hotplug /run/xen
chgrp qubes /run/qubes
chmod 0775 /run/qubes

if [ -e /sys/module/grant_table/parameters/free_per_iteration ]; then
    echo 1000 > /sys/module/grant_table/parameters/free_per_iteration
fi

# Set default services depending on VM type
vm_type=$(qubes_vm_type)
case $vm_type in
AppVM) DEFAULT_ENABLED=$DEFAULT_ENABLED_APPVM; touch /run/qubes/this-is-appvm;;
NetVM) DEFAULT_ENABLED=$DEFAULT_ENABLED_NETVM; touch /run/qubes/this-is-netvm;;
ProxyVM) DEFAULT_ENABLED=$DEFAULT_ENABLED_PROXYVM; touch /run/qubes/this-is-proxyvm;;
TemplateVM) DEFAULT_ENABLED=$DEFAULT_ENABLED_TEMPLATEVM; touch /run/qubes/this-is-templatevm;;
DispVM) :;;
*) echo "Bad VM type $vm_type!" >&2; exit 1;;
esac

persistence=$(qubesdb-read /qubes-vm-persistence)
case $persistence in
full) touch /run/qubes/persistent-full;;
rw-only) touch /run/qubes/persistent-rw-only;;
none) touch /run/qubes/persistent-none;;
*) echo "Bad VM persistence $persistence" >&2; exit 1;;
esac

# Enable default services
for srv in $DEFAULT_ENABLED; do
    touch "/run/qubes-service/$srv"
done

IFS=$'\n'
services=$(qubesdb-multiread /qubes-service/)
for i in $services; do
    # Sanitize and parse service name
    [[ "$i" =~ ^([[:alnum:]_][[:alnum:]._-]*)\ =\ ([01])$ ]] || continue
    srv_path=/run/qubes-service/${BASH_REMATCH[1]} enabled=${BASH_REMATCH[2]}
    if (( enabled )); then
        touch "$srv_path"
    else
        rm -f "$srv_path"
    fi
done

# Prepare environment for other services
echo > /run/qubes-service-environment

exit 0
