#!/bin/sh

# Source Qubes library.
# shellcheck source=init/functions
. /usr/lib/qubes/init/functions

# Setup gateway for all the VMs this NetVM is servicing...
network=$(qubesdb-read /qubes-netvm-network 2>/dev/null)
if [ "x$network" != "x" ]; then

    if [ -e /proc/sys/kernel ] && ! [ -e /proc/sys/kernel/modules_disabled ]; then
        readonly modprobe_fail_cmd='true'
    else
        readonly modprobe_fail_cmd='false'
    fi

    gateway=$(qubesdb-read /qubes-netvm-gateway)
    gateway6=$(qubesdb-read /qubes-netvm-gateway6 ||:)
    #netmask=$(qubesdb-read /qubes-netvm-netmask)
    primary_dns=$(qubesdb-read /qubes-netvm-primary-dns 2>/dev/null || echo "$gateway")
    secondary_dns=$(qubesdb-read /qubes-netvm-secondary-dns)
    primary_dns6=$(qubesdb-read /qubes-netvm-primary-dns6 ||:)
    secondary_dns6=$(qubesdb-read /qubes-netvm-secondary-dns6 ||:)
    modprobe netbk 2> /dev/null || modprobe xen-netback || "${modprobe_fail_cmd}"
    if [ -n "$primary_dns6" ]; then
        echo "NS1=$primary_dns6" > /var/run/qubes/qubes-ns
        echo "NS2=$secondary_dns6" >> /var/run/qubes/qubes-ns
        echo "NS3=$primary_dns" >> /var/run/qubes/qubes-ns
        echo "NS4=$secondary_dns" >> /var/run/qubes/qubes-ns
    else
        echo "NS1=$primary_dns" > /var/run/qubes/qubes-ns
        echo "NS2=$secondary_dns" >> /var/run/qubes/qubes-ns
    fi
    /usr/lib/qubes/qubes-setup-dnat-to-ns
    echo "1" > /proc/sys/net/ipv4/ip_forward
    # enable also IPv6 forwarding, if IPv6 is enabled
    if [ -n "$gateway6" ]; then
        echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    fi
fi
