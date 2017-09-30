#!/bin/sh

# Setup gateway for all the VMs this netVM is serviceing...
network=$(qubesdb-read /qubes-netvm-network 2>/dev/null)
if [ "x$network" != "x" ]; then

    if [ -e /proc/sys/kernel ] && ! [ -e /proc/sys/kernel/modules_disabled ]; then
        readonly modprobe_fail_cmd='true'
    else
        readonly modprobe_fail_cmd='false'
    fi

    gateway=$(qubesdb-read /qubes-netvm-gateway)
    #netmask=$(qubesdb-read /qubes-netvm-netmask)
    primary_dns=$(qubesdb-read /qubes-netvm-primary-dns 2>/dev/null || echo "$gateway")
    secondary_dns=$(qubesdb-read /qubes-netvm-secondary-dns)
    modprobe netbk 2> /dev/null || modprobe xen-netback || "${modprobe_fail_cmd}"
    echo "NS1=$primary_dns" > /var/run/qubes/qubes-ns
    echo "NS2=$secondary_dns" >> /var/run/qubes/qubes-ns
    /usr/lib/qubes/qubes-setup-dnat-to-ns
    echo "1" > /proc/sys/net/ipv4/ip_forward
    /sbin/ethtool -K eth0 sg off || true
fi
