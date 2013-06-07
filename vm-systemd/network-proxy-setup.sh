#!/bin/sh

# Setup gateway for all the VMs this netVM is serviceing...
network=$(/usr/bin/qubesdb-read /qubes-netvm-network 2>/dev/null)
if [ "x$network" != "x" ]; then
    gateway=$(/usr/bin/qubesdb-read /qubes-netvm-gateway)
    netmask=$(/usr/bin/qubesdb-read /qubes-netvm-netmask)
    secondary_dns=$(/usr/bin/qubesdb-read /qubes-netvm-secondary-dns)
    modprobe netbk 2> /dev/null || modprobe xen-netback
    echo "NS1=$gateway" > /var/run/qubes/qubes-ns
    echo "NS2=$secondary_dns" >> /var/run/qubes/qubes-ns
    /usr/lib/qubes/qubes-setup-dnat-to-ns
    echo "1" > /proc/sys/net/ipv4/ip_forward
    /sbin/ethtool -K eth0 sg off || :
fi
