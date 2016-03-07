#!/bin/sh

# Setup gateway for all the VMs this netVM is serviceing...
network=$(qubesdb-read /qubes-netvm-network 2>/dev/null)
if [ "x$network" != "x" ]; then
    gateway=$(qubesdb-read /qubes-netvm-gateway)
    netmask=$(qubesdb-read /qubes-netvm-netmask)
    primary_dns=$(qubesdb-read /qubes-netvm-primary-dns 2>/dev/null || echo $gateway)
    secondary_dns=$(qubesdb-read /qubes-netvm-secondary-dns)
<<<<<<< HEAD
    modprobe netbk 2> /dev/null || modprobe xen-netback
    echo "NS1=$gateway" > /var/run/qubes/qubes-ns
=======
    modprobe netbk 2> /dev/null || modprobe xen-netback || "${modprobe_fail_cmd}"
    echo "NS1=$primary_dns" > /var/run/qubes/qubes-ns
>>>>>>> fb9b3b6... network: use `qubes-primary-dns` QubesDB entry if present
    echo "NS2=$secondary_dns" >> /var/run/qubes/qubes-ns
    /usr/lib/qubes/qubes-setup-dnat-to-ns
    echo "1" > /proc/sys/net/ipv4/ip_forward
    /sbin/ethtool -K eth0 sg off || :
fi
