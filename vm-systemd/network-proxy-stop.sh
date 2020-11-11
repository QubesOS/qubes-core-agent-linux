#!/bin/sh

echo 0 > /proc/sys/net/ipv4/ip_forward
# disable also IPv6 forwarding, if IPv6 applicable
if [ -w /proc/sys/net/ipv6/conf/all/forwarding ]; then
    echo 0 > /proc/sys/net/ipv6/conf/all/forwarding
fi
