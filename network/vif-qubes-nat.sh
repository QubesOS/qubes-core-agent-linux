#!/bin/bash
# shellcheck disable=SC2154
#set -x

undetectable_netvm_ips=

netns="${vif}-nat"
netvm_if="${vif}"
netns_netvm_if="${vif}-p"
netns_appvm_if="${vif}"

#
#               .----------------------------------.
#               |          NetVM/ProxyVM           |
# .------------.|.------------------.              |
# |   AppVM    ||| $netns namespace |              |
# |            |||                  |              |
# |  eth0<--------->$netns_appvm_if |              |
# |$appvm_ip   |||   $appvm_gw_ip   |              |
# |$appvm_gw_ip|||         ^        |              |
# '------------'||         |NAT     |              |
#               ||         v        |              |
#               ||  $netns_netvm_if<--->$netvm_if  |
#               ||     $netvm_ip    |  $netvm_gw_ip|
#               |'------------------'              |
#               '----------------------------------'
#

readonly netvm_mac=fe:ff:ff:ff:ff:ff mac=00:16:3e:5e:6c:00

function run
{
    #echo "$@" >> /var/log/qubes-nat.log
    "$@"
}

function netns
{
    if [[ "$1" = 'ip' ]]; then
        shift
        run ip -n "$netns" "$@"
    else
        run ip netns exec "$netns" "$@"
    fi
}

run ip addr flush dev "$netns_appvm_if"
run ip netns delete "$netns" || :

if test "$command" = online; then
    echo 1 > "/proc/sys/net/ipv6/conf/$netns_appvm_if/disable_ipv6"
    run ip netns add "$netns"
    run ip link set "$netns_appvm_if" netns "$netns"

    # keep the same MAC as the real vif interface, so NetworkManager will still
    # ignore it.
    # for the peer interface, make sure that it has the same MAC address
    # as the actual VM, so that our neighbor entry works.
    run ip link add name "$netns_netvm_if" address "$mac" type veth \
        peer name "$netvm_if" address "$netvm_mac"
    echo 1 > "/proc/sys/net/ipv6/conf/$netns_netvm_if/disable_ipv6"
    run ip link set dev "$netns_netvm_if" netns "$netns"

    netns sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'

    if test -n "$undetectable_netvm_ips"; then
        # prevent an AppVM connecting to its own ProxyVM IP because that makes the internal IPs detectable even with no firewall rules
        more_antispoof=" ip daddr != { $netvm_ip, $netvm_gw_ip, $netvm_dns1_ip, $netvm_dns2_ip }"
    else
        more_antispoof=
    fi

    netns nft "
table netdev antispoof {
    chain antispoof {
        type filter hook ingress device $netns_appvm_if priority filter; policy drop;
        ip saddr $appvm_ip$more_antispoof ip saddr set $netvm_ip fwd to $netns_netvm_if
        arp htype 1 arp ptype ip arp hlen 6 arp plen 4 arp saddr ether $mac arp saddr ip $appvm_ip accept
        counter
    }
    chain reverse {
        type filter hook ingress device $netns_netvm_if priority filter; policy drop;
        ip daddr $netvm_ip ip daddr set $appvm_ip fwd to $netns_appvm_if
        ether type arp accept
        counter
    }
}"

    netns ip addr add "$netvm_ip" dev "$netns_netvm_if"
    netns ip addr add "$appvm_gw_ip" dev "$netns_appvm_if"

    netns ip link set "$netns_netvm_if" up
    netns ip link set "$netns_appvm_if" up
fi
