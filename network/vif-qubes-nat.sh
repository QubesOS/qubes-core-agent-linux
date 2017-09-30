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


function run
{
    #echo "$@" >> /var/log/qubes-nat.log
    "$@"
}

function netns
{
    run ip netns exec "$netns" "$@"
}

run ip addr flush dev "$netns_appvm_if"
run ip netns delete "$netns" || :

if test "$command" == online; then
    run ip netns add "$netns"
    run ip link set "$netns_appvm_if" netns "$netns"

    # keep the same MAC as the real vif interface, so NetworkManager will still
    # ignore it
    run ip link add "$netns_netvm_if" type veth peer name "$netvm_if" address fe:ff:ff:ff:ff:ff
    run ip link set "$netns_netvm_if" netns "$netns"

    netns ip6tables -t raw -I PREROUTING -j DROP
    netns ip6tables -P INPUT DROP
    netns ip6tables -P FORWARD DROP
    netns ip6tables -P OUTPUT DROP

    netns sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'

    netns iptables -t raw -I PREROUTING -i "$netns_appvm_if" ! -s "$appvm_ip" -j DROP

    if test -n "$undetectable_netvm_ips"; then
        # prevent an AppVM connecting to its own ProxyVM IP because that makes the internal IPs detectable even with no firewall rules
        netns iptables -t raw -I PREROUTING -i "$netns_appvm_if" -d "$netvm_ip" -j DROP

        # same for the gateway/DNS IPs
        netns iptables -t raw -I PREROUTING -i "$netns_appvm_if" -d "$netvm_gw_ip" -j DROP
        netns iptables -t raw -I PREROUTING -i "$netns_appvm_if" -d "$netvm_dns1_ip" -j DROP
        netns iptables -t raw -I PREROUTING -i "$netns_appvm_if" -d "$netvm_dns2_ip" -j DROP
    fi

    netns iptables -t nat -I PREROUTING -i "$netns_netvm_if" -j DNAT --to-destination "$appvm_ip"
    netns iptables -t nat -I POSTROUTING -o "$netns_netvm_if" -j SNAT --to-source "$netvm_ip"

    netns iptables -t nat -I PREROUTING -i "$netns_appvm_if" -d "$appvm_gw_ip" -j DNAT --to-destination "$netvm_gw_ip"
    netns iptables -t nat -I POSTROUTING -o "$netns_appvm_if" -s "$netvm_gw_ip" -j SNAT --to-source "$appvm_gw_ip"

    if test -n "$appvm_dns1_ip"; then
        netns iptables -t nat -I PREROUTING -i "$netns_appvm_if" -d "$appvm_dns1_ip" -j DNAT --to-destination "$netvm_dns1_ip"
        netns iptables -t nat -I POSTROUTING -o "$netns_appvm_if" -s "$netvm_dns1_ip" -j SNAT --to-source "$appvm_dns1_ip"
    fi

    if test -n "$appvm_dns2_ip"; then
        netns iptables -t nat -I PREROUTING -i "$netns_appvm_if" -d "$appvm_dns2_ip" -j DNAT --to-destination "$netvm_dns2_ip"
        netns iptables -t nat -I POSTROUTING -o "$netns_appvm_if" -s "$netvm_dns2_ip" -j SNAT --to-source "$appvm_dns2_ip"
    fi

    netns ip addr add "$netvm_ip" dev "$netns_netvm_if"
    netns ip addr add "$appvm_gw_ip" dev "$netns_appvm_if"

    netns ip link set "$netns_netvm_if" up
    netns ip link set "$netns_appvm_if" up

    netns ip route add "$appvm_ip" dev "$netns_appvm_if" src "$appvm_gw_ip"
    netns ip route add "$netvm_gw_ip" dev "$netns_netvm_if" src "$netvm_ip"
    netns ip route add default via "$netvm_gw_ip" dev "$netns_netvm_if" src "$netvm_ip"


    #run ip addr add "$netvm_gw_ip" dev "$netvm_if"
    #run ip link set "$netvm_if" up
    #run ip route add "$netvm_ip" dev "$netvm_if" src "$netvm_gw_ip"
fi

