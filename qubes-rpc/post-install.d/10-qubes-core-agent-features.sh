#!/bin/sh

# announce features supported by this template

version=$(grep "^[0-9]" /usr/share/qubes/marker-vm | head -1)
qvm-features-request "qubes-agent-version=$version"

qvm-features-request qrexec=1
qvm-features-request os=Linux
qvm-features-request vmexec=1

if [ -x /usr/bin/qubes-gui ]; then
    qvm-features-request gui=1
fi

if systemctl -q is-enabled qubes-firewall.service 2>/dev/null; then
    qvm-features-request qubes-firewall=1
else
    qvm-features-request qubes-firewall=0
fi

qvm-features-request supported-service.meminfo-writer=1

if [ -e /etc/xdg/autostart/blueman.desktop ]; then
    qvm-features-request supported-service.blueman=1
fi

# native services plugged into qubes-services with systemd drop-ins, list them
# only when actual service is installed
advertise_systemd_service() {
    qsrv=$1
    shift
    for unit in "$@"; do
        if systemctl -q is-enabled "$unit" 2>/dev/null; then
            qvm-features-request supported-service."$qsrv"=1
        fi
    done
}

if [ "$(cat /sys/module/ipv6/parameters/disable_ipv6 2>/dev/null)" = "0" ] &&
   [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)" = "0" ] ; then
    qvm-features-request supported-feature.ipv6=1
fi

advertise_systemd_service network-manager NetworkManager.service \
                              network-manager.service
advertise_systemd_service modem-manager ModemManager.service
advertise_systemd_service avahi avahi-daemon.service
advertise_systemd_service crond anacron.service cron.service crond.service
advertise_systemd_service cups cups.service cups.socket org.cups.cupsd.service
advertise_systemd_service clocksync chronyd.service qubes-sync-time.service \
                              systemd-timesyncd.service
advertise_systemd_service exim4 exim4.service
advertise_systemd_service getty@tty getty@tty.service
advertise_systemd_service netfilter-persistent netfilter-persistent.service
advertise_systemd_service qubes-update-check qubes-update-check.service
advertise_systemd_service updates-proxy-setup qubes-updates-proxy-forwarder.socket
advertise_systemd_service qubes-updates-proxy qubes-updates-proxy.service
advertise_systemd_service qubes-firewall qubes-firewall.service
advertise_systemd_service qubes-network qubes-network.service
advertise_systemd_service apparmor apparmor.service
