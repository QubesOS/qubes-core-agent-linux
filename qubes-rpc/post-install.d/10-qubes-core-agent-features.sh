#!/bin/sh
#
# The Qubes OS Project, http://www.qubes-os.org
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#
# URL: https://github.com/dylanaraps/pfetch
# License: MIT
# Copyright (c) 2016-2019 Dylan Araps
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

# Announce features supported by this template

set -eu

qubes_version=$(grep -m1 "^[0-9]" /usr/share/qubes/marker-vm)
qvm-features-request qubes-agent-version="$qubes_version"

if [ -r /etc/os-release ]; then
    distro_like=""
    eol=""
    version=""
    while IFS='=' read -r key val; do
        val="${val##[\"\']}"
        val="${val%%[\"\']}"
        case "$key" in
            ID) distro="$val";;
            ID_LIKE) distro_like="$val";;
            VERSION_ID) version="$val";;
            SUPPORT_END) eol="$val";;
        esac
    done < /etc/os-release
    if [ -f /usr/share/kicksecure/marker ]; then
        distro="kicksecure"
        distro_like="debian"
        version=$(cat /etc/kicksecure_version)
    elif [ -f /usr/share/whonix/marker ]; then
        distro="whonix"
        distro_like="debian"
        version=$(cat /etc/whonix_version)
    fi

    # Debian/Ubuntu have it elsewhere:
    if [ -z "$eol" ] && [ -f "/usr/share/distro-info/$distro.csv" ]; then
        # debian: version,codename,series,created,release,eol,eol-lts,eol-elts
        # ubuntu: version,codename,series,created,release,eol,eol-server,eol-esm
        eol=$(grep "^$version," "/usr/share/distro-info/$distro.csv" | cut -f 6 -d ,)
    fi

    qvm-features-request os-distribution="$distro"
    qvm-features-request os-distribution-like="$distro_like"
    qvm-features-request os-version="$version"
    qvm-features-request os-eol="$eol"
fi

qvm-features-request qrexec=1
qvm-features-request os="$(uname -s)"
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

qvm-features-request supported-service.no-qubesincoming-cleanup=1
qvm-features-request supported-service.minimal-netvm=1
qvm-features-request supported-service.minimal-usbvm=1

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
