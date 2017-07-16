#!/bin/sh

# announce features supported by this template

qvm-features-request qrexec=1

if [ -x /usr/bin/qubes-gui ]; then
    qvm-features-request gui=1
fi

if systemctl -q is-enabled qubes-firewall.service 2>/dev/null; then
    qvm-features-request qubes-firewall=1
else
    qvm-features-request qubes-firewall=0
fi
