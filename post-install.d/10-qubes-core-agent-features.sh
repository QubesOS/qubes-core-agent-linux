#!/bin/sh

# announce features supported by this template

qvm-features-request qrexec=1

if [ -x /usr/bin/qubes-gui ]; then
    qvm-features-request gui=1
fi
