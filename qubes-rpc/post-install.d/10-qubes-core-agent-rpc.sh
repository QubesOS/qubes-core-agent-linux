#!/bin/bash

shopt -s nullglob

# announce RPC services supported by this template

# if read fails for some reason, default to full
persistence=$(qubesdb-read /qubes-vm-persistence || echo full)

if [ "$persistence" = "full" ]; then
    services_dir=/etc/qubes-rpc
elif [ "$persistence" = "rw-only" ]; then
    # report only AppVM-local services
    services_dir=/usr/local/etc/qubes-rpc
else
    # no services will survive restart, don't report
    exit 0
fi

for srv in "$services_dir"/*; do
    if [ -f "$srv" ] && [ -x "$srv" ] || [ -S "$srv" ]; then
        srv_name=${srv##*/}
        srv_name=${srv_name%%+*}
        qvm-features-request supported-rpc."${srv_name}"=1
    fi
done
