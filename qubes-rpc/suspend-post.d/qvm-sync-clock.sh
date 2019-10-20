#!/bin/sh

if [ ! -f /var/run/qubes-service/clocksync ]; then
    /usr/bin/qvm-sync-clock
fi
