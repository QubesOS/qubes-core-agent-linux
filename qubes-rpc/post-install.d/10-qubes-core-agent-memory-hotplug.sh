#!/bin/bash

# detect if in-vm kernel supports memory hotplug
# report for newest kernel in /boot, regardless of which one is running

shopt -s nullglob

mem_hotplug_supported=
# look for first kernel with matching config
# shellcheck disable=SC2012
for kernel in $(ls /boot/vmlinuz-* | sort -rV); do
    kver="${kernel#*/vmlinuz-}"
    if [ -e "/boot/config-$kver" ]; then
        config="/boot/config-$kver"
        if grep -q CONFIG_XEN_BALLOON_MEMORY_HOTPLUG=y "$config"; then
            mem_hotplug_supported=1
        fi
        break
    fi
done

# report both positive and negative info
qvm-features-request supported-feature.memory-hotplug="$mem_hotplug_supported"
