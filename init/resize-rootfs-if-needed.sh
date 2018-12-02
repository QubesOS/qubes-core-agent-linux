#!/bin/sh

# Possibly resize root device (partition, filesystem), if underlying device was
# enlarged.

set -e

# if underlying root device is read-only, don't do anything
if [ "$(blockdev --getro /dev/xvda)" -eq "1" ]; then
    echo "xvda is read-only, not resizing" >&2
    exit 0
fi

sysfs_xvda="/sys/class/block/xvda"

# if root filesystem is already using (almost) the whole disk
# 203M for BIOS and /boot data, 222 for ext4 filesystem overhead
# See QubesOS/qubes-core-agent-linux#146 for more details
size_margin=$(((222 + 203) * 2 * 1024))
rootfs_size=$(df --block-size=512 --output=size / | tail -n 1 | tr -d ' ')
if [ "$(cat $sysfs_xvda/size)" -lt \
       $(( size_margin + rootfs_size )) ]; then
   echo "root filesystem already at $rootfs_size blocks" >&2
   exit 0
fi

# resize needed, do it
/usr/lib/qubes/resize-rootfs
