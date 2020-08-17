#!/bin/sh

# Possibly resize root device (partition, filesystem), if underlying device was
# enlarged.

#### KVM:
. /usr/lib/qubes/hypervisor.sh
########

set -e

#### KVM:
if hypervisor xen; then
    ROOTDEV="xvda"
elif hypervisor kvm; then
    ROOTDEV="vda"
else
    exit 0
fi
########

# if underlying root device is read-only, don't do anything
#### KVM:
##if [ "$(blockdev --getro /dev/xvda)" -eq "1" ]; then
##    echo "xvda is read-only, not resizing" >&2
##    exit 0
##fi
##sysfs_xvda="/sys/class/block/xvda"
if [ "$(blockdev --getro /dev/$ROOTDEV)" -eq "1" ]; then
    echo "$ROOTDEV is read-only, not resizing" >&2
    exit 0
fi
sysfs_rootdev="/sys/class/block/$ROOTDEV"
########

# if root filesystem is already using (almost) the whole disk
# 203M for BIOS and /boot data
boot_data_size=$((203 * 2 * 1024))
# rootfs size is calculated on-the-fly. `df` doesn't work because it doesn't
# include fs overhead, and calculating a static size for overhead doesn't work
# because that can change dynamically over the filesystem's lifetime.
# See QubesOS/qubes-core-agent-linux#146 and QubesOS/qubes-core-agent-linux#152
# for more details
ext4_block_count=$(dumpe2fs /dev/mapper/dmroot | grep '^Block count:' | sed -E 's/Block count:[[:space:]]+//')
ext4_block_size=$(dumpe2fs /dev/mapper/dmroot | grep '^Block size:' | sed -E 's/Block size:[[:space:]]+//')
rootfs_size=$((ext4_block_count * ext4_block_size / 512))
# 5 MB in 512-byte units for some random extra bits
size_margin=$((5 * 1024 * 2))
#### KVM:
##if [ "$(cat $sysfs_xvda/size)" -lt \
########
if [ "$(cat $sysfs_rootdev/size)" -lt \
       $(( rootfs_size + boot_data_size + size_margin )) ]; then
   echo "root filesystem already at $rootfs_size blocks" >&2
   exit 0
fi

# resize needed, do it
/usr/lib/qubes/resize-rootfs
