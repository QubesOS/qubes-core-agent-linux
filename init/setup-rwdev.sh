#!/bin/sh

# Source Qubes library.
# shellcheck source=init/functions
. /usr/lib/qubes/init/functions

#### KVM:
. /usr/lib/qubes/hypervisor.sh
########

set -e

#### KVM:
##dev=/dev/xvdb
if hypervisor xen; then
    dev=/dev/xvdb
elif hypervisor kvm; then
    dev=/dev/vdb
else
    exit 0
fi
########
max_size=10485760  # check at most 10 MiB

if [ -e "$dev" ] ; then
    # The private /dev/xvdb device is present.

    # check if private.img (xvdb) is empty - all zeros
    private_size=$(( $(blockdev --getsz "$dev") * 512))
    if [ $private_size -gt $max_size ]; then
        private_size=$max_size
    fi
    if cmp --bytes $private_size "$dev" /dev/zero >/dev/null && { blkid -p "$dev" >/dev/null; [ $? -eq 2 ]; }; then
        # the device is empty, create filesystem
        echo "Virgin boot of the VM: creating private.img filesystem on $dev" >&2
        # journals are only useful on reboot, so don't write one in a DispVM
        if is_dispvm ; then
            journal="-O ^has_journal"
        else
            journal="-O has_journal"
        fi
        if ! content=$(mkfs.ext4 -m 0 -q "$journal" "$dev" 2>&1) ; then
            echo "Virgin boot of the VM: creation of private.img on $dev failed:" >&2
            echo "$content" >&2
            echo "Virgin boot of the VM: aborting" >&2
            exit 1
        fi
        if ! content=$(tune2fs -m 0 "$dev" 2>&1) ; then
            echo "Virgin boot of the VM: marking free space on $dev as usable failed:" >&2
            echo "$content" >&2
            echo "Virgin boot of the VM: aborting" >&2
            exit 1
        fi
    fi

    echo "Private device management: checking $dev" >&2
    if content=$(fsck.ext4 -p "$dev" 2>&1) ; then
        echo "Private device management: fsck.ext4 of $dev succeeded" >&2
    else
        echo "Private device management: fsck.ext4 $dev failed:" >&2
        echo "$content" >&2
    fi
fi
