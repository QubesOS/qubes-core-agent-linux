#!/bin/sh

set -e

dev=/dev/xvdb

if [ -e "$dev" ] ; then
    # The private /dev/xvdb device is present.

    # check if private.img (xvdb) is empty - all zeros
    private_size_512=$(blockdev --getsz "$dev")
    if dd if=/dev/zero bs=512 count="$private_size_512" 2>/dev/null | diff "$dev" - >/dev/null; then
        # the device is empty, create filesystem
        echo "Virgin boot of the VM: creating private.img filesystem on $dev" >&2
        if ! content=$(mkfs.ext4 -m 0 -q "$dev" 2>&1) ; then
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
