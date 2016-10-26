#!/bin/sh

set -e

dev=/dev/xvdb

if [ -e "$dev" ] ; then
    # The private /dev/xvdb device is present.

    # check if private.img (xvdb) is empty - all zeros
    private_size_512=`blockdev --getsz "$dev"`
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

    echo "Private device size management: enlarging $dev" >&2
    if content=$(resize2fs "$dev" 2>&1) ; then
        echo "Private device size management: resize2fs of $dev succeeded" >&2
    else
        echo "Private device size management: resize2fs $dev failed:" >&2
        echo "$content" >&2
        echo "Private device size management: attempting to mark $dev clean" >&2
        if content=$(fsck.ext4 -fp "$dev" 2>&1) ; then
            echo "Private device size management: $dev marked clean, enlarging it again" >&2
            if content=$(resize2fs "$dev" 2>&1) ; then
                echo "Private device size management: resize2fs of $dev succeeded" >&2
            else
                echo "Private device size management: resize2fs of $dev failed even after marking file system clean:" >&2
                echo "$content" >&2
                echo "Private device size management: expect serious trouble ahead" >&2
            fi
        else
            echo "Private device size management: $dev could not be marked clean:" >&2
            echo "$content" >&2
            echo "Private device size management: expect serious trouble ahead" >&2
        fi
    fi

fi
