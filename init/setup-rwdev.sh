#!/bin/sh

set -e

if [ -e /dev/xvdb ] ; then
    # The private /dev/xvdb device is present.

    # check if private.img (xvdb) is empty - all zeros
    private_size_512=`blockdev --getsz /dev/xvdb`
    if dd if=/dev/zero bs=512 count=$private_size_512 2>/dev/null | diff /dev/xvdb - >/dev/null; then
        # the device is empty, create filesystem
        echo "Virgin boot of the VM: creating private.img filesystem" >&2
        mkfs.ext4 -m 0 -q /dev/xvdb || exit 1
    fi

    tune2fs -m 0 /dev/xvdb
    echo "Virgin boot of the VM: marking private.img as clean" >&2
    fsck.ext4 -fp /dev/xvdb
    echo "Virgin boot of the VM: enlarging private.img" >&2
    if ! content=$(resize2fs /dev/xvdb 2>&1) ; then
        echo "resize2fs /dev/xvdb failed:" >&2
        echo "$content" >&2
    fi

fi
