#!/bin/sh --

# This may fail, but that is harmless
umount --lazy /run/modules /lib/modules 2> /dev/null

# Nothing else may fail
set -eu

# Make sure permissions are correct
umask 0022
mkdir -p /run/modules /lib/.modules_work
mount -n -t ext3 -o ro /dev/xvdd /run/modules
# Mount the overlayfs.  Disable indexing to avoid a mount failure
# if indexing is on by default in the kernel configuration.
mount -t overlay libmodules /lib/modules -o lowerdir=/run/modules,upperdir=/lib/modules,workdir=/lib/.modules_work,index=off,redirect_dir=on
umount /run/modules
