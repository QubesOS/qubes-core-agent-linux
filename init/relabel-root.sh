#!/bin/sh --
set -eu
# shellcheck disable=SC1091
. /etc/selinux/config
echo 0 > /sys/fs/selinux/enforce
setfiles -r /mnt -- "/etc/selinux/$SELINUXTYPE/contexts/files/file_contexts" /mnt
touch /.qubes-relabeled
rm -f /.autorelabel
systemctl --force poweroff
