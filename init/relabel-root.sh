#!/bin/sh --
set -eu
. /etc/selinux/config
echo 0 > /sys/fs/selinux/enforce
setfiles -r /mnt -- "/etc/selinux/$SELINUXTYPE/contexts/files/file_contexts" /mnt
touch /.qubes-relabeled
rm -f /.autorelabel
systemctl --force poweroff
