#!/bin/bash --
set -eu
unset SELINUXTYPE
if [ -f /etc/selinux/config ]; then
    # shellcheck disable=SC1091
    . /etc/selinux/config
fi
ctx_file=/etc/selinux/${SELINUXTYPE:-targeted}/contexts/files/file_contexts
if [ "$ctx_file" -nt /rw/.autorelabel ]; then
    restorecon -R /rw
    touch "--reference=$ctx_file" /rw/.autorelabel
fi
