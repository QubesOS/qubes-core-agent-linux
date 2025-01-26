#!/bin/bash

# Source Qubes library.
# shellcheck source=init/functions
. /usr/lib/qubes/init/functions

set -e

/usr/lib/qubes/init/setup-rwdev.sh
if [ -e /dev/xvdb ] ; then mount /rw ; fi
/usr/lib/qubes/init/setup-rw.sh

if is_custom_persist_enabled; then
  mount_home=false
  mount_usr_local=false

  while read -r qubes_persist_entry; do
    [[ "$qubes_persist_entry" =~ \=\ /home$ ]] && mount_home=true
    [[ "$qubes_persist_entry" =~ \=\ /usr/local$ ]] && mount_usr_local=true
  done <<< "$(qubesdb-multiread /persist/)"
else
  mount_home=true
  mount_usr_local=true
fi

if $mount_home; then
  initialize_home "/rw/home" ifneeded
else
  disable_persistent_home
  initialize_home "/home" unconditionally
fi

if ! $mount_usr_local; then
  disable_persistent_usrlocal
fi

systemctl daemon-reload

