#!/bin/bash

# Source Qubes library.
# shellcheck source=init/functions
. /usr/lib/qubes/init/functions

if is_updateable ; then
    /usr/lib/qubes/qrexec-client-vm dom0 qubes.SyncAppMenus /bin/sh /etc/qubes-rpc/qubes.GetAppmenus
fi
