#!/bin/sh

UPDATEABLE=`/usr/bin/xenstore-read qubes-vm-updateable`

if [ "$UPDATEABLE" = "True" ]; then
    /usr/lib/qubes/qrexec_client_vm dom0 qubes.SyncAppMenus /bin/sh /etc/qubes-rpc/qubes.GetAppmenus
fi
