#!/bin/sh

# Source Qubes library.
# shellcheck source=init/functions
. /usr/lib/qubes/init/functions

#### KVM:
. /usr/lib/qubes/hypervisor.sh
########

set -e

#### KVM:
if hypervisor xen; then
    DEVID="xvdb"
elif hypervisor kvm; then
    DEVID="vdb"
else
    exit 0
fi
########

/usr/lib/qubes/init/setup-rwdev.sh
#### KVM:
##if [ -e /dev/xvdb ] ; then mount /rw ; fi
if [ -e /dev/${DEVID} ] ; then mount /rw ; fi
########
/usr/lib/qubes/init/setup-rw.sh

initialize_home "/rw/home" ifneeded
echo "Mounting /rw/home onto /home" >&2
mount /home
echo "Mounting /rw/usrlocal onto /usr/local" >&2
mount /usr/local
/usr/lib/qubes/init/bind-dirs.sh
