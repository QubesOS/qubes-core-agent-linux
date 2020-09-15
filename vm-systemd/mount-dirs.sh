#!/bin/sh

# Source Qubes library.
# shellcheck source=init/functions
. /usr/lib/qubes/init/functions

set -e

/usr/lib/qubes/init/setup-rwdev.sh
if [ -e /dev/xvdb ] ; then mount /rw ; fi
/usr/lib/qubes/init/setup-rw.sh

initialize_home "/rw/home" ifneeded
echo "Mounting /rw/home onto /home" >&2
mount /home
echo "Mounting /rw/usrlocal onto /usr/local" >&2
mount /usr/local
/usr/lib/qubes/init/bind-dirs.sh
