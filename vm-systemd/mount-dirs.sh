#!/bin/sh

# Source Qubes library.
. /usr/lib/qubes/init/functions

set -e

/usr/lib/qubes/init/setup-rwdev.sh
if [ -e /dev/xvdb ] ; then mount /rw ; fi
/usr/lib/qubes/init/setup-rw.sh

if qsvc qubes-dvm; then
    /usr/lib/qubes/init/setup-dvm-home.sh
    echo "Mounting /home_volatile onto /home" >&2
    mount --bind /home_volatile /home
else
    echo "Mounting /home" >&2
    mount /home
    # https://github.com/QubesOS/qubes-issues/issues/1328#issuecomment-169483029
    # Do none of the following in a DispVM.
    /usr/lib/qubes/init/bind-dirs.sh
fi
