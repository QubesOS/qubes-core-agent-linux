#!/bin/sh

command -v nm-applet > /dev/null 2>&1 || exit 0

# Source Qubes library.
# shellcheck source=init/functions
. /usr/lib/qubes/init/functions

# Run nm-applet only when network-manager is enabled
if qsvc network-manager; then
    gsettings set org.gnome.nm-applet show-applet true
    nm-applet
fi
