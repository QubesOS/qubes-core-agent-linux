#!/bin/sh

type nm-applet > /dev/null 2>&1 || exit 0

# Source Qubes library.
. /usr/lib/qubes/init/functions

# Hide nm-applet when network-manager is disabled
qsvc network-manager && nm_enabled=true || nm_enabled=false
gsettings set org.gnome.nm-applet show-applet $nm_enabled
