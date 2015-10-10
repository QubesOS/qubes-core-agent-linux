#!/bin/sh

type nm-applet > /dev/null 2>&1 || exit 0

# Hide nm-applet when network-manager is disabled
nm_enabled=false
[ -f /var/run/qubes-service/network-manager ] && nm_enabled=true
gsettings set org.gnome.nm-applet show-applet $nm_enabled
