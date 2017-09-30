#!/bin/bash

# Source Qubes library.
# shellcheck source=init/functions
. /usr/lib/qubes/init/functions

if ! is_fully_persistent && test -f /etc/xdg/autostart/print-applet.desktop ; then
	if qsvc cups ; then
		# Allow also notification icon
		sed -i -e '/^NotShowIn=.*QUBES/s/;QUBES//' /etc/xdg/autostart/print-applet.desktop
	else
		# Disable notification icon
		sed -i -e '/QUBES/!s/^NotShowIn=\(.*\)/NotShowIn=QUBES;\1/' /etc/xdg/autostart/print-applet.desktop
	fi
fi
