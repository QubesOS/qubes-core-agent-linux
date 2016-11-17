#!/bin/sh

# Source Qubes library.
. /usr/lib/qubes/init/functions

echo "Setting up DVM home" >&2

touch /etc/this-is-dvm

# If the user has customized DispVM settings, use its home instead of default skel
[ -e /home_volatile/user/.qubes-dispvm-customized ] && already_customized=yes || already_customized=no
[ -e /rw/home/user/.qubes-dispvm-customized ] && wants_customization=yes || wants_customization=no
if [ "$wants_customization" = "yes" ] ; then
    if [ "$already_customized" = "no" ] ; then
        echo "Customizing /home from /rw/home/user" >&2
        rm -rf /home_volatile/user
        cp -af /rw/home/user /home_volatile/user
        chown -R user.user /home_volatile/user
    fi
else
    initialize_home "/home_volatile" unconditionally
fi
