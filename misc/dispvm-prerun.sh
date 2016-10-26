#!/bin/sh

# This script must be run as the `user` user.
# It is customarily launched from prepare-dvm.sh.

# At this point, the DispVM home directory customizations
# undertaken by mount-dirs.sh have taken place.
# We know this because dispvm-prerun.sh executes after
# local-fs.target, and mount-dirs.sh runs before it.

me=$( basename "$0" )
apps="/usr/libexec/evinced"

echo "$me started." >&2

for app in $apps ; do
    echo "Launching $app" >&2
    $app &
done

echo "Waiting for I/O to quiesce" >&2
PREV_IO=0
while true; do
	IO=`vmstat -D | awk '/read|write/ {IOs+=$1} END {print IOs}'`
	if [ $IO -lt $(( $PREV_IO + 50 )) ]; then
		break;
	fi
	PREV_IO=$IO
	sleep 2
done

echo "Closing windows" >&2
/usr/lib/qubes/close-window `xwininfo -root -children|tail -n +7 |awk '{print $1}'`
sleep 1
fuser -vkm /rw

echo "$me finished." >&2
