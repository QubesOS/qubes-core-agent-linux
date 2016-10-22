#!/bin/bash

# Source Qubes library.
. /usr/lib/qubes/init/functions

set -e

echo "Waiting for user session to quiesce." >&2
echo user | /bin/sh /etc/qubes-rpc/qubes.WaitForSession || :

echo "Possibly running save script." >&2
possibly_run_save_script

echo "Unmounting /rw filesystem." >&2
umount_retry /rw || echo "Giving up and proceeding.  Warning: this may not work." >&2

dmesg -C
qubesdb-watch /qubes-restore-complete &
watch_pid=$!
free | grep Mem: |
    (read label total used free shared buffers cached; qubesdb-write /qubes-used-mem $(( $used + $cached )) )

# we're still running in DispVM template
echo "Waiting for restore signal." >&2
qubesdb-read /qubes-restore-complete >/dev/null || wait $watch_pid
echo "Restore complete." >&2

# Reload random seed
echo "Reloading random seed." >&2
reload_random_seed
