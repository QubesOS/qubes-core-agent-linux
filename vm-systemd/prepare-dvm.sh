#!/bin/bash

possibly_run_save_script()
{
	ENCODED_SCRIPT=$(qubesdb-read /qubes-save-script)
	if [ -z "$ENCODED_SCRIPT" ] ; then return ; fi
	echo $ENCODED_SCRIPT|perl -e 'use MIME::Base64 qw(decode_base64); local($/) = undef;print decode_base64(<STDIN>)' >/tmp/qubes-save-script
	chmod 755 /tmp/qubes-save-script
	DISPLAY=:0 su - user -c /tmp/qubes-save-script
}

if true; then
    echo user | /bin/sh /etc/qubes-rpc/qubes.WaitForSession
    possibly_run_save_script
    umount /rw
    dmesg -c >/dev/null
    qubesdb-watch /qubes-restore-complete &
    watch_pid=$!
    free | grep Mem: |
        (read label total used free shared buffers cached; qubesdb-write /qubes-used-mem $(( $used + $cached )) )
    # we're still running in DispVM template
    echo "Waiting for save/restore..."
    qubesdb-read /qubes-restore-complete || wait $watch_pid
    echo Back to life.
    systemctl --no-block restart qubes-random-seed.service
fi

