#!/bin/sh

possibly_run_save_script()
{
	ENCODED_SCRIPT=$(qubesdb-read /qubes-save-script)
	if [ -z "$ENCODED_SCRIPT" ] ; then return ; fi
	echo $ENCODED_SCRIPT|perl -e 'use MIME::Base64 qw(decode_base64); local($/) = undef;print decode_base64(<STDIN>)' >/tmp/qubes-save-script
	chmod 755 /tmp/qubes-save-script
	Xorg -config /etc/X11/xorg-preload-apps.conf :0 &
	while ! [ -S /tmp/.X11-unix/X0 ]; do sleep 0.5; done
	DISPLAY=:0 su - user -c /tmp/qubes-save-script
	killall Xorg
}

if qubesdb-read /qubes-save-request 2>/dev/null ; then
    if [ -L /home ]; then
        rm /home
        mkdir /home
    fi
    mount --bind /home_volatile /home
    touch /etc/this-is-dvm
    mount /rw
    possibly_run_save_script
    umount /rw
    dmesg -c >/dev/null
    free | grep Mem: | 
        (read a b c d ; qubesdb-write /qubes-used-mem $c)
    # give dom0 time to read some entries, when done it will shutdown qubesdb,
    # so wait for it
    qubesdb-watch /stop-qubesdb
    # just to make sure
    systemctl stop qubes-db.service

    # we're still running in DispVM template
    echo "Waiting for save/restore..."
    # the service will start only after successful restore
    systemctl start qubes-db.service
    echo Back to life.
fi

