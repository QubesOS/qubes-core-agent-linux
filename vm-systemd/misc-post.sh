#!/bin/sh

if [ -f /var/run/qubes-service/yum-proxy-setup -o -f /var/run/qubes-service/updates-proxy-setup ]; then
    if [ -d /etc/apt/apt.conf.d ]; then
        echo 'Acquire::http::Proxy "http://10.137.255.254:8082/";' >> /etc/apt/apt.conf.d/01qubes-proxy
    fi
    if [ -d /etc/yum.conf.d ]; then
        echo proxy=http://10.137.255.254:8082/ > /etc/yum.conf.d/qubes-proxy.conf
    fi
else
    if [ -d /etc/apt/apt.conf.d ]; then
        rm -f /etc/apt/apt.conf.d/01qubes-proxy
    fi
    if [ -d /etc/yum.conf.d ]; then
        echo > /etc/yum.conf.d/qubes-proxy.conf
    fi
fi

# Set IP address again (besides action in udev rules); this is needed by
# DispVM (to override DispVM-template IP) and in case when qubes-ip was
# called by udev before loading evtchn kernel module - in which case
# xenstore-read fails
INTERFACE=eth0 /usr/lib/qubes/setup-ip

if [ -e /dev/xvdb -a ! -e /etc/this-is-dvm ] ; then
    resize2fs /dev/xvdb 2> /dev/null || echo "'resize2fs /dev/xvdb' failed"
    tune2fs -m 0 /dev/xvdb
    mount /rw

    if ! [ -d /rw/home ] ; then
        echo
        echo "--> Virgin boot of the VM: Linking /home to /rw/home"

        mkdir -p /rw/config
        touch /rw/config/rc.local
        touch /rw/config/rc.local-early

        mkdir -p /rw/home
        cp -a /home.orig/user /rw/home

        mkdir -p /rw/usrlocal
        cp -a /usr/local.orig/* /rw/usrlocal

        touch /var/lib/qubes/first-boot-completed
    fi
    # Chown home if user UID have changed - can be the case on template switch
    HOME_USER_UID=`ls -dn /rw/home/user | awk '{print $3}'`
    if [ "`id -u user`" -ne "$HOME_USER_UID" ]; then
        find /rw/home/user -uid "$HOME_USER_UID" -print0 | xargs -0 chown user:user
    fi
    if [ -L /home ]; then
        rm /home
        mkdir /home
    fi
    mount /home
fi

[ -x /rw/config/rc.local ] && /rw/config/rc.local

# Start services which haven't own proper systemd unit:

# Start AppVM specific services
if [ ! -f /etc/systemd/system/cups.service ]; then
    if [ -f /var/run/qubes-service/cups ]; then
        /usr/sbin/service cups start
        # Allow also notification icon
        sed -i -e '/^NotShowIn=.*QUBES/s/;QUBES//' /etc/xdg/autostart/print-applet.desktop
    else
        # Disable notification icon
        sed -i -e '/QUBES/!s/^NotShowIn=\(.*\)/NotShowIn=QUBES;\1/' /etc/xdg/autostart/print-applet.desktop
    fi
fi
if [ -f /var/run/qubes-service/network-manager ]; then
    # Allow also notification icon
    sed -i -e '/QUBES/!s/^OnlyShowIn=.*/\0QUBES;/' /etc/xdg/autostart/nm-applet.desktop
    sed -i -e '/^NotShowIn=.*/s/QUBES;//' /etc/xdg/autostart/nm-applet.desktop
else
    # Disable notification icon
    sed -i -e '/^OnlyShowIn=.*/s/QUBES;//' /etc/xdg/autostart/nm-applet.desktop
    sed -i -e '/QUBES/!s/^NotShowIn=.*/\0QUBES;/' /etc/xdg/autostart/nm-applet.desktop
fi

exit 0
