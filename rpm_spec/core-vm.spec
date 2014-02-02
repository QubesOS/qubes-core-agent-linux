#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2010  Joanna Rutkowska <joanna@invisiblethingslab.com>
# Copyright (C) 2010  Rafal Wojtczuk  <rafal@invisiblethingslab.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#

%{!?version: %define version %(cat version)}

Name:		qubes-core-vm
Version:	%{version}
Release:	1%{dist}
Summary:	The Qubes core files for VM

Group:		Qubes
Vendor:		Invisible Things Lab
License:	GPL
URL:		http://www.qubes-os.org
Requires:	/usr/bin/xenstore-read
Requires:   fedora-release
Requires:   yum-plugin-post-transaction-actions
Requires:   NetworkManager >= 0.8.1-1
%if %{fedora} >= 18
# Fedora >= 18 defaults to firewalld, which isn't supported nor needed by Qubes
Requires:   iptables-services
Conflicts:  firewalld
%endif
Requires:	/usr/bin/mimeopen
Requires:   ethtool
Requires:   tinyproxy
Requires:   ntpdate
Requires:   net-tools
Requires:   nautilus-actions
Requires:   qubes-core-vm-kernel-placeholder
Requires:   qubes-utils
%if %{fedora} >= 20
# gpk-update-viewer required by qubes-manager
Requires:   gnome-packagekit-updater
%endif
Provides:   qubes-core-vm
Obsoletes:  qubes-core-commonvm
Obsoletes:  qubes-core-appvm
Obsoletes:  qubes-core-netvm
Obsoletes:  qubes-core-proxyvm
Obsoletes:  qubes-upgrade-vm < 2.0
BuildRequires: xen-devel
BuildRequires: qubes-utils-devel

%define _builddir %(pwd)

%define kde_service_dir /usr/share/kde4/services

%description
The Qubes core files for installation inside a Qubes VM.

%prep
# we operate on the current directory, so no need to unpack anything
# symlink is to generate useful debuginfo packages
rm -f %{name}-%{version}
ln -sf . %{name}-%{version}
%setup -T -D

%build
for dir in qubes-rpc qrexec misc; do
  (cd $dir; make)
done

%pre

if [ "$1" !=  1 ] ; then
# do this whole %pre thing only when updating for the first time...
exit 0
fi

mkdir -p /var/lib/qubes
if [ -e /etc/fstab ] ; then 
mv /etc/fstab /var/lib/qubes/fstab.orig
fi

adduser --create-home user

%install

(cd qrexec; make install DESTDIR=$RPM_BUILD_ROOT)
make install-vm DESTDIR=$RPM_BUILD_ROOT

%triggerin -- initscripts
if [ -e /etc/init/serial.conf ]; then
	cp /usr/lib/qubes/serial.conf /etc/init/serial.conf
fi

%post

# disable some Upstart services
for F in plymouth-shutdown prefdm splash-manager start-ttys tty ; do
	if [ -e /etc/init/$F.conf ]; then
		mv -f /etc/init/$F.conf /etc/init/$F.conf.disabled
	fi
done

remove_ShowIn () {
	if [ -e /etc/xdg/autostart/$1.desktop ]; then
		sed -i '/^\(Not\|Only\)ShowIn/d' /etc/xdg/autostart/$1.desktop
	fi
}

# don't want it at all
for F in abrt-applet deja-dup-monitor imsettings-start krb5-auth-dialog pulseaudio restorecond sealertauto gnome-power-manager gnome-sound-applet gnome-screensaver orca-autostart; do
	if [ -e /etc/xdg/autostart/$F.desktop ]; then
		remove_ShowIn $F
		echo 'NotShowIn=QUBES;' >> /etc/xdg/autostart/$F.desktop
	fi
done

# don't want it in DisposableVM
for F in gcm-apply ; do
	if [ -e /etc/xdg/autostart/$F.desktop ]; then
		remove_ShowIn $F
		echo 'NotShowIn=DisposableVM;' >> /etc/xdg/autostart/$F.desktop
	fi
done

# want it in AppVM only
for F in gnome-keyring-gpg gnome-keyring-pkcs11 gnome-keyring-secrets gnome-keyring-ssh gnome-settings-daemon user-dirs-update-gtk gsettings-data-convert ; do
	if [ -e /etc/xdg/autostart/$F.desktop ]; then
		remove_ShowIn $F
		echo 'OnlyShowIn=GNOME;AppVM;' >> /etc/xdg/autostart/$F.desktop
	fi
done

# remove existing rule to add own later
for F in gpk-update-icon nm-applet ; do
	remove_ShowIn $F
done

echo 'OnlyShowIn=GNOME;UpdateableVM;' >> /etc/xdg/autostart/gpk-update-icon.desktop || :
echo 'OnlyShowIn=GNOME;NetVM;' >> /etc/xdg/autostart/nm-applet.desktop || :

usermod -p '' root
usermod -L user

# Create NetworkManager configuration if we do not have it
if ! [ -e /etc/NetworkManager/NetworkManager.conf ]; then
echo '[main]' > /etc/NetworkManager/NetworkManager.conf
echo 'plugins = keyfile' >> /etc/NetworkManager/NetworkManager.conf
echo '[keyfile]' >> /etc/NetworkManager/NetworkManager.conf
fi
/usr/lib/qubes/qubes-fix-nm-conf.sh


# Remove ip_forward setting from sysctl, so NM will not reset it
sed 's/^net.ipv4.ip_forward.*/#\0/'  -i /etc/sysctl.conf

# Install firmware link only on system which haven't it yet
if ! [ -e /lib/firmware/updates ]; then
  ln -s /lib/modules/firmware /lib/firmware/updates
fi

if ! grep -q '/etc/yum\.conf\.d/qubes-proxy\.conf' /etc/yum.conf; then
  echo >> /etc/yum.conf
  echo '# Yum does not support inclusion of config dir...' >> /etc/yum.conf
  echo 'include=file:///etc/yum.conf.d/qubes-proxy.conf' >> /etc/yum.conf
fi

# Revert 'Prevent unnecessary updates in VMs':
sed -i -e '/^exclude = kernel/d' /etc/yum.conf

# qubes-core-vm has been broken for some time - it overrides /etc/hosts; restore original content
if ! grep -q localhost /etc/hosts; then
  cat <<EOF > /etc/hosts
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4 `hostname`
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
EOF
fi

if [ "$1" !=  1 ] ; then
# do the rest of %post thing only when updating for the first time...
exit 0
fi

if [ -e /etc/init/serial.conf ] && ! [ -f /var/lib/qubes/serial.orig ] ; then
	cp /etc/init/serial.conf /var/lib/qubes/serial.orig
fi

#echo "--> Disabling SELinux..."
sed -e s/^SELINUX=.*$/SELINUX=disabled/ </etc/selinux/config >/etc/selinux/config.processed
mv /etc/selinux/config.processed /etc/selinux/config
setenforce 0 2>/dev/null

# Remove most of the udev scripts to speed up the VM boot time
# Just leave the xen* scripts, that are needed if this VM was
# ever used as a net backend (e.g. as a VPN domain in the future)
#echo "--> Removing unnecessary udev scripts..."
mkdir -p /var/lib/qubes/removed-udev-scripts
for f in /etc/udev/rules.d/*
do
    if [ $(basename $f) == "xen-backend.rules" ] ; then
        continue
    fi

    if [ $(basename $f) == "50-qubes-misc.rules" ] ; then
        continue
    fi

    if echo $f | grep -q qubes; then
        continue
    fi

    mv $f /var/lib/qubes/removed-udev-scripts/
done
mkdir -p /rw
#rm -f /etc/mtab
#echo "--> Removing HWADDR setting from /etc/sysconfig/network-scripts/ifcfg-eth0"
#mv /etc/sysconfig/network-scripts/ifcfg-eth0 /etc/sysconfig/network-scripts/ifcfg-eth0.orig
#grep -v HWADDR /etc/sysconfig/network-scripts/ifcfg-eth0.orig > /etc/sysconfig/network-scripts/ifcfg-eth0

%preun
if [ "$1" = 0 ] ; then
    # no more packages left
    if [ -e /var/lib/qubes/fstab.orig ] ; then
    mv /var/lib/qubes/fstab.orig /etc/fstab
    fi
    mv /var/lib/qubes/removed-udev-scripts/* /etc/udev/rules.d/
    if [ -e /var/lib/qubes/serial.orig ] ; then
    mv /var/lib/qubes/serial.orig /etc/init/serial.conf
    fi
fi

%postun
if [ $1 -eq 0 ] ; then
    /usr/bin/glib-compile-schemas %{_datadir}/glib-2.0/schemas &> /dev/null || :

    if [ -l /lib/firmware/updates ]; then
      rm /lib/firmware/updates
    fi
fi

%posttrans
    /usr/bin/glib-compile-schemas %{_datadir}/glib-2.0/schemas &> /dev/null || :

%clean
rm -rf $RPM_BUILD_ROOT
rm -f %{name}-%{version}

%files
%defattr(-,root,root,-)
%dir /var/lib/qubes
%dir /var/run/qubes
%dir %attr(0775,user,user) /var/lib/qubes/dom0-updates
%{kde_service_dir}/qvm-copy.desktop
%{kde_service_dir}/qvm-dvm.desktop
/etc/NetworkManager/dispatcher.d/30-qubes-external-ip
/etc/NetworkManager/dispatcher.d/qubes-nmhook
/etc/X11/xorg-preload-apps.conf
/etc/dispvm-dotfiles.tbz
/etc/dhclient.d/qubes-setup-dnat-to-ns.sh
/etc/fstab
/etc/pki/rpm-gpg/RPM-GPG-KEY-qubes*
/etc/polkit-1/localauthority/50-local.d/qubes-allow-all.pkla
/etc/polkit-1/rules.d/00-qubes-allow-all.rules
%dir /etc/qubes-rpc
/etc/qubes-rpc/qubes.Filecopy
/etc/qubes-rpc/qubes.OpenInVM
/etc/qubes-rpc/qubes.GetAppmenus
/etc/qubes-rpc/qubes.VMShell
/etc/qubes-rpc/qubes.SyncNtpClock
/etc/qubes-rpc/qubes.SuspendPre
/etc/qubes-rpc/qubes.SuspendPost
/etc/qubes-rpc/qubes.WaitForSession
/etc/qubes-rpc/qubes.DetachPciDevice
/etc/qubes-rpc/qubes.Backup
/etc/qubes-rpc/qubes.Restore
/etc/qubes-rpc/qubes.SelectFile
/etc/qubes-rpc/qubes.SelectDirectory
/etc/sudoers.d/qubes
%config(noreplace) /etc/sysconfig/iptables
%config(noreplace) /etc/sysconfig/ip6tables
/etc/sysconfig/modules/qubes-core.modules
/etc/sysconfig/modules/qubes-misc.modules
%config(noreplace) /etc/tinyproxy/filter-qubes-yum
%config(noreplace) /etc/tinyproxy/tinyproxy-qubes-yum.conf
/etc/udev/rules.d/50-qubes-misc.rules
/etc/udev/rules.d/99-qubes-network.rules
/etc/xdg/nautilus-actions/nautilus-actions.conf
/etc/xen/scripts/vif-route-qubes
%config(noreplace) /etc/yum.conf.d/qubes-proxy.conf
%config(noreplace) /etc/yum.repos.d/qubes-r2-beta2.repo
%config(noreplace) /etc/yum.repos.d/qubes-r2-beta3.repo
/etc/yum/pluginconf.d/yum-qubes-hooks.conf
/etc/yum/post-actions/qubes-trigger-sync-appmenus.action
/usr/sbin/qubes-serial-login
/usr/bin/qvm-copy-to-vm
/usr/bin/qvm-open-in-dvm
/usr/bin/qvm-open-in-vm
/usr/bin/qvm-run
/usr/bin/qvm-mru-entry
/usr/bin/xenstore-watch-qubes
%dir /usr/lib/qubes
/usr/lib/qubes/vusb-ctl.py*
/usr/lib/qubes/dispvm-prerun.sh
/usr/lib/qubes/sync-ntp-clock
/usr/lib/qubes/prepare-suspend
/usr/lib/qubes/network-manager-prepare-conf-dir
/usr/lib/qubes/qrexec-agent
/usr/lib/qubes/qrexec-client-vm
/usr/lib/qubes/qrexec_client_vm
/usr/lib/qubes/qubes-rpc-multiplexer
/usr/lib/qubes/qfile-agent
%attr(4755,root,root) /usr/lib/qubes/qfile-unpacker
/usr/lib/qubes/qopen-in-vm
/usr/lib/qubes/qrun-in-vm
/usr/lib/qubes/qubes-download-dom0-updates.sh
/usr/lib/qubes/qubes-fix-nm-conf.sh
/usr/lib/qubes/qubes-setup-dnat-to-ns
/usr/lib/qubes/qubes-trigger-sync-appmenus.sh
/usr/lib/qubes/qvm-copy-to-vm.gnome
/usr/lib/qubes/qvm-copy-to-vm.kde
/usr/lib/qubes/serial.conf
/usr/lib/qubes/setup-ip
/usr/lib/qubes/tar2qfile
/usr/lib/qubes/vm-file-editor
/usr/lib/qubes/wrap-in-html-if-url.sh
/usr/lib/qubes/iptables-yum-proxy
/usr/lib/yum-plugins/yum-qubes-hooks.py*
/usr/sbin/qubes-firewall
/usr/sbin/qubes-netwatcher
/usr/share/glib-2.0/schemas/org.gnome.settings-daemon.plugins.updates.gschema.override
/usr/share/file-manager/actions/qvm-copy-gnome.desktop
/usr/share/file-manager/actions/qvm-dvm-gnome.desktop
%dir /usr/share/qubes
/usr/share/qubes/mime-override/globs
%dir /home_volatile
%attr(700,user,user) /home_volatile/user
%dir /mnt/removable

%package sysvinit
Summary:        Qubes unit files for SysV init style or upstart
License:        GPL v2 only
Group:          Qubes
Requires:       upstart
Requires:       qubes-core-vm
Provides:       qubes-core-vm-init-scripts
Conflicts:      qubes-core-vm-systemd

%description sysvinit
The Qubes core startup configuration for SysV init (or upstart).

%files sysvinit
/etc/init.d/qubes-core
/etc/init.d/qubes-core-appvm
/etc/init.d/qubes-core-netvm
/etc/init.d/qubes-firewall
/etc/init.d/qubes-netwatcher
/etc/init.d/qubes-yum-proxy
/etc/init.d/qubes-qrexec-agent

%post sysvinit

#echo "--> Turning off unnecessary services..."
# FIXME: perhaps there is more elegant way to do this?
for f in /etc/init.d/*
do
        srv=`basename $f`
        [ $srv = 'functions' ] && continue
        [ $srv = 'killall' ] && continue
        [ $srv = 'halt' ] && continue
        [ $srv = 'single' ] && continue
        [ $srv = 'reboot' ] && continue
        [ $srv = 'qubes-gui' ] && continue
        chkconfig $srv off
done

#echo "--> Enabling essential services..."
chkconfig rsyslog on
chkconfig haldaemon on
chkconfig messagebus on
chkconfig iptables on
chkconfig ip6tables on
chkconfig --add qubes-core || echo "WARNING: Cannot add service qubes-core!"
chkconfig qubes-core on || echo "WARNING: Cannot enable service qubes-core!"
chkconfig --add qubes-core-netvm || echo "WARNING: Cannot add service qubes-core-netvm!"
chkconfig qubes-core-netvm on || echo "WARNING: Cannot enable service qubes-core-netvm!"
chkconfig --add qubes-core-appvm || echo "WARNING: Cannot add service qubes-core-appvm!"
chkconfig qubes-core-appvm on || echo "WARNING: Cannot enable service qubes-core-appvm!"
chkconfig --add qubes-firewall || echo "WARNING: Cannot add service qubes-firewall!"
chkconfig qubes-firewall on || echo "WARNING: Cannot enable service qubes-firewall!"
chkconfig --add qubes-netwatcher || echo "WARNING: Cannot add service qubes-netwatcher!"
chkconfig qubes-netwatcher on || echo "WARNING: Cannot enable service qubes-netwatcher!"
chkconfig --add qubes-yum-proxy || echo "WARNING: Cannot add service qubes-yum-proxy!"
chkconfig qubes-yum-proxy on || echo "WARNING: Cannot enable service qubes-yum-proxy!"
chkconfig --add qubes-qrexec-agent || echo "WARNING: Cannot add service qubes-qrexec-agent!"
chkconfig qubes-qrexec-agent on || echo "WARNING: Cannot enable service qubes-qrexec-agent!"

# TODO: make this not display the silly message about security context...
sed -i s/^id:.:initdefault:/id:3:initdefault:/ /etc/inittab

%preun sysvinit
if [ "$1" = 0 ] ; then
    # no more packages left
    chkconfig qubes-core off
    chkconfig qubes-core-netvm off
    chkconfig qubes-core-appvm off
    chkconfig qubes-firewall off
    chkconfig qubes-netwatcher off
    chkconfig qubes-yum-proxy off
    chkconfig qubes-qrexec-agent off
fi

%package systemd
Summary:        Qubes unit files for SystemD init style
License:        GPL v2 only
Group:          Qubes
Requires:       systemd
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units
Requires:       qubes-core-vm
Provides:       qubes-core-vm-init-scripts
Conflicts:      qubes-core-vm-sysvinit

%description systemd
The Qubes core startup configuration for SystemD init.

%files systemd
%defattr(-,root,root,-)
/lib/systemd/system/qubes-dvm.service
/lib/systemd/system/qubes-misc-post.service
/lib/systemd/system/qubes-firewall.service
/lib/systemd/system/qubes-netwatcher.service
/lib/systemd/system/qubes-network.service
/lib/systemd/system/qubes-sysinit.service
/lib/systemd/system/qubes-update-check.service
/lib/systemd/system/qubes-update-check.timer
/lib/systemd/system/qubes-yum-proxy.service
/lib/systemd/system/qubes-qrexec-agent.service
%dir /usr/lib/qubes/init
/usr/lib/qubes/init/prepare-dvm.sh
/usr/lib/qubes/init/network-proxy-setup.sh
/usr/lib/qubes/init/misc-post.sh
/usr/lib/qubes/init/misc-post-stop.sh
/usr/lib/qubes/init/qubes-sysinit.sh
/usr/lib/qubes/init/ModemManager.service
/usr/lib/qubes/init/NetworkManager.service
/usr/lib/qubes/init/NetworkManager-wait-online.service
/usr/lib/qubes/init/cups.service
/usr/lib/qubes/init/cups.socket
/usr/lib/qubes/init/cups.path
/usr/lib/qubes/init/ntpd.service
/usr/lib/qubes/init/chronyd.service
%ghost %attr(0644,root,root) /etc/systemd/system/ModemManager.service
%ghost %attr(0644,root,root) /etc/systemd/system/NetworkManager.service
%ghost %attr(0644,root,root) /etc/systemd/system/NetworkManager-wait-online.service
%ghost %attr(0644,root,root) /etc/systemd/system/cups.service
%ghost %attr(0644,root,root) /etc/systemd/system/cups.socket
%ghost %attr(0644,root,root) /etc/systemd/system/cups.path

%post systemd

for srv in qubes-dvm qubes-sysinit qubes-misc-post qubes-netwatcher qubes-network qubes-firewall qubes-yum-proxy qubes-qrexec-agent; do
    /bin/systemctl enable $srv.service 2> /dev/null
done

/bin/systemctl enable qubes-update-check.timer 2> /dev/null

UNITDIR=/lib/systemd/system
OVERRIDEDIR=/usr/lib/qubes/init

# Install overriden services only when original exists
for srv in cups ModemManager NetworkManager NetworkManager-wait-online ntpd chronyd; do
    if [ -f $UNITDIR/$srv.service ]; then
        cp $OVERRIDEDIR/$srv.service /etc/systemd/system/
    fi
    if [ -f $UNITDIR/$srv.socket -a -f $OVERRIDEDIR/$srv.socket ]; then
        cp $OVERRIDEDIR/$srv.socket /etc/systemd/system/
    fi
    if [ -f $UNITDIR/$srv.path -a -f $OVERRIDEDIR/$srv.path ]; then
        cp $OVERRIDEDIR/$srv.path /etc/systemd/system/
    fi
done

# Set default "runlevel"
rm -f /etc/systemd/system/default.target
ln -s /lib/systemd/system/multi-user.target /etc/systemd/system/default.target

DISABLE_SERVICES="alsa-store alsa-restore auditd avahi avahi-daemon backuppc cpuspeed crond"
DISABLE_SERVICES="$DISABLE_SERVICES fedora-autorelabel fedora-autorelabel-mark ipmi hwclock-load hwclock-save"
DISABLE_SERVICES="$DISABLE_SERVICES mdmonitor multipathd openct rpcbind mcelog fedora-storage-init fedora-storage-init-late"
DISABLE_SERVICES="$DISABLE_SERVICES plymouth-start plymouth-read-write plymouth-quit plymouth-quit-wait"
DISABLE_SERVICES="$DISABLE_SERVICES sshd tcsd sm-client sendmail mdmonitor-takeover"
DISABLE_SERVICES="$DISABLE_SERVICES rngd smartd upower irqbalance colord"
for srv in $DISABLE_SERVICES; do
    if [ -f /lib/systemd/system/$srv.service ]; then
        if fgrep -q '[Install]' /lib/systemd/system/$srv.service; then
            /bin/systemctl disable $srv.service 2> /dev/null
        else
            # forcibly disable
            ln -sf /dev/null /etc/systemd/system/$srv.service
        fi
    fi
done

rm -f /etc/systemd/system/getty.target.wants/getty@tty*.service

# Enable some services
/bin/systemctl enable iptables.service 2> /dev/null
/bin/systemctl enable ip6tables.service 2> /dev/null
/bin/systemctl enable rsyslog.service 2> /dev/null
/bin/systemctl enable ntpd.service 2> /dev/null
# Disable original service to enable overriden one
/bin/systemctl disable ModemManager.service 2> /dev/null
/bin/systemctl disable NetworkManager.service 2> /dev/null
# Disable D-BUS activation of NetworkManager - in AppVm it causes problems (eg PackageKit timeouts)
/bin/systemctl mask dbus-org.freedesktop.NetworkManager.service 2> /dev/null
/bin/systemctl enable ModemManager.service 2> /dev/null
/bin/systemctl enable NetworkManager.service 2> /dev/null
# Fix for https://bugzilla.redhat.com/show_bug.cgi?id=974811
/bin/systemctl enable NetworkManager-dispatcher.service 2> /dev/null

# Enable cups only when it is real SystemD service
[ -e /lib/systemd/system/cups.service ] && /bin/systemctl enable cups.service 2> /dev/null

exit 0

%postun systemd

#Do not run this part on upgrades
if [ "$1" != 0 ] ; then
    exit 0
fi

for srv in qubes-dvm qubes-sysinit qubes-misc-post qubes-netwatcher qubes-network qubes-qrexec-agent; do
    /bin/systemctl disable $srv.service
do
