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
Requires:   nautilus-python
Requires:   qubes-core-vm-kernel-placeholder
Requires:   qubes-utils
Requires:   initscripts
# for qubes-desktop-run
Requires:   pygobject3-base
%if %{fedora} >= 20
# gpk-update-viewer required by qubes-manager
Requires:   gnome-packagekit-updater
%endif
Requires:   ImageMagick
Requires:   fakeroot
Requires:   desktop-notification-daemon
Provides:   qubes-core-vm
Obsoletes:  qubes-core-commonvm
Obsoletes:  qubes-core-appvm
Obsoletes:  qubes-core-netvm
Obsoletes:  qubes-core-proxyvm
Obsoletes:  qubes-upgrade-vm < 2.0
BuildRequires: xen-devel
BuildRequires: qubes-utils-devel >= 2.0.5
BuildRequires: libX11-devel

%define _builddir %(pwd)

%define kde_service_dir /usr/share/kde4/services

%define installOverridenServices() \
UNITDIR=/lib/systemd/system\
OVERRIDEDIR=/usr/lib/qubes/init\
# Install overriden services only when original exists\
for srv in %*; do\
    if [ -f $UNITDIR/$srv.service ]; then\
        cp $OVERRIDEDIR/$srv.service /etc/systemd/system/\
        /bin/systemctl is-enabled $srv.service >/dev/null && /bin/systemctl --no-reload reenable $srv.service 2>/dev/null\
    fi\
    if [ -f $UNITDIR/$srv.socket -a -f $OVERRIDEDIR/$srv.socket ]; then\
        cp $OVERRIDEDIR/$srv.socket /etc/systemd/system/\
        /bin/systemctl is-enabled $srv.socket >/dev/null && /bin/systemctl --no-reload reenable $srv.socket 2>/dev/null\
    fi\
    if [ -f $UNITDIR/$srv.path -a -f $OVERRIDEDIR/$srv.path ]; then\
        cp $OVERRIDEDIR/$srv.path /etc/systemd/system/\
        /bin/systemctl is-enabled $srv.path >/dev/null && /bin/systemctl --no-reload reenable $srv.path 2>/dev/null\
    fi\
done\
/bin/systemctl daemon-reload\
%{nil}

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
usermod -p '' root
usermod -L user

%install

(cd qrexec; make install DESTDIR=$RPM_BUILD_ROOT)
make install-vm DESTDIR=$RPM_BUILD_ROOT

# Create ghost files to silent rpmbuild warnings, those files will NOT be
# included in package
mkdir -p $RPM_BUILD_ROOT/etc/systemd/system
for f in ModemManager.service NetworkManager.service \
        NetworkManager-wait-online.service cups.service cups.socket cups.path; do
    cp $RPM_BUILD_ROOT/usr/lib/qubes/init/$f $RPM_BUILD_ROOT/etc/systemd/system/
done

%if %{fedora} < 21
cp -p $RPM_BUILD_ROOT/usr/lib/qubes/init/iptables $RPM_BUILD_ROOT/etc/sysconfig/iptables
cp -p $RPM_BUILD_ROOT/usr/lib/qubes/init/ip6tables $RPM_BUILD_ROOT/etc/sysconfig/ip6tables
%endif

%triggerin -- initscripts
if [ -e /etc/init/serial.conf ]; then
	cp /usr/share/qubes/serial.conf /etc/init/serial.conf
fi

%triggerin -- pulseaudio-module-x11
sed -i '/^\(Not\|Only\)ShowIn/d' /etc/xdg/autostart/pulseaudio.desktop
echo 'NotShowIn=QUBES;' >> /etc/xdg/autostart/pulseaudio.desktop

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

# reenable if disabled by some earlier version of package
remove_ShowIn abrt-applet.desktop imsettings-start.desktop

# don't want it at all
for F in deja-dup-monitor krb5-auth-dialog pulseaudio restorecond sealertauto gnome-power-manager gnome-sound-applet gnome-screensaver orca-autostart; do
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
%if %{fedora} >= 20
echo 'OnlyShowIn=GNOME;QUBES;' >> /etc/xdg/autostart/nm-applet.desktop || :
%else
echo 'OnlyShowIn=GNOME;NetVM;' >> /etc/xdg/autostart/nm-applet.desktop || :
%endif

# Create NetworkManager configuration if we do not have it
if ! [ -e /etc/NetworkManager/NetworkManager.conf ]; then
echo '[main]' > /etc/NetworkManager/NetworkManager.conf
echo 'plugins = keyfile' >> /etc/NetworkManager/NetworkManager.conf
echo '[keyfile]' >> /etc/NetworkManager/NetworkManager.conf
fi
/usr/lib/qubes/qubes-fix-nm-conf.sh


# Remove ip_forward setting from sysctl, so NM will not reset it
sed 's/^net.ipv4.ip_forward.*/#\0/'  -i /etc/sysctl.conf

# Remove old firmware updates link
if [ -L /lib/firmware/updates ]; then
  rm -f /lib/firmware/updates
fi

if ! grep -q '/etc/yum\.conf\.d/qubes-proxy\.conf' /etc/yum.conf; then
  echo >> /etc/yum.conf
  echo '# Yum does not support inclusion of config dir...' >> /etc/yum.conf
  echo 'include=file:///etc/yum.conf.d/qubes-proxy.conf' >> /etc/yum.conf
fi

# Revert 'Prevent unnecessary updates in VMs':
sed -i -e '/^exclude = kernel/d' /etc/yum.conf

# Location of files which contains list of protected files
mkdir -p /etc/qubes/protected-files.d
PROTECTED_FILE_LIST='/etc/qubes/protected-files.d'

# qubes-core-vm has been broken for some time - it overrides /etc/hosts; restore original content
if ! grep -rq "^/etc/hosts$" "${PROTECTED_FILE_LIST}" 2>/dev/null; then
    if ! grep -q localhost /etc/hosts; then
      cat <<EOF > /etc/hosts
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4 `hostname`
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
EOF
    fi
fi

# ensure that hostname resolves to 127.0.0.1 resp. ::1 and that /etc/hosts is
# in the form expected by qubes-sysinit.sh
if ! grep -rq "^/etc/hostname$" "${PROTECTED_FILE_LIST}" 2>/dev/null; then
    for ip in '127\.0\.0\.1' '::1'; do
        if grep -q "^${ip}\(\s\|$\)" /etc/hosts; then
            sed -i "/^${ip}\s/,+0s/\(\s`hostname`\)\+\(\s\|$\)/\2/g" /etc/hosts
            sed -i "s/^${ip}\(\s\|$\).*$/\0 `hostname`/" /etc/hosts
        else
            echo "${ip} `hostname`" >> /etc/hosts
        fi
    done
fi

# Copy ip(|6)tables into place if they do not already exist in filesystem.
# This prevents conflict with iptables-service
if [ ! -f '/etc/sysconfig/iptables' ]; then
  cp -p /usr/lib/qubes/init/iptables /etc/sysconfig/iptables
fi
if [ ! -f '/etc/sysconfig/ip6tables' ]; then
  cp -p /usr/lib/qubes/init/ip6tables /etc/sysconfig/ip6tables
fi

if [ "$1" !=  1 ] ; then
# do the rest of %post thing only when updating for the first time...
exit 0
fi

if [ -e /etc/init/serial.conf ] && ! [ -f /var/lib/qubes/serial.orig ] ; then
	cp /etc/init/serial.conf /var/lib/qubes/serial.orig
fi

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

%triggerin -- notification-daemon
# Enable autostart of notification-daemon when installed
if [ ! -e /etc/xdg/autostart/notification-daemon.desktop ]; then
    ln -s /usr/share/applications/notification-daemon.desktop /etc/xdg/autostart/
fi
exit 0

%triggerin -- selinux-policy
#echo "--> Disabling SELinux..."
sed -e s/^SELINUX=.*$/SELINUX=disabled/ </etc/selinux/config >/etc/selinux/config.processed
mv /etc/selinux/config.processed /etc/selinux/config
setenforce 0 2>/dev/null
exit 0

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

    if [ -L /lib/firmware/updates ]; then
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
%{kde_service_dir}/qvm-move.desktop
%{kde_service_dir}/qvm-dvm.desktop
/etc/NetworkManager/dispatcher.d/30-qubes-external-ip
/etc/NetworkManager/dispatcher.d/qubes-nmhook
%config(noreplace) /etc/X11/xorg-preload-apps.conf
/etc/dispvm-dotfiles.tbz
/etc/dhclient.d/qubes-setup-dnat-to-ns.sh
/etc/fstab
/etc/pki/rpm-gpg/RPM-GPG-KEY-qubes*
%config(noreplace) /etc/polkit-1/localauthority/50-local.d/qubes-allow-all.pkla
%config(noreplace) /etc/polkit-1/rules.d/00-qubes-allow-all.rules
%dir /etc/qubes-rpc
%config(noreplace) /etc/qubes-rpc/qubes.Filecopy
%config(noreplace) /etc/qubes-rpc/qubes.OpenInVM
%config(noreplace) /etc/qubes-rpc/qubes.GetAppmenus
%config(noreplace) /etc/qubes-rpc/qubes.VMShell
%config(noreplace) /etc/qubes-rpc/qubes.SyncNtpClock
%config(noreplace) /etc/qubes-rpc/qubes.SuspendPre
%config(noreplace) /etc/qubes-rpc/qubes.SuspendPost
%config(noreplace) /etc/qubes-rpc/qubes.WaitForSession
%config(noreplace) /etc/qubes-rpc/qubes.DetachPciDevice
%config(noreplace) /etc/qubes-rpc/qubes.Backup
%config(noreplace) /etc/qubes-rpc/qubes.Restore
%config(noreplace) /etc/qubes-rpc/qubes.SelectFile
%config(noreplace) /etc/qubes-rpc/qubes.SelectDirectory
%config(noreplace) /etc/qubes-rpc/qubes.GetImageRGBA
%config(noreplace) /etc/qubes-rpc/qubes.SetDateTime
%config(noreplace) /etc/sudoers.d/qubes
%if %{fedora} < 21
%config(noreplace) /etc/sysconfig/iptables
%config(noreplace) /etc/sysconfig/ip6tables
%endif
/usr/lib/qubes/init/iptables
/usr/lib/qubes/init/ip6tables
%config(noreplace) /etc/tinyproxy/filter-updates
%config(noreplace) /etc/tinyproxy/tinyproxy-updates.conf
%config(noreplace) /etc/udev/rules.d/50-qubes-misc.rules
%config(noreplace) /etc/udev/rules.d/99-qubes-network.rules
/etc/xdg/autostart/00-qubes-show-hide-nm-applet.desktop
/etc/xen/scripts/vif-route-qubes
%config(noreplace) /etc/yum.conf.d/qubes-proxy.conf
%config(noreplace) /etc/yum.repos.d/qubes-r2.repo
/etc/yum/pluginconf.d/yum-qubes-hooks.conf
/etc/yum/post-actions/qubes-trigger-sync-appmenus.action
/usr/lib/systemd/system/user@.service.d/90-session-stop-timeout.conf
/usr/sbin/qubes-serial-login
/usr/bin/qvm-copy-to-vm
/usr/bin/qvm-move-to-vm
/usr/bin/qvm-open-in-dvm
/usr/bin/qvm-open-in-vm
/usr/bin/qvm-run
/usr/bin/qvm-mru-entry
/usr/bin/xenstore-watch-qubes
/usr/bin/qubes-desktop-run
/usr/bin/qrexec-client-vm
%dir /usr/lib/qubes
/usr/lib/qubes/vusb-ctl.py*
/usr/lib/qubes/dispvm-prerun.sh
/usr/lib/qubes/sync-ntp-clock
/usr/lib/qubes/prepare-suspend
/usr/lib/qubes/network-manager-prepare-conf-dir
/usr/lib/qubes/show-hide-nm-applet.sh
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
/usr/lib/qubes/qvm-move-to-vm.gnome
/usr/lib/qubes/qvm-move-to-vm.kde
/usr/lib/qubes/setup-ip
/usr/lib/qubes/tar2qfile
/usr/lib/qubes/vm-file-editor
/usr/lib/qubes/wrap-in-html-if-url.sh
/usr/lib/qubes/iptables-updates-proxy
/usr/lib/qubes/close-window
/usr/lib/yum-plugins/yum-qubes-hooks.py*
/usr/sbin/qubes-firewall
/usr/sbin/qubes-netwatcher
/usr/share/qubes/serial.conf
/usr/share/glib-2.0/schemas/org.gnome.settings-daemon.plugins.updates.gschema.override
/usr/share/glib-2.0/schemas/org.gnome.nautilus.gschema.override
/usr/share/nautilus-python/extensions/qvm_copy_nautilus.py*
/usr/share/nautilus-python/extensions/qvm_move_nautilus.py*
/usr/share/nautilus-python/extensions/qvm_dvm_nautilus.py*

%dir /usr/share/qubes
/usr/share/qubes/mime-override/globs
%dir /home_volatile
%attr(700,user,user) /home_volatile/user
%dir /mnt/removable
%dir /rw

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
/etc/init.d/qubes-updates-proxy
/etc/init.d/qubes-qrexec-agent
/etc/sysconfig/modules/qubes-core.modules
/etc/sysconfig/modules/qubes-misc.modules

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
chkconfig --add qubes-updates-proxy || echo "WARNING: Cannot add service qubes-updates-proxy!"
chkconfig qubes-updates-proxy on || echo "WARNING: Cannot enable service qubes-updates-proxy!"
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
    chkconfig qubes-updates-proxy off
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
/lib/systemd/system/qubes-updates-proxy.service
/lib/systemd/system/qubes-qrexec-agent.service
/lib/systemd/system-preset/75-qubes-vm.preset
/lib/modules-load.d/qubes-core.conf
/lib/modules-load.d/qubes-misc.conf
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
/usr/lib/qubes/init/crond.service
%ghost %attr(0644,root,root) /etc/systemd/system/ModemManager.service
%ghost %attr(0644,root,root) /etc/systemd/system/NetworkManager.service
%ghost %attr(0644,root,root) /etc/systemd/system/NetworkManager-wait-online.service
%ghost %attr(0644,root,root) /etc/systemd/system/cups.service
%ghost %attr(0644,root,root) /etc/systemd/system/cups.socket
%ghost %attr(0644,root,root) /etc/systemd/system/cups.path

%post systemd

for srv in qubes-dvm qubes-sysinit qubes-misc-post qubes-netwatcher qubes-network qubes-firewall qubes-updates-proxy qubes-qrexec-agent; do
    /bin/systemctl --no-reload enable $srv.service 2> /dev/null
done

/bin/systemctl --no-reload enable qubes-update-check.timer 2> /dev/null

# Set default "runlevel"
rm -f /etc/systemd/system/default.target
ln -s /lib/systemd/system/multi-user.target /etc/systemd/system/default.target

grep '^[[:space:]]*[^#;]' /lib/systemd/system-preset/75-qubes-vm.preset | while read action unit_name; do
    case "$action" in
    (disable)
        if [ -f /lib/systemd/system/$unit_name.service ]; then
            if fgrep -q '[Install]' /lib/systemd/system/$unit_name; then
                /bin/systemctl --no-reload preset $unit_name 2> /dev/null
            else
                # forcibly disable
                ln -sf /dev/null /etc/systemd/system/$unit_name
            fi
        fi
        ;;
    esac
done

rm -f /etc/systemd/system/getty.target.wants/getty@tty*.service

# Enable some services
/bin/systemctl --no-reload enable iptables.service 2> /dev/null
/bin/systemctl --no-reload enable ip6tables.service 2> /dev/null
/bin/systemctl --no-reload enable rsyslog.service 2> /dev/null
/bin/systemctl --no-reload enable ntpd.service 2> /dev/null
/bin/systemctl --no-reload enable crond.service 2> /dev/null

# Enable cups only when it is real SystemD service
[ -e /lib/systemd/system/cups.service ] && /bin/systemctl --no-reload enable cups.service 2> /dev/null

/bin/systemctl daemon-reload

exit 0

%triggerin systemd -- NetworkManager
%installOverridenServices ModemManager NetworkManager NetworkManager-wait-online
# Disable D-BUS activation of NetworkManager - in AppVm it causes problems (eg PackageKit timeouts)
/bin/systemctl mask dbus-org.freedesktop.NetworkManager.service 2> /dev/null
# Fix for https://bugzilla.redhat.com/show_bug.cgi?id=974811
/bin/systemctl enable NetworkManager-dispatcher.service 2> /dev/null
exit 0

%triggerin systemd -- cups
%installOverridenServices cups
exit 0

%triggerin systemd -- cronie
%installOverridenServices crond
exit 0

%triggerin systemd -- haveged
/bin/systemctl enable haveged.service 2> /dev/null
exit 0

%postun systemd

#Do not run this part on upgrades
if [ "$1" != 0 ] ; then
    exit 0
fi

for srv in qubes-dvm qubes-sysinit qubes-misc-post qubes-netwatcher qubes-network qubes-qrexec-agent; do
    /bin/systemctl disable $srv.service
do
