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

%define qubes_services qubes-core qubes-core-netvm qubes-core-early qubes-firewall qubes-iptables qubes-updates-proxy qubes-qrexec-agent qubes-updates-proxy-forwarder
%define qubes_preset_file 75-qubes-vm.preset

%{!?version: %define version %(cat version)}
%{!?backend_vmm: %define backend_vmm %(echo $BACKEND_VMM)}

%define scriptletfuns is_static() { \
    [ -f "%{_unitdir}/$1" ] && ! grep -q '^[[].nstall]' "%{_unitdir}/$1" \
} \
 \
is_masked() { \
    if [ ! -L %{_sysconfdir}/systemd/system/"$1" ] \
    then \
       return 1 \
    fi \
    target=`readlink %{_sysconfdir}/systemd/system/"$1" 2>/dev/null` || : \
    if [ "$target" = "/dev/null" ] \
    then \
       return 0 \
    fi \
    return 1 \
} \
\
mask() { \
    ln -sf /dev/null %{_sysconfdir}/systemd/system/"$1" \
} \
\
unmask() { \
    if ! is_masked "$1" \
    then \
        return 0 \
    fi \
    rm -f %{_sysconfdir}/systemd/system/"$1" \
} \
\
preset_units() { \
    local represet= \
    cat "$1" | while read action unit_name \
    do \
        if [ "$action" = "#" -a "$unit_name" = "Units below this line will be re-preset on package upgrade" ] \
        then \
            represet=1 \
            continue \
        fi \
        echo "$action $unit_name" | grep -q '^[[:space:]]*[^#;]' || continue \
        [ -n "$action" -a -n "$unit_name" ] || continue \
        if [ "$2" = "initial" -o "$represet" = "1" ] \
        then \
            if [ "$action" = "disable" ] && is_static "$unit_name" \
            then \
                if ! is_masked "$unit_name" \
                then \
                    # We must effectively mask these units, even if they are static. \
                    mask "$unit_name" \
                fi \
            elif [ "$action" = "enable" ] && is_static "$unit_name" \
            then \
                if is_masked "$unit_name" \
                then \
                    # We masked this static unit before, now we unmask it. \
                    unmask "$unit_name" \
                fi \
                 systemctl --no-reload preset "$unit_name" >/dev/null 2>&1 || : \
            else \
                systemctl --no-reload preset "$unit_name" >/dev/null 2>&1 || : \
            fi \
        fi \
    done \
} \
\
restore_units() { \
    grep '^[[:space:]]*[^#;]' "$1" | while read action unit_name \
    do \
        if is_static "$unit_name" && is_masked "$unit_name" \
        then \
            # If the unit had been masked by us, we must unmask it here. \
            # Otherwise systemctl preset will fail badly. \
            unmask "$unit_name" \
        fi \
        systemctl --no-reload preset "$unit_name" >/dev/null 2>&1 || : \
    done \
} \

Name:		qubes-core-agent
Version:	%{version}
Release:	1%{dist}
Summary:	The Qubes core files for VM

Group:		Qubes
Vendor:		Invisible Things Lab
License:	GPL
URL:		http://www.qubes-os.org
%if %{fedora} < 22
Requires:   yum-plugin-post-transaction-actions
%endif
%if %{fedora} >= 18
# Fedora >= 18 defaults to firewalld, which isn't supported nor needed by Qubes
Conflicts:  firewalld
%endif
Requires:	xdg-utils
Requires:   qubes-utils >= 3.1.3
Requires:   initscripts
Requires:   gawk
Requires:   sed
Requires:   util-linux
# for qubes-desktop-run
Requires:   pygobject3-base
Requires:   dbus-python
# for qubes-session-autostart, xdg-icon
Requires:   pyxdg
Requires:   python-daemon
# for qvm-feature-request
Requires:   python2-qubesdb
Requires:   ImageMagick
Requires:   librsvg2-tools
Requires:   zenity
Requires:   qubes-core-agent-qrexec
Requires:   qubes-libvchan
Requires:   qubes-db-vm
%if 0%{fedora} >= 23
Requires:   python3-dnf-plugins-qubes-hooks
%else
Requires:   python2-dnf-plugins-qubes-hooks
%endif
%if 0%{?rhel} >= 7
Requires:   python34-dnf-plugins-qubes-hooks
%endif
Obsoletes:  qubes-core-vm-kernel-placeholder <= 1.0
Obsoletes:  qubes-upgrade-vm < 3.2
Provides:   qubes-core-vm = %{version}-%{release}
Obsoletes:  qubes-core-vm < 4.0.0
Provides:	qubes-core-vm-doc = %{version}-%{release}
Obsoletes:	qubes-core-vm-doc < 4.0.0
BuildRequires: pandoc
BuildRequires: xen-devel
BuildRequires: libX11-devel
BuildRequires: qubes-utils-devel >= 3.1.3
BuildRequires: qubes-libvchan-%{backend_vmm}-devel
BuildRequires: pam-devel

%description
The Qubes core files for installation inside a Qubes VM.

%package -n python2-dnf-plugins-qubes-hooks
Summary:	DNF plugin for Qubes specific post-installation actions
BuildRequires: python2-devel
%{?python_provide:%python_provide python2-dnf-plugins-qubes-hooks}

%description -n python2-dnf-plugins-qubes-hooks
DNF plugin for Qubes specific post-installation actions:
 * notify dom0 that updates were installed
 * refresh applications shortcut list

%if 0%{fedora} >= 23
%package -n python3-dnf-plugins-qubes-hooks
Summary:        DNF plugin for Qubes specific post-installation actions
BuildRequires: python3-devel
%{?python_provide:%python_provide python3-dnf-plugins-qubes-hooks}

%description -n python3-dnf-plugins-qubes-hooks
DNF plugin for Qubes specific post-installation actions:
 * notify dom0 that updates were installed
 * refresh applications shortcut list
%endif

%if 0%{?rhel} >= 7
%package -n python34-dnf-plugins-qubes-hooks
Summary:        DNF plugin for Qubes specific post-installation actions
BuildRequires: python34-devel
%{?python_provide:%python_provide python34-dnf-plugins-qubes-hooks}

%description -n python34-dnf-plugins-qubes-hooks
DNF plugin for Qubes specific post-installation actions:
 * notify dom0 that updates were installed
 * refresh applications shortcut list
%endif

%package qrexec
Summary:    Qubes qrexec agent
Requires:   qubes-core-agent
Requires:   nautilus-python
Conflicts:  qubes-core-vm < 4.0.0

%description qrexec
Agent part of Qubes RPC system. A daemon responsible for starting processes as
requested by dom0 or other VMs, according to dom0-enforced policy.

%package nautilus
Summary:    Qubes integration for Nautilus
Requires:   qubes-core-agent
Requires:   nautilus-python
Conflicts:  qubes-core-vm < 4.0.0

%description nautilus
Nautilus addons for inter-VM file copy/move/open.

%package dom0-updates
Summary:    Scripts required to handle dom0 updates
Requires:   qubes-core-agent
Requires:   fakeroot
Conflicts:  qubes-core-vm < 4.0.0

%description dom0-updates
Scripts required to handle dom0 updates.

%package networking
Summary:    Networking support for Qubes VM
Requires:   ethtool
Requires:   net-tools
Requires:   nftables
Requires:   socat
Requires:   qubes-core-agent
Requires:   tinyproxy
Conflicts:  qubes-core-vm < 4.0.0

%description networking
This package provides:
 * basic network functionality (setting IP address, DNS, default gateway)
 * proxy service used by TemplateVMs to download updates
 * qubes-firewall service (FirewallVM)

Note: if you want to use NetworkManager (you do want it in NetVM), install also
qubes-core-agent-network-manager.

%package network-manager
Summary:    NetworkManager integration for Qubes VM
# to show/hide nm-applet
Requires:   NetworkManager >= 0.8.1-1
Requires:   glib2
Requires:   qubes-core-agent-networking
Conflicts:  qubes-core-vm < 4.0.0

%description network-manager
Integration of NetworkManager for Qubes VM:
 * make connections config persistent
 * adjust DNS redirections when needed
 * show/hide NetworkManager applet icon

%package passwordless-root
Summary:    Passwordless root access from normal user
Conflicts:  qubes-core-vm < 4.0.0

%description passwordless-root
Configure sudo, PolicyKit and similar tool to not ask for any password when
switching from user to root. Since all the user data in a VM is accessible
already from normal user account, there is not much more to guard there. Qubes
VM is a single user system.

%define _builddir %(pwd)

%define kde_service_dir /usr/share/kde4/services

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
make -C doc manpages

%pre
# Make sure there is a qubes group
groupadd --force --system --gid 98 qubes
id -u 'user' >/dev/null 2>&1 || {
  useradd --user-group --create-home --shell /bin/bash user
}
usermod -a --groups qubes user

if [ "$1" !=  1 ] ; then
# do this whole %%pre thing only when updating for the first time...
exit 0
fi

mkdir -p /var/lib/qubes
if [ -e /etc/fstab ] ; then
mv /etc/fstab /var/lib/qubes/fstab.orig
fi

usermod -L user

%pre passwordless-root

usermod -p '' root

%install

(cd qrexec; make install DESTDIR=$RPM_BUILD_ROOT)
make install-vm DESTDIR=$RPM_BUILD_ROOT

%if %{fedora} >= 22
rm -f $RPM_BUILD_ROOT/etc/yum/post-actions/qubes-trigger-sync-appmenus.action
%endif

%if 0%{?rhel} >= 7
sed -i \
        -e 's:-primary:-centos:' \
        -e 's:/fc:/centos:' \
        $RPM_BUILD_ROOT/etc/yum.repos.d/qubes-*.repo
%endif

%triggerin -- initscripts
if [ -e /etc/init/serial.conf ]; then
	cp /usr/share/qubes/serial.conf /etc/init/serial.conf
fi

%triggerin -- grub2-tools

if ! grep -q /etc/default/grub.qubes /etc/default/grub 2>/dev/null; then
    # do not keep Qubes-related settings directly in user-controlled config,
    # include another file
    echo '. /etc/default/grub.qubes' >> /etc/default/grub
fi

%post

# disable some Upstart services
for F in plymouth-shutdown prefdm splash-manager start-ttys tty ; do
	if [ -e /etc/init/$F.conf ]; then
		mv -f /etc/init/$F.conf /etc/init/$F.conf.disabled
	fi
done


# Remove old firmware updates link
if [ -L /lib/firmware/updates ]; then
  rm -f /lib/firmware/updates
fi

if test -f /etc/yum.conf && ! grep -q '/etc/yum\.conf\.d/qubes-proxy\.conf' /etc/yum.conf; then
  echo >> /etc/yum.conf
  echo '# Yum does not support inclusion of config dir...' >> /etc/yum.conf
  echo 'include=file:///etc/yum.conf.d/qubes-proxy.conf' >> /etc/yum.conf
fi

# And actually setup the proxy usage in package managers
/usr/lib/qubes/update-proxy-configs

# Location of files which contains list of protected files
mkdir -p /etc/qubes/protected-files.d
. /usr/lib/qubes/init/functions

# qubes-core-vm has been broken for some time - it overrides /etc/hosts; restore original content
if ! is_protected_file /etc/hosts ; then
    if ! grep -q localhost /etc/hosts; then
      cat <<EOF > /etc/hosts
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4 `hostname`
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
EOF
    fi
fi

# ensure that hostname resolves to 127.0.0.1 resp. ::1 and that /etc/hosts is
# in the form expected by qubes-sysinit.sh
if ! is_protected_file /etc/hostname ; then
    for ip in '127\.0\.0\.1' '::1'; do
        if grep -q "^${ip}\(\s\|$\)" /etc/hosts; then
            sed -i "/^${ip}\s/,+0s/\(\s`hostname`\)\+\(\s\|$\)/\2/g" /etc/hosts
            sed -i "s/^${ip}\(\s\|$\).*$/\0 `hostname`/" /etc/hosts
        else
            echo "${ip} `hostname`" >> /etc/hosts
        fi
    done
fi

if [ "$1" !=  1 ] ; then
# do the rest of %%post thing only when updating for the first time...
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

%post network-manager

# Create NetworkManager configuration if we do not have it
if ! [ -e /etc/NetworkManager/NetworkManager.conf ]; then
echo '[main]' > /etc/NetworkManager/NetworkManager.conf
echo 'plugins = keyfile' >> /etc/NetworkManager/NetworkManager.conf
echo '[keyfile]' >> /etc/NetworkManager/NetworkManager.conf
fi

# Remove ip_forward setting from sysctl, so NM will not reset it
sed 's/^net.ipv4.ip_forward.*/#\0/'  -i /etc/sysctl.conf

/usr/lib/qubes/qubes-fix-nm-conf.sh

%post networking
%systemd_post qubes-firewall.service
%systemd_post qubes-iptables.service
%systemd_post qubes-network.service
%systemd_post qubes-updates-proxy.service

%post qrexec
%systemd_post qubes-qrexec-agent.service

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

%preun networking
%systemd_preun qubes-firewall.service
%systemd_preun qubes-iptables.service
%systemd_preun qubes-network.service
%systemd_preun qubes-updates-proxy.service

%preun qrexec
%systemd_preun qubes-qrexec-agent.service

%postun
if [ $1 -eq 0 ] ; then
    /usr/bin/glib-compile-schemas %{_datadir}/glib-2.0/schemas &> /dev/null || :

    if [ -L /lib/firmware/updates ]; then
      rm /lib/firmware/updates
    fi

    rm -rf /var/lib/qubes/xdg
fi

%postun passwordless-root
if [ $1 -eq 0 ]; then
    usermod -p '*' root
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
%{kde_service_dir}/qvm-copy.desktop
%{kde_service_dir}/qvm-move.desktop
%{kde_service_dir}/qvm-dvm.desktop
%config(noreplace) /etc/X11/xorg-preload-apps.conf
/etc/fstab
/etc/pki/rpm-gpg/RPM-GPG-KEY-qubes*
%dir /etc/qubes-rpc
%config(noreplace) /etc/qubes-rpc/qubes.Filecopy
%config(noreplace) /etc/qubes-rpc/qubes.OpenInVM
%config(noreplace) /etc/qubes-rpc/qubes.OpenURL
%config(noreplace) /etc/qubes-rpc/qubes.GetAppmenus
%config(noreplace) /etc/qubes-rpc/qubes.VMShell
%config(noreplace) /etc/qubes-rpc/qubes.VMRootShell
%config(noreplace) /etc/qubes-rpc/qubes.SuspendPre
%config(noreplace) /etc/qubes-rpc/qubes.SuspendPreAll
%config(noreplace) /etc/qubes-rpc/qubes.SuspendPost
%config(noreplace) /etc/qubes-rpc/qubes.SuspendPostAll
%config(noreplace) /etc/qubes-rpc/qubes.WaitForSession
%config(noreplace) /etc/qubes-rpc/qubes.DetachPciDevice
%config(noreplace) /etc/qubes-rpc/qubes.Backup
%config(noreplace) /etc/qubes-rpc/qubes.Restore
%config(noreplace) /etc/qubes-rpc/qubes.SelectFile
%config(noreplace) /etc/qubes-rpc/qubes.SelectDirectory
%config(noreplace) /etc/qubes-rpc/qubes.GetImageRGBA
%config(noreplace) /etc/qubes-rpc/qubes.SetDateTime
%config(noreplace) /etc/qubes-rpc/qubes.InstallUpdatesGUI
%config(noreplace) /etc/qubes-rpc/qubes.ResizeDisk
%config(noreplace) /etc/qubes-rpc/qubes.StartApp
%config(noreplace) /etc/qubes-rpc/qubes.PostInstall
%config(noreplace) /etc/qubes-rpc/qubes.GetDate
%dir /etc/qubes/rpc-config
/etc/qubes/rpc-config/README
%config(noreplace) /etc/qubes/rpc-config/qubes.OpenInVM
%config(noreplace) /etc/qubes/rpc-config/qubes.OpenURL
%config(noreplace) /etc/qubes/rpc-config/qubes.SelectFile
%config(noreplace) /etc/qubes/rpc-config/qubes.SelectDirectory
%config(noreplace) /etc/qubes/rpc-config/qubes.StartApp
%config(noreplace) /etc/qubes/rpc-config/qubes.InstallUpdatesGUI
%dir /etc/qubes/autostart
%config(noreplace) /etc/default/grub.qubes
/etc/qubes/autostart/README.txt
%config /etc/qubes/autostart/*.desktop.d/30_qubes.conf
%dir /etc/qubes/suspend-pre.d
/etc/qubes/suspend-pre.d/README
%dir /etc/qubes/suspend-post.d
/etc/qubes/suspend-post.d/README
/etc/qubes/suspend-post.d/qvm-sync-clock.sh
%dir /etc/qubes/post-install.d
/etc/qubes/post-install.d/README
/etc/qubes/post-install.d/*.sh
%config(noreplace) /etc/sudoers.d/qt_x11_no_mitshm
%config(noreplace) /etc/sysctl.d/20_tcp_timestamps.conf
%config(noreplace) /etc/udev/rules.d/50-qubes-misc.rules
%config(noreplace) /etc/qubes-suspend-module-blacklist
%config(noreplace) /etc/yum.conf.d/qubes-proxy.conf
%config(noreplace) /etc/yum.repos.d/qubes-r4.repo
/etc/yum/pluginconf.d/yum-qubes-hooks.conf
%config(noreplace) /etc/dnf/plugins/qubes-hooks.conf
%if %{fedora} < 22
/etc/yum/post-actions/qubes-trigger-sync-appmenus.action
%endif
/usr/lib/systemd/system/user@.service.d/90-session-stop-timeout.conf
/usr/sbin/qubes-serial-login
/usr/bin/qvm-copy-to-vm
/usr/bin/qvm-move-to-vm
/usr/bin/qvm-copy
/usr/bin/qvm-move
/usr/bin/qvm-open-in-dvm
/usr/bin/qvm-open-in-vm
/usr/bin/qvm-run-vm
/usr/bin/qvm-features-request
/usr/bin/qvm-sync-clock
/usr/bin/xenstore-watch-qubes
/usr/bin/qubes-desktop-run
/usr/bin/qubes-open
/usr/bin/qubes-session-autostart
%dir /usr/lib/qubes
/usr/lib/qubes/prepare-suspend
/usr/lib/qubes/qfile-agent
%attr(4755,root,root) /usr/lib/qubes/qfile-unpacker
/usr/lib/qubes/qopen-in-vm
/usr/lib/qubes/qrun-in-vm
/usr/lib/qubes/qubes-trigger-sync-appmenus.sh
/usr/lib/qubes/qvm-copy-to-vm.kde
/usr/lib/qubes/qvm-move-to-vm.kde
/usr/lib/qubes/tar2qfile
/usr/lib/qubes/vm-file-editor
/usr/lib/qubes/close-window
/usr/lib/qubes/xdg-icon
/usr/lib/qubes/update-proxy-configs
/usr/lib/qubes/upgrades-installed-check
/usr/lib/qubes/upgrades-status-notify
/usr/lib/qubes/qubes-sync-clock
/usr/lib/yum-plugins/yum-qubes-hooks.py*
/usr/lib/dracut/dracut.conf.d/30-qubes.conf
%dir /usr/lib/qubes/init
/usr/lib/qubes/init/bind-dirs.sh
/usr/lib/qubes/init/control-printer-icon.sh
/usr/lib/qubes/init/functions
/usr/lib/qubes/init/misc-post-stop.sh
/usr/lib/qubes/init/misc-post.sh
/usr/lib/qubes/init/mount-dirs.sh
/usr/lib/qubes/init/qubes-early-vm-config.sh
/usr/lib/qubes/init/qubes-random-seed.sh
/usr/lib/qubes/init/qubes-sysinit.sh
/usr/lib/qubes/init/setup-rw.sh
/usr/lib/qubes/init/setup-rwdev.sh
/usr/lib/qubes/init/functions
%dir /usr/lib/qubes-bind-dirs.d
/usr/lib/qubes-bind-dirs.d/30_cron.conf
/usr/lib/python2.7/site-packages/qubesxdg.py*
/usr/share/qubes/serial.conf
/usr/share/glib-2.0/schemas/20_org.gnome.settings-daemon.plugins.updates.qubes.gschema.override
/usr/share/glib-2.0/schemas/20_org.gnome.nautilus.qubes.gschema.override
/usr/share/glib-2.0/schemas/20_org.mate.NotificationDaemon.qubes.gschema.override
/usr/share/glib-2.0/schemas/20_org.gnome.desktop.wm.preferences.qubes.gschema.override
%{_mandir}/man1/qvm-*.1*

%dir %{python_sitelib}/qubesagent-*-py2.7.egg-info
%{python_sitelib}/qubesagent-*-py2.7.egg-info/*
%dir %{python_sitelib}/qubesagent
%{python_sitelib}/qubesagent/__init__.py*
%{python_sitelib}/qubesagent/firewall.py*
%{python_sitelib}/qubesagent/test_firewall.py*

/usr/share/qubes/mime-override/globs
/usr/share/qubes/qubes-master-key.asc
%dir /mnt/removable
%dir /rw

%files -n python2-dnf-plugins-qubes-hooks
%{python2_sitelib}/dnf-plugins/*

%if 0%{fedora} >= 23
%files -n python3-dnf-plugins-qubes-hooks
%{python3_sitelib}/dnf-plugins/*
%endif

%if 0%{?rhel} >= 7
%files -n python34-dnf-plugins-qubes-hooks
%{python3_sitelib}/dnf-plugins/*
%endif

%files qrexec
%config(noreplace) /etc/pam.d/qrexec
/usr/bin/qrexec-fork-server
/usr/bin/qrexec-client-vm
/usr/lib/qubes/qrexec-agent
/usr/lib/qubes/qrexec-client-vm
/usr/lib/qubes/qrexec_client_vm
/usr/lib/qubes/qubes-rpc-multiplexer
/lib/systemd/system/qubes-qrexec-agent.service
%{_mandir}/man1/qrexec-client-vm.1*

%files nautilus
/usr/lib/qubes/qvm-copy-to-vm.gnome
/usr/lib/qubes/qvm-move-to-vm.gnome
/usr/share/nautilus-python/extensions/qvm_copy_nautilus.py*
/usr/share/nautilus-python/extensions/qvm_move_nautilus.py*
/usr/share/nautilus-python/extensions/qvm_dvm_nautilus.py*

%files dom0-updates
%dir %attr(0775,user,user) /var/lib/qubes/dom0-updates
/usr/lib/qubes/qubes-download-dom0-updates.sh

%files networking
%config(noreplace) /etc/qubes-rpc/qubes.UpdatesProxy
%config(noreplace) /etc/qubes/ip6tables.rules
%config(noreplace) /etc/qubes/iptables.rules
%config(noreplace) /etc/tinyproxy/tinyproxy-updates.conf
%config(noreplace) /etc/tinyproxy/updates-blacklist
%config(noreplace) /etc/udev/rules.d/99-qubes-network.rules
/etc/dhclient.d/qubes-setup-dnat-to-ns.sh
/etc/xen/scripts/vif-qubes-nat.sh
/etc/xen/scripts/vif-route-qubes
/lib/systemd/system/qubes-firewall.service
/lib/systemd/system/qubes-iptables.service
/lib/systemd/system/qubes-network.service
/lib/systemd/system/qubes-updates-proxy.service
/usr/lib/qubes/init/network-proxy-setup.sh
/usr/lib/qubes/init/qubes-iptables
/usr/lib/qubes/iptables-updates-proxy
/usr/lib/qubes/qubes-setup-dnat-to-ns
/usr/lib/qubes/setup-ip
/usr/lib/tmpfiles.d/qubes-core-agent-linux.conf
/usr/sbin/qubes-firewall

%files network-manager
/etc/NetworkManager/dispatcher.d/30-qubes-external-ip
/etc/NetworkManager/dispatcher.d/qubes-nmhook
/etc/xdg/autostart/00-qubes-show-hide-nm-applet.desktop
/usr/lib/NetworkManager/conf.d/30-qubes.conf
/usr/lib/qubes/network-manager-prepare-conf-dir
/usr/lib/qubes/qubes-fix-nm-conf.sh
/usr/lib/qubes/show-hide-nm-applet.sh

%files passwordless-root
%config(noreplace) /etc/polkit-1/localauthority/50-local.d/qubes-allow-all.pkla
%config(noreplace) /etc/polkit-1/rules.d/00-qubes-allow-all.rules
%config(noreplace) /etc/sudoers.d/qubes

%package sysvinit
Summary:        Qubes unit files for SysV init style or upstart
License:        GPL v2 only
Group:          Qubes
Requires:       upstart
Requires:       qubes-core-agent
Requires:       qubes-core-agent-qrexec
Requires:       qubes-core-agent-networking
Provides:       qubes-core-agent-init-scripts
Conflicts:      qubes-core-agent-systemd
Provides:       qubes-core-vm-sysvinit = %{version}-%{release}
Obsoletes:      qubes-core-vm-sysvinit < 4.0.0

%description sysvinit
The Qubes core startup configuration for SysV init (or upstart).

%files sysvinit
/etc/init.d/qubes-sysinit
/etc/init.d/qubes-core-early
/etc/init.d/qubes-core
/etc/init.d/qubes-core-netvm
/etc/init.d/qubes-firewall
/etc/init.d/qubes-iptables
/etc/init.d/qubes-updates-proxy
/etc/init.d/qubes-qrexec-agent
/etc/init.d/qubes-updates-proxy-forwarder
/etc/sysconfig/modules/qubes-core.modules

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
for svc in %qubes_services ; do
    if [ "$1" = 1 ] ; then
        chkconfig --add $svc || echo "WARNING: Cannot add service $svc!"
    else
        chkconfig $svc resetpriorities || echo "WARNING: Cannot reset priorities of service $svc!"
    fi
done

# dropped services
chkconfig qubes-netwatcher off || :

# TODO: make this not display the silly message about security context...
sed -i s/^id:.:initdefault:/id:3:initdefault:/ /etc/inittab

%preun sysvinit
if [ "$1" = 0 ] ; then
    # no more packages left
    for svc in %qubes_services ; do
        chkconfig --del $svc
    done
fi

%package systemd
Summary:        Qubes unit files for SystemD init style
License:        GPL v2 only
Group:          Qubes
Requires:       systemd
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units
Requires:       qubes-core-agent
Provides:       qubes-core-agent-init-scripts
Conflicts:      qubes-core-agent-sysvinit
Provides:       qubes-core-vm-systemd = %{version}-%{release}
Obsoletes:      qubes-core-vm-systemd < 4.0.0

%description systemd
The Qubes core startup configuration for SystemD init.

%files systemd
%defattr(-,root,root,-)
/lib/systemd/system/qubes-misc-post.service
/lib/systemd/system/qubes-mount-dirs.service
/lib/systemd/system/qubes-sysinit.service
/lib/systemd/system/qubes-early-vm-config.service
/lib/systemd/system/qubes-update-check.service
/lib/systemd/system/qubes-update-check.timer
/lib/systemd/system/qubes-sync-time.service
/lib/systemd/system/qubes-sync-time.timer
/lib/systemd/system/qubes-updates-proxy-forwarder@.service
/lib/systemd/system/qubes-updates-proxy-forwarder.socket
/lib/systemd/system-preset/%qubes_preset_file
/lib/modules-load.d/qubes-core.conf
/lib/systemd/system/chronyd.service.d/30_qubes.conf
/lib/systemd/system/crond.service.d/30_qubes.conf
/lib/systemd/system/cups.service.d/30_qubes.conf
/lib/systemd/system/cups.socket.d/30_qubes.conf
/lib/systemd/system/cups.path.d/30_qubes.conf
/lib/systemd/system/org.cups.cupsd.service.d/30_qubes.conf
/lib/systemd/system/org.cups.cupsd.socket.d/30_qubes.conf
/lib/systemd/system/org.cups.cupsd.path.d/30_qubes.conf
/lib/systemd/system/getty@tty.service.d/30_qubes.conf
/lib/systemd/system/ModemManager.service.d/30_qubes.conf
/lib/systemd/system/NetworkManager.service.d/30_qubes.conf
/lib/systemd/system/NetworkManager-wait-online.service.d/30_qubes.conf
/lib/systemd/system/systemd-random-seed.service.d/30_qubes.conf
/lib/systemd/system/systemd-timesyncd.service.d/30_qubes.conf
/lib/systemd/system/tinyproxy.service.d/30_not_needed_in_qubes_by_default.conf
/lib/systemd/system/tor.service.d/30_qubes.conf
/lib/systemd/system/tor@default.service.d/30_qubes.conf
/lib/systemd/system/tmp.mount.d/30_qubes.conf
/usr/lib/systemd/user/pulseaudio.service.d/30_qubes.conf
/usr/lib/systemd/user/pulseaudio.socket.d/30_qubes.conf

%post systemd

changed=

%scriptletfuns

if [ $1 -eq 1 ]
then
    preset_units %{_presetdir}/%qubes_preset_file initial
    changed=true
else
    preset_units %{_presetdir}/%qubes_preset_file upgrade
    changed=true
    # Upgrade path - now qubes-iptables is used instead
    for svc in iptables ip6tables
    do
        if [ -f "$svc".service ]
        then
            systemctl --no-reload preset "$svc".service
            changed=true
        fi
    done
fi

if [ $1 -eq 1 ]
then
    # First install.
    # Set default "runlevel".
    # FIXME: this ought to be done via kernel command line.
    # The fewer deviations of the template from the seed
    # image, the better.
    rm -f %{_sysconfdir}/systemd/system/default.target
    ln -s %{_unitdir}/multi-user.target %{_sysconfdir}/systemd/system/default.target
    changed=true
fi

# remove old symlinks
if [ -L %{_sysconfdir}/systemd/system/sysinit.target.wants/qubes-random-seed.service ]
then
    rm -f %{_sysconfdir}/systemd/system/sysinit.target.wants/qubes-random-seed.service
    changed=true
fi
if [ -L %{_sysconfdir}/systemd/system/multi-user.target.wants/qubes-mount-home.service ]
then
    rm -f %{_sysconfdir}/systemd/system/multi-user.target.wants/qubes-mount-home.service
    changed=true
fi

if [ "x$changed" != "x" ]
then
    systemctl daemon-reload
fi

%preun systemd

if [ $1 -eq 0 ] ; then
    # Run this only during uninstall.
    # Save the preset file to later use it to re-preset services there
    # once the Qubes OS preset file is removed.
    mkdir -p %{_rundir}/qubes-uninstall
    cp -f %{_presetdir}/%qubes_preset_file %{_rundir}/qubes-uninstall/
fi

%postun systemd

changed=

%scriptletfuns

if [ -d %{_rundir}/qubes-uninstall ]
then
    # We have a saved preset file (or more).
    # Re-preset the units mentioned there.
    restore_units %{_rundir}/qubes-uninstall/%qubes_preset_file
    rm -rf %{_rundir}/qubes-uninstall
    changed=true
fi

if [ "x$changed" != "x" ]
then
    systemctl daemon-reload
fi
