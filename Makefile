RPMS_DIR=rpm/

VERSION := $(shell cat version)

DIST ?= fc18
KDESERVICEDIR ?= /usr/share/kde4/services
SBINDIR ?= /usr/sbin
LIBDIR ?= /usr/lib
SYSLIBDIR ?= /lib

PYTHON = /usr/bin/python2
PYTHON_SITEARCH = `python2 -c 'import distutils.sysconfig; print distutils.sysconfig.get_python_lib(1)'`
PYTHON2_SITELIB = `python2 -c 'import distutils.sysconfig; print distutils.sysconfig.get_python_lib()'`
PYTHON3_SITELIB = `python3 -c 'import distutils.sysconfig; print(distutils.sysconfig.get_python_lib())'`

# This makefile uses some bash-isms, make uses /bin/sh by default.
SHELL = /bin/bash

help:
	@echo "make rpms                  -- generate binary rpm packages"
	@echo "make rpms-vm               -- generate binary rpm packages for VM"
	@echo "make clean                 -- cleanup"
	@echo "make install-vm            -- install VM related files"
	@echo ""
	@echo "You must have lsb_release, rpm-sign and pandoc installed."

rpms: rpms-vm

rpms-vm:
	[ "$$BACKEND_VMM" != "" ] || { echo "error: you must define variable BACKEND_VMM" >&2 ; exit 1 ; }
	lsb_release >/dev/null 2>&1 || { echo "error: you need lsb_release (package lsb) installed" >&2 ; exit 1 ; }
	type pandoc >/dev/null 2>&1 || { echo "error: you need pandoc installed" >&2 ; exit 1 ; }
	type rpmsign >/dev/null 2>&1 || { echo "error: you need rpm-sign installed" >&2 ; exit 1 ; }
	rpmbuild --define "_rpmdir $(RPMS_DIR)" -bb rpm_spec/core-vm.spec
	rpmbuild --define "_rpmdir $(RPMS_DIR)" -bb rpm_spec/core-vm-doc.spec
	[ "$$SKIP_SIGNING" != "" ] || rpm --addsign \
		$(RPMS_DIR)/x86_64/qubes-core-vm-*$(VERSION)*.rpm \
		$(RPMS_DIR)/x86_64/qubes-core-vm-doc-*$(VERSION)*.rpm

rpms-dom0:
	@true

clean:
	make -C misc clean
	make -C qrexec clean
	make -C qubes-rpc clean

all:
	make -C misc
	make -C qrexec
	make -C qubes-rpc

# Dropin Directory
SYSTEM_DROPIN_DIR ?= "lib/systemd/system"
USER_DROPIN_DIR ?= "usr/lib/systemd/user"

SYSTEM_DROPINS := chronyd.service crond.service
SYSTEM_DROPINS += cups.service cups-browsed.service cups.path cups.socket ModemManager.service
SYSTEM_DROPINS += NetworkManager.service NetworkManager-wait-online.service ntpd.service getty@tty.service
SYSTEM_DROPINS += tinyproxy.service
SYSTEM_DROPINS += tmp.mount
SYSTEM_DROPINS += org.cups.cupsd.service org.cups.cupsd.path org.cups.cupsd.socket
SYSTEM_DROPINS += systemd-random-seed.service
SYSTEM_DROPINS += tor.service tor@default.service

USER_DROPINS := pulseaudio.service pulseaudio.socket

# Ubuntu Dropins
ifeq ($(shell lsb_release -is), Ubuntu)

    # 'crond.service' is named 'cron.service in Debian
    SYSTEM_DROPINS := $(strip $(patsubst crond.service, cron.service, $(SYSTEM_DROPINS)))
    SYSTEM_DROPINS += anacron.service
    SYSTEM_DROPINS += anacron-resume.service
endif

# Debian Dropins
ifeq ($(shell lsb_release -is), Debian)
    # Don't have 'ntpd' in Debian
    SYSTEM_DROPINS := $(filter-out ntpd.service, $(SYSTEM_DROPINS))

    # 'crond.service' is named 'cron.service in Debian
    SYSTEM_DROPINS := $(strip $(patsubst crond.service, cron.service, $(SYSTEM_DROPINS)))

    # Wheezy System Dropins
    # Disable sysinit 'network-manager.service' since systemd 'NetworkManager.service' is already installed
    SYSTEM_DROPINS += $(strip $(if $(filter wheezy, $(shell lsb_release -cs)), network-manager.service,))

    # handled by qubes-iptables service now
    SYSTEM_DROPINS += netfilter-persistent.service

    SYSTEM_DROPINS += anacron.service
    SYSTEM_DROPINS += anacron-resume.service
    SYSTEM_DROPINS += exim4.service
    SYSTEM_DROPINS += avahi-daemon.service
endif

install-systemd-dropins:
	# Install system dropins
	@for dropin in $(SYSTEM_DROPINS); do \
	    install -d $(DESTDIR)/$(SYSTEM_DROPIN_DIR)/$${dropin}.d ;\
	    install -m 0644 vm-systemd/$${dropin}.d/*.conf $(DESTDIR)/$(SYSTEM_DROPIN_DIR)/$${dropin}.d/ ;\
	done

	# Install user dropins
	@for dropin in $(USER_DROPINS); do \
	    install -d $(DESTDIR)/$(USER_DROPIN_DIR)/$${dropin}.d ;\
	    install -m 0644 vm-systemd/user/$${dropin}.d/*.conf $(DESTDIR)/$(USER_DROPIN_DIR)/$${dropin}.d/ ;\
	done

install-init:
	install -d $(DESTDIR)$(LIBDIR)/qubes/init
	# FIXME: do a source code move vm-systemd/*.sh to init/
	# since those scripts are shared between sysvinit and systemd.
	install -m 0755 init/*.sh vm-systemd/*.sh $(DESTDIR)$(LIBDIR)/qubes/init/
	install -m 0644 init/functions $(DESTDIR)$(LIBDIR)/qubes/init/

install-systemd: install-init
	install -d $(DESTDIR)$(SYSLIBDIR)/systemd/system{,-preset} $(DESTDIR)$(LIBDIR)/qubes/init $(DESTDIR)$(SYSLIBDIR)/modules-load.d
	install -m 0644 vm-systemd/qubes-*.service $(DESTDIR)$(SYSLIBDIR)/systemd/system/
	install -m 0644 vm-systemd/qubes-*.timer $(DESTDIR)$(SYSLIBDIR)/systemd/system/
	install -m 0644 vm-systemd/75-qubes-vm.preset $(DESTDIR)$(SYSLIBDIR)/systemd/system-preset/
	install -m 0644 vm-systemd/qubes-core.conf $(DESTDIR)$(SYSLIBDIR)/modules-load.d/
	install -m 0644 vm-systemd/qubes-misc.conf $(DESTDIR)$(SYSLIBDIR)/modules-load.d/
	install -m 0755 network/qubes-iptables $(DESTDIR)$(LIBDIR)/qubes/init/
	install -D -m 0644 vm-systemd/qubes-core-agent-linux.tmpfiles \
		$(DESTDIR)/usr/lib/tmpfiles.d/qubes-core-agent-linux.conf

install-sysvinit: install-init
	install -d $(DESTDIR)/etc/init.d
	install vm-init.d/qubes-sysinit $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-core-early $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-core $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-core-netvm $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-firewall $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-netwatcher $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-qrexec-agent $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-updates-proxy $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-dvm $(DESTDIR)/etc/init.d/
	install -D vm-init.d/qubes-core.modules $(DESTDIR)/etc/sysconfig/modules/qubes-core.modules
	install -D vm-init.d/qubes-misc.modules $(DESTDIR)/etc/sysconfig/modules/qubes-misc.modules
	install network/qubes-iptables $(DESTDIR)/etc/init.d/

install-rh: install-systemd install-systemd-dropins install-sysvinit
	install -D -m 0644 misc/qubes-r3.repo $(DESTDIR)/etc/yum.repos.d/qubes-r3.repo
	install -d $(DESTDIR)/usr/share/glib-2.0/schemas/
	install -m 0644 misc/org.gnome.settings-daemon.plugins.updates.gschema.override $(DESTDIR)/usr/share/glib-2.0/schemas/
	install -m 0644 misc/org.gnome.nautilus.gschema.override $(DESTDIR)/usr/share/glib-2.0/schemas/
	install -m 0644 misc/org.mate.NotificationDaemon.gschema.override $(DESTDIR)/usr/share/glib-2.0/schemas/
	install -d $(DESTDIR)$(LIBDIR)/yum-plugins/
	install -m 0644 misc/yum-qubes-hooks.py* $(DESTDIR)$(LIBDIR)/yum-plugins/
	install -D -m 0644 misc/yum-qubes-hooks.conf $(DESTDIR)/etc/yum/pluginconf.d/yum-qubes-hooks.conf
	install -d -m 755 $(DESTDIR)/etc/pki/rpm-gpg
	install -m 644 misc/RPM-GPG-KEY-qubes* $(DESTDIR)/etc/pki/rpm-gpg/
	install -D -m 644 misc/session-stop-timeout.conf $(DESTDIR)$(LIBDIR)/systemd/system/user@.service.d/90-session-stop-timeout.conf

	install -d $(DESTDIR)/etc/yum.conf.d
	touch $(DESTDIR)/etc/yum.conf.d/qubes-proxy.conf

	install -D -m 0644 misc/qubes-trigger-sync-appmenus.action $(DESTDIR)/etc/yum/post-actions/qubes-trigger-sync-appmenus.action

	install -D -m 0644 misc/serial.conf $(DESTDIR)/usr/share/qubes/serial.conf
	install -D misc/qubes-serial-login $(DESTDIR)/$(SBINDIR)/qubes-serial-login
	install -D -m 0644 misc/dracut-qubes.conf \
		$(DESTDIR)/usr/lib/dracut/dracut.conf.d/30-qubes.conf

	install -D -m 0644 misc/dnf-qubes-hooks.py \
		$(DESTDIR)$(PYTHON2_SITELIB)/dnf-plugins/qubes-hooks.py
	install -D -m 0644 misc/dnf-qubes-hooks.py \
		$(DESTDIR)$(PYTHON3_SITELIB)/dnf-plugins/qubes-hooks.py
	install -D -m 0644 misc/dnf-qubes-hooks.conf $(DESTDIR)/etc/dnf/plugins/qubes-hooks.conf


install-common:
	$(MAKE) -C autostart-dropins install
	install -m 0644 -D misc/fstab $(DESTDIR)/etc/fstab

	install -d -m 0750 $(DESTDIR)/etc/sudoers.d/
	install -D -m 0440 misc/qubes.sudoers $(DESTDIR)/etc/sudoers.d/qubes
	install -D -m 0440 misc/sudoers.d_qt_x11_no_mitshm $(DESTDIR)/etc/sudoers.d/qt_x11_no_mitshm
	install -D -m 0644 misc/20_tcp_timestamps.conf $(DESTDIR)/etc/sysctl.d/20_tcp_timestamps.conf

	install -d $(DESTDIR)/var/lib/qubes

	install -D misc/xenstore-watch $(DESTDIR)/usr/bin/xenstore-watch-qubes
	install -d $(DESTDIR)/etc/udev/rules.d
	install -m 0644 misc/udev-qubes-misc.rules $(DESTDIR)/etc/udev/rules.d/50-qubes-misc.rules
	install -d $(DESTDIR)$(LIBDIR)/qubes/
	install misc/vusb-ctl.py $(DESTDIR)$(LIBDIR)/qubes/
	install misc/qubes-trigger-sync-appmenus.sh $(DESTDIR)$(LIBDIR)/qubes/
	install -d -m 0750 $(DESTDIR)/etc/polkit-1/rules.d
	install -D -m 0644 misc/polkit-1-qubes-allow-all.pkla $(DESTDIR)/etc/polkit-1/localauthority/50-local.d/qubes-allow-all.pkla
	install -D -m 0644 misc/polkit-1-qubes-allow-all.rules $(DESTDIR)/etc/polkit-1/rules.d/00-qubes-allow-all.rules
	install -D -m 0644 misc/mime-globs $(DESTDIR)/usr/share/qubes/mime-override/globs
	install misc/qubes-download-dom0-updates.sh $(DESTDIR)$(LIBDIR)/qubes/
	install -g user -m 2775 -d $(DESTDIR)/var/lib/qubes/dom0-updates
	install -D -m 0644 misc/qubes-master-key.asc $(DESTDIR)/usr/share/qubes/qubes-master-key.asc

	install misc/dispvm-prerun.sh $(DESTDIR)$(LIBDIR)/qubes/dispvm-prerun.sh
	install misc/close-window $(DESTDIR)$(LIBDIR)/qubes/close-window

	install misc/upgrades-installed-check $(DESTDIR)$(LIBDIR)/qubes/upgrades-installed-check
	install misc/upgrades-status-notify $(DESTDIR)$(LIBDIR)/qubes/upgrades-status-notify

	install -m 0644 network/udev-qubes-network.rules $(DESTDIR)/etc/udev/rules.d/99-qubes-network.rules
	install network/qubes-setup-dnat-to-ns $(DESTDIR)$(LIBDIR)/qubes
	install network/qubes-fix-nm-conf.sh $(DESTDIR)$(LIBDIR)/qubes
	install network/setup-ip $(DESTDIR)$(LIBDIR)/qubes/
	install network/network-manager-prepare-conf-dir $(DESTDIR)$(LIBDIR)/qubes/
	install -d $(DESTDIR)/etc/dhclient.d
	ln -s /usr/lib/qubes/qubes-setup-dnat-to-ns $(DESTDIR)/etc/dhclient.d/qubes-setup-dnat-to-ns.sh
	install -d $(DESTDIR)/etc/NetworkManager/dispatcher.d/
	install network/{qubes-nmhook,30-qubes-external-ip} $(DESTDIR)/etc/NetworkManager/dispatcher.d/
	install -d $(DESTDIR)/usr/lib/NetworkManager/conf.d
	install -m 0644 network/nm-30-qubes.conf $(DESTDIR)/usr/lib/NetworkManager/conf.d/30-qubes.conf
	install -D network/vif-route-qubes $(DESTDIR)/etc/xen/scripts/vif-route-qubes
	install -m 0644 -D network/tinyproxy-updates.conf $(DESTDIR)/etc/tinyproxy/tinyproxy-updates.conf
	install -m 0644 -D network/updates-blacklist $(DESTDIR)/etc/tinyproxy/updates-blacklist
	install -m 0755 -D network/iptables-updates-proxy $(DESTDIR)$(LIBDIR)/qubes/iptables-updates-proxy
	install -d $(DESTDIR)/etc/xdg/autostart
	install -m 0755 network/show-hide-nm-applet.sh $(DESTDIR)$(LIBDIR)/qubes/show-hide-nm-applet.sh
	install -m 0644 network/show-hide-nm-applet.desktop $(DESTDIR)/etc/xdg/autostart/00-qubes-show-hide-nm-applet.desktop
	install -m 0400 -D network/iptables $(DESTDIR)/etc/qubes/iptables.rules
	install -m 0400 -D network/ip6tables $(DESTDIR)/etc/qubes/ip6tables.rules
	install -m 0755 network/update-proxy-configs $(DESTDIR)$(LIBDIR)/qubes/


	install -d $(DESTDIR)/$(SBINDIR)
	install network/qubes-firewall $(DESTDIR)/$(SBINDIR)/
	install network/qubes-netwatcher $(DESTDIR)/$(SBINDIR)/

	install -d $(DESTDIR)/usr/bin
	install -m 0755 misc/qubes-session-autostart $(DESTDIR)/usr/bin/qubes-session-autostart

	install qubes-rpc/{qvm-open-in-dvm,qvm-open-in-vm,qvm-copy-to-vm,qvm-run,qvm-mru-entry} $(DESTDIR)/usr/bin
	ln -s qvm-copy-to-vm $(DESTDIR)/usr/bin/qvm-move-to-vm
	install qubes-rpc/qvm-copy-to-vm.kde $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/qvm-copy-to-vm.gnome $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/qvm-move-to-vm.kde $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/qvm-move-to-vm.gnome $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/xdg-icon $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/{vm-file-editor,qfile-agent,qopen-in-vm} $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/qubes-open $(DESTDIR)/usr/bin
	install qubes-rpc/tar2qfile $(DESTDIR)$(LIBDIR)/qubes
	# Install qfile-unpacker as SUID - because it will fail to receive files from other vm
	install -m 4755  qubes-rpc/qfile-unpacker $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/qrun-in-vm $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/sync-ntp-clock $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/prepare-suspend $(DESTDIR)$(LIBDIR)/qubes
	install -m 0644 misc/qubes-suspend-module-blacklist $(DESTDIR)/etc/qubes-suspend-module-blacklist
	install -d $(DESTDIR)/$(KDESERVICEDIR)
	install -m 0644 qubes-rpc/{qvm-copy.desktop,qvm-move.desktop,qvm-dvm.desktop} $(DESTDIR)/$(KDESERVICEDIR)
	install -d $(DESTDIR)/etc/qubes-rpc
	install -m 0755 qubes-rpc/{qubes.Filecopy,qubes.OpenInVM,qubes.VMShell,qubes.SyncNtpClock} $(DESTDIR)/etc/qubes-rpc
	install -m 0755 qubes-rpc/qubes.OpenURL $(DESTDIR)/etc/qubes-rpc
	install -m 0755 qubes-rpc/{qubes.SuspendPre,qubes.SuspendPost,qubes.GetAppmenus} $(DESTDIR)/etc/qubes-rpc
	install -m 0755 qubes-rpc/qubes.SuspendPreAll $(DESTDIR)/etc/qubes-rpc
	install -m 0755 qubes-rpc/qubes.SuspendPostAll $(DESTDIR)/etc/qubes-rpc
	install -m 0755 qubes-rpc/qubes.WaitForSession $(DESTDIR)/etc/qubes-rpc
	install -m 0755 qubes-rpc/qubes.DetachPciDevice $(DESTDIR)/etc/qubes-rpc
	install -m 0755 qubes-rpc/qubes.{Backup,Restore} $(DESTDIR)/etc/qubes-rpc
	install -m 0755 qubes-rpc/qubes.Select{File,Directory} $(DESTDIR)/etc/qubes-rpc
	install -m 0755 qubes-rpc/qubes.GetImageRGBA $(DESTDIR)/etc/qubes-rpc
	install -m 0755 qubes-rpc/qubes.SetDateTime $(DESTDIR)/etc/qubes-rpc
	install -m 0755 qubes-rpc/qubes.InstallUpdatesGUI $(DESTDIR)/etc/qubes-rpc

	install -d $(DESTDIR)/etc/qubes/suspend-pre.d
	install -m 0644 qubes-rpc/suspend-pre.README $(DESTDIR)/etc/qubes/suspend-pre.d/README
	install -d $(DESTDIR)/etc/qubes/suspend-post.d
	install -m 0644 qubes-rpc/suspend-post.README $(DESTDIR)/etc/qubes/suspend-post.d/README

	install -d $(DESTDIR)/usr/share/nautilus-python/extensions
	install -m 0644 qubes-rpc/*_nautilus.py $(DESTDIR)/usr/share/nautilus-python/extensions

	install -D -m 0755 misc/qubes-desktop-run $(DESTDIR)/usr/bin/qubes-desktop-run

	mkdir -p $(DESTDIR)/$(PYTHON_SITEARCH)/qubes/

ifeq ($(shell lsb_release -is), Debian)
	install -m 0644 misc/xdg.py $(DESTDIR)/$(PYTHON_SITEARCH)/qubes/
else
	install -m 0644 misc/py2/xdg.py* $(DESTDIR)/$(PYTHON_SITEARCH)/qubes/
endif

ifneq (,$(filter xenial zesty stretch, $(shell lsb_release -cs)))
	mkdir -p $(DESTDIR)/etc/systemd/system/
	install -m 0644 vm-systemd/haveged.service  $(DESTDIR)/etc/systemd/system/
endif

	install -d $(DESTDIR)/mnt/removable

	install -D -m 0644 misc/xorg-preload-apps.conf $(DESTDIR)/etc/X11/xorg-preload-apps.conf

	install -d $(DESTDIR)/usr/lib/qubes-bind-dirs.d
	install -D -m 0644 misc/30_cron.conf $(DESTDIR)/usr/lib/qubes-bind-dirs.d/30_cron.conf


	install -d $(DESTDIR)/var/run/qubes
	install -d $(DESTDIR)/home_volatile/user
	install -d $(DESTDIR)/rw

install-deb: install-common install-systemd install-systemd-dropins
	mkdir -p $(DESTDIR)/etc/apt/sources.list.d
	sed -e "s/@DIST@/`lsb_release -cs`/" misc/qubes-r3.list.in > $(DESTDIR)/etc/apt/sources.list.d/qubes-r3.list
	install -D -m 644 misc/qubes-archive-keyring.gpg $(DESTDIR)/etc/apt/trusted.gpg.d/qubes-archive-keyring.gpg
	install -D -m 644 network/00notify-hook $(DESTDIR)/etc/apt/apt.conf.d/00notify-hook
	install -D -m 0644 misc/apt-conf-70no-unattended $(DESTDIR)/etc/apt/apt.conf.d/70no-unattended
	install -d $(DESTDIR)/etc/sysctl.d
	install -m 644 network/80-qubes.conf $(DESTDIR)/etc/sysctl.d/
	install -D -m 644 misc/profile.d_qt_x11_no_mitshm.sh $(DESTDIR)/etc/profile.d/qt_x11_no_mitshm.sh
	install -D -m 440 misc/sudoers.d_umask $(DESTDIR)/etc/sudoers.d/umask
	install -d $(DESTDIR)/etc/pam.d
	install -m 0644 misc/pam.d_su.qubes $(DESTDIR)/etc/pam.d/su.qubes
	install -d $(DESTDIR)/etc/needrestart/conf.d
	install -D -m 0644 misc/50_qubes.conf $(DESTDIR)/etc/needrestart/conf.d/50_qubes.conf
	install -d $(DESTDIR)/usr/share/glib-2.0/schemas/
	install -m 0644 misc/org.gnome.nautilus.gschema.override $(DESTDIR)/usr/share/glib-2.0/schemas/


install-vm: install-rh install-common
