RPMS_DIR=rpm/

VERSION := $(shell cat version)

DIST ?= fc18
KDESERVICEDIR ?= /usr/share/kde4/services
SBINDIR ?= /usr/sbin
LIBDIR ?= /usr/lib
SYSLIBDIR ?= /lib

PYTHON = /usr/bin/python2
PYTHON_SITEARCH = `python2 -c 'import distutils.sysconfig; print distutils.sysconfig.get_python_lib(1)'`

# This makefile uses some bash-isms, make uses /bin/sh by default.
SHELL = /bin/bash

help:
	@echo "make rpms                  -- generate binary rpm packages"
	@echo "make rpms-vm               -- generate binary rpm packages for VM"
	@echo "make clean                 -- cleanup"
	@echo "make install-vm            -- install VM related files"

rpms: rpms-vm

rpms-vm:
	rpmbuild --define "_rpmdir $(RPMS_DIR)" -bb rpm_spec/core-vm.spec
	rpmbuild --define "_rpmdir $(RPMS_DIR)" -bb rpm_spec/core-vm-doc.spec
	rpm --addsign \
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
DROPIN_DIR ?= "lib/systemd"

SYSTEM_DROPINS := chronyd.service crond.service cups.service cups.path cups.socket ModemManager.service
SYSTEM_DROPINS += NetworkManager.service NetworkManager-wait-online.service ntpd.service getty@tty.service
SYSTEM_DROPINS += tinyproxy.service
SYSTEM_DROPINS += tmp.mount
SYSTEM_DROPINS += org.cups.cupsd.service org.cups.cupsd.path org.cups.cupsd.socket

USER_DROPINS := pulseaudio.service pulseaudio.socket

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
endif

install-systemd-dropins:
	# Install system dropins
	@for dropin in $(SYSTEM_DROPINS); do \
	    install -d $(DESTDIR)/$(DROPIN_DIR)/system/$${dropin}.d ;\
	    install -m 0644 vm-systemd/$${dropin}.d/*.conf $(DESTDIR)/$(DROPIN_DIR)/system/$${dropin}.d/ ;\
	done

	# Install user dropins
	@for dropin in $(USER_DROPINS); do \
	    install -d $(DESTDIR)/$(DROPIN_DIR)/user/$${dropin}.d ;\
	    install -m 0644 vm-systemd/user/$${dropin}.d/*.conf $(DESTDIR)/$(DROPIN_DIR)/user/$${dropin}.d/ ;\
	done

install-systemd:
	install -d $(DESTDIR)$(SYSLIBDIR)/systemd/system{,-preset} $(DESTDIR)$(LIBDIR)/qubes/init $(DESTDIR)$(SYSLIBDIR)/modules-load.d
	install -m 0755 vm-systemd/*.sh $(DESTDIR)$(LIBDIR)/qubes/init/
	install -m 0644 vm-systemd/qubes-*.service $(DESTDIR)$(SYSLIBDIR)/systemd/system/
	install -m 0644 vm-systemd/qubes-*.timer $(DESTDIR)$(SYSLIBDIR)/systemd/system/
	install -m 0644 vm-systemd/75-qubes-vm.preset $(DESTDIR)$(SYSLIBDIR)/systemd/system-preset/
	install -m 0644 vm-systemd/qubes-core.conf $(DESTDIR)$(SYSLIBDIR)/modules-load.d/
	install -m 0644 vm-systemd/qubes-misc.conf $(DESTDIR)$(SYSLIBDIR)/modules-load.d/
	install -m 0755 network/qubes-iptables $(DESTDIR)$(LIBDIR)/qubes/init/
	install -D -m 0644 vm-systemd/qubes-core-agent-linux.tmpfiles \
		$(DESTDIR)/usr/lib/tmpfiles.d/qubes-core-agent-linux.conf

install-sysvinit:
	install -d $(DESTDIR)/etc/init.d
	install vm-init.d/qubes-core $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-core-appvm $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-core-netvm $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-firewall $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-netwatcher $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-qrexec-agent $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-updates-proxy $(DESTDIR)/etc/init.d/
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
		$(DESTDIR)/usr/lib/python2.7/site-packages/dnf-plugins/qubes-hooks.py
	install -D -m 0644 misc/dnf-qubes-hooks.pyc \
		$(DESTDIR)/usr/lib/python2.7/site-packages/dnf-plugins/qubes-hooks.pyc
	install -D -m 0644 misc/dnf-qubes-hooks.pyo \
		$(DESTDIR)/usr/lib/python2.7/site-packages/dnf-plugins/qubes-hooks.pyo
	install -D -m 0644 misc/dnf-qubes-hooks.conf $(DESTDIR)/etc/dnf/plugins/qubes-hooks.conf


install-common:
	$(MAKE) -C autostart-dropins install
	install -m 0644 -D misc/fstab $(DESTDIR)/etc/fstab

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
	install -D -m 0644 misc/polkit-1-qubes-allow-all.pkla $(DESTDIR)/etc/polkit-1/localauthority/50-local.d/qubes-allow-all.pkla
	install -D -m 0644 misc/polkit-1-qubes-allow-all.rules $(DESTDIR)/etc/polkit-1/rules.d/00-qubes-allow-all.rules
	install -D -m 0644 misc/mime-globs $(DESTDIR)/usr/share/qubes/mime-override/globs
	install misc/qubes-download-dom0-updates.sh $(DESTDIR)$(LIBDIR)/qubes/
	install -g user -m 2775 -d $(DESTDIR)/var/lib/qubes/dom0-updates

	if [ -r misc/dispvm-dotfiles.$(DIST).tbz ] ; \
	then \
		install misc/dispvm-dotfiles.$(DIST).tbz $(DESTDIR)/etc/dispvm-dotfiles.tbz ; \
	else \
		install misc/dispvm-dotfiles.tbz $(DESTDIR)/etc/dispvm-dotfiles.tbz ; \
	fi;

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
	install -D network/vif-route-qubes $(DESTDIR)/etc/xen/scripts/vif-route-qubes
	install -m 0644 -D network/tinyproxy-updates.conf $(DESTDIR)/etc/tinyproxy/tinyproxy-updates.conf
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

	install qubes-rpc/{qvm-open-in-dvm,qvm-open-in-vm,qvm-copy-to-vm,qvm-move-to-vm,qvm-run,qvm-mru-entry} $(DESTDIR)/usr/bin
	install qubes-rpc/wrap-in-html-if-url.sh $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/qvm-copy-to-vm.kde $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/qvm-copy-to-vm.gnome $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/qvm-move-to-vm.kde $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/qvm-move-to-vm.gnome $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/xdg-icon $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/{vm-file-editor,qfile-agent,qopen-in-vm} $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/tar2qfile $(DESTDIR)$(LIBDIR)/qubes
	# Install qfile-unpacker as SUID - because it will fail to receive files from other vm
	install -m 4755  qubes-rpc/qfile-unpacker $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/qrun-in-vm $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/sync-ntp-clock $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/prepare-suspend $(DESTDIR)$(LIBDIR)/qubes
	install -d $(DESTDIR)/$(KDESERVICEDIR)
	install -m 0644 qubes-rpc/{qvm-copy.desktop,qvm-move.desktop,qvm-dvm.desktop} $(DESTDIR)/$(KDESERVICEDIR)
	install -d $(DESTDIR)/etc/qubes-rpc
	install -m 0644 qubes-rpc/{qubes.Filecopy,qubes.OpenInVM,qubes.VMShell,qubes.SyncNtpClock} $(DESTDIR)/etc/qubes-rpc
	install -m 0644 qubes-rpc/{qubes.SuspendPre,qubes.SuspendPost,qubes.GetAppmenus} $(DESTDIR)/etc/qubes-rpc
	install -m 0644 qubes-rpc/qubes.WaitForSession $(DESTDIR)/etc/qubes-rpc
	install -m 0644 qubes-rpc/qubes.DetachPciDevice $(DESTDIR)/etc/qubes-rpc
	install -m 0644 qubes-rpc/qubes.{Backup,Restore} $(DESTDIR)/etc/qubes-rpc
	install -m 0644 qubes-rpc/qubes.Select{File,Directory} $(DESTDIR)/etc/qubes-rpc
	install -m 0644 qubes-rpc/qubes.GetImageRGBA $(DESTDIR)/etc/qubes-rpc
	install -m 0644 qubes-rpc/qubes.SetDateTime $(DESTDIR)/etc/qubes-rpc
	install -m 0755 qubes-rpc/qubes.InstallUpdatesGUI $(DESTDIR)/etc/qubes-rpc

	install -d $(DESTDIR)/usr/share/nautilus-python/extensions
	install -m 0644 qubes-rpc/*_nautilus.py $(DESTDIR)/usr/share/nautilus-python/extensions

	install -D -m 0755 misc/qubes-desktop-run $(DESTDIR)/usr/bin/qubes-desktop-run

	mkdir -p $(DESTDIR)/$(PYTHON_SITEARCH)/qubes/

ifeq ($(shell lsb_release -is), Debian)
	install -m 0644 misc/xdg.py $(DESTDIR)/$(PYTHON_SITEARCH)/qubes/
else
	install -m 0644 misc/xdg.py* $(DESTDIR)/$(PYTHON_SITEARCH)/qubes/
endif

	install -d $(DESTDIR)/mnt/removable

	install -D -m 0644 misc/xorg-preload-apps.conf $(DESTDIR)/etc/X11/xorg-preload-apps.conf

	install -d $(DESTDIR)/var/run/qubes
	install -d $(DESTDIR)/home_volatile/user
	install -d $(DESTDIR)/rw

install-deb: install-common install-systemd install-systemd-dropins
	mkdir -p $(DESTDIR)/etc/apt/sources.list.d
	sed -e "s/@DIST@/`lsb_release -cs`/" misc/qubes-r3.list.in > $(DESTDIR)/etc/apt/sources.list.d/qubes-r3.list
	install -D -m 644 misc/qubes-archive-keyring.gpg $(DESTDIR)/etc/apt/trusted.gpg.d/qubes-archive-keyring.gpg
	install -D -m 644 network/00notify-hook $(DESTDIR)/etc/apt/apt.conf.d/00notify-hook
	install -d $(DESTDIR)/etc/sysctl.d
	install -m 644 network/80-qubes.conf $(DESTDIR)/etc/sysctl.d/
	install -D -m 644 misc/profile.d_qt_x11_no_mitshm.sh $(DESTDIR)/etc/profile.d/qt_x11_no_mitshm.sh
	install -D -m 440 misc/sudoers.d_umask $(DESTDIR)/etc/sudoers.d/umask
	install -d $(DESTDIR)/etc/pam.d
	install -m 0644 misc/pam.d_su.qubes $(DESTDIR)/etc/pam.d/su.qubes
	install -d $(DESTDIR)/etc/needrestart/conf.d
	install -D -m 0644 misc/50_qubes.conf $(DESTDIR)/etc/needrestart/conf.d/50_qubes.conf


install-vm: install-rh install-common
