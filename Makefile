RPMS_DIR=rpm/

VERSION := $(shell cat version)

DIST ?= fc18
KDESERVICEDIR ?= /usr/share/kde4/services
SBINDIR ?= /usr/sbin
LIBDIR ?= /usr/lib
SYSLIBDIR ?= /lib

# This makefile uses some bash-isms, make uses /bin/sh by default.
SHELL = /bin/bash

help:
	@echo "make rpms                  -- generate binary rpm packages"
	@echo "make rpms-vm               -- generate binary rpm packages for VM"
	@echo "make update-repo-current   -- copy newly generated rpms to qubes yum repo"
	@echo "make update-repo-current-testing  -- same, but to -current-testing repo"
	@echo "make update-repo-unstable  -- same, but to -testing repo"
	@echo "make update-repo-installer -- copy dom0 rpms to installer repo"
	@echo "make clean                 -- cleanup"
	@echo "make install-vm            -- install VM related files"

rpms: rpms-vm

rpms-vm:
	rpmbuild --define "_rpmdir $(RPMS_DIR)" -bb rpm_spec/core-vm.spec
	rpmbuild --define "_rpmdir $(RPMS_DIR)" -bb rpm_spec/core-vm-doc.spec
	rpmbuild --define "_rpmdir $(RPMS_DIR)" -bb rpm_spec/core-vm-kernel-placeholder.spec
	rpm --addsign \
		$(RPMS_DIR)/x86_64/qubes-core-vm-*$(VERSION)*.rpm \
		$(RPMS_DIR)/x86_64/qubes-core-vm-doc-*$(VERSION)*.rpm \
		$(RPMS_DIR)/x86_64/qubes-core-vm-kernel-placeholder-*.rpm

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

install-systemd:
	install -d $(DESTDIR)$(SYSLIBDIR)/systemd/system $(DESTDIR)$(LIBDIR)/qubes/init $(DESTDIR)$(SYSLIBDIR)/modules-load.d
	install -m 0755 vm-systemd/*.sh $(DESTDIR)$(LIBDIR)/qubes/init/
	install -m 0644 vm-systemd/qubes-*.service $(DESTDIR)$(SYSLIBDIR)/systemd/system/
	install -m 0644 vm-systemd/qubes-*.timer $(DESTDIR)$(SYSLIBDIR)/systemd/system/
	install -m 0644 vm-systemd/ModemManager.service $(DESTDIR)$(LIBDIR)/qubes/init/
	install -m 0644 vm-systemd/NetworkManager.service $(DESTDIR)$(LIBDIR)/qubes/init/
	install -m 0644 vm-systemd/NetworkManager-wait-online.service $(DESTDIR)$(LIBDIR)/qubes/init/
	install -m 0644 vm-systemd/qubes-core.conf $(DESTDIR)$(SYSLIBDIR)/modules-load.d/
	install -m 0644 vm-systemd/qubes-misc.conf $(DESTDIR)$(SYSLIBDIR)/modules-load.d/
	install -m 0644 vm-systemd/cups.* $(DESTDIR)$(LIBDIR)/qubes/init/
	install -m 0644 vm-systemd/ntpd.service $(DESTDIR)$(LIBDIR)/qubes/init/
	install -m 0644 vm-systemd/chronyd.service $(DESTDIR)$(LIBDIR)/qubes/init/
	install -m 0644 vm-systemd/crond.service $(DESTDIR)$(LIBDIR)/qubes/init/

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


install-rh: install-systemd install-sysvinit
	install -D -m 0644 misc/qubes-r2.repo $(DESTDIR)/etc/yum.repos.d/qubes-r2.repo
	install -d $(DESTDIR)/usr/share/glib-2.0/schemas/
	install -m 0644 misc/org.gnome.settings-daemon.plugins.updates.gschema.override $(DESTDIR)/usr/share/glib-2.0/schemas/
	install -m 0644 misc/org.gnome.nautilus.gschema.override $(DESTDIR)/usr/share/glib-2.0/schemas/
	install -d $(DESTDIR)$(LIBDIR)/yum-plugins/
	install -m 0644 misc/yum-qubes-hooks.py* $(DESTDIR)$(LIBDIR)/yum-plugins/
	install -D -m 0644 misc/yum-qubes-hooks.conf $(DESTDIR)/etc/yum/pluginconf.d/yum-qubes-hooks.conf
	install -d -m 755 $(DESTDIR)/etc/pki/rpm-gpg
	install -m 644 misc/RPM-GPG-KEY-qubes* $(DESTDIR)/etc/pki/rpm-gpg/
	install -D -m 644 misc/session-stop-timeout.conf $(DESTDIR)$(LIBDIR)/systemd/system/user@.service.d/90-session-stop-timeout.conf


	install -d $(DESTDIR)/etc/yum.conf.d
	touch $(DESTDIR)/etc/yum.conf.d/qubes-proxy.conf

	install misc/qubes-download-dom0-updates.sh $(DESTDIR)$(LIBDIR)/qubes/
	install -d $(DESTDIR)/var/lib/qubes/dom0-updates
	install -D -m 0644 misc/qubes-trigger-sync-appmenus.action $(DESTDIR)/etc/yum/post-actions/qubes-trigger-sync-appmenus.action

	install -D -m 0644 misc/serial.conf $(DESTDIR)/usr/share/qubes/serial.conf
	install -D misc/qubes-serial-login $(DESTDIR)/$(SBINDIR)/qubes-serial-login

	install -m 0400 -D network/iptables $(DESTDIR)/usr/lib/qubes/init/iptables
	install -m 0400 -D network/ip6tables $(DESTDIR)/usr/lib/qubes/init/ip6tables

install-common:
	install -m 0644 -D misc/fstab $(DESTDIR)/etc/fstab

	install -D -m 0440 misc/qubes.sudoers $(DESTDIR)/etc/sudoers.d/qubes

	install -d $(DESTDIR)/var/lib/qubes

	install -D misc/xenstore-watch $(DESTDIR)/usr/bin/xenstore-watch-qubes
	install -d $(DESTDIR)/etc/udev/rules.d
	install -m 0644 misc/udev-qubes-misc.rules $(DESTDIR)/etc/udev/rules.d/50-qubes-misc.rules
	install -d $(DESTDIR)$(LIBDIR)/qubes/
	install misc/vusb-ctl.py $(DESTDIR)$(LIBDIR)/qubes/
	install misc/qubes-trigger-sync-appmenus.sh $(DESTDIR)$(LIBDIR)/qubes/
	install -D misc/polkit-1-qubes-allow-all.pkla $(DESTDIR)/etc/polkit-1/localauthority/50-local.d/qubes-allow-all.pkla
	install -D misc/polkit-1-qubes-allow-all.rules $(DESTDIR)/etc/polkit-1/rules.d/00-qubes-allow-all.rules
	install -D -m 0644 misc/mime-globs $(DESTDIR)/usr/share/qubes/mime-override/globs

	mkdir -p $(DESTDIR)$(LIBDIR)/qubes

	if [ -r misc/dispvm-dotfiles.$(DIST).tbz ] ; \
	then \
		install misc/dispvm-dotfiles.$(DIST).tbz $(DESTDIR)/etc/dispvm-dotfiles.tbz ; \
	else \
		install misc/dispvm-dotfiles.tbz $(DESTDIR)/etc/dispvm-dotfiles.tbz ; \
	fi;

	install misc/dispvm-prerun.sh $(DESTDIR)$(LIBDIR)/qubes/dispvm-prerun.sh
	install misc/close-window $(DESTDIR)$(LIBDIR)/qubes/close-window

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
	install -m 0644 -D network/filter-updates $(DESTDIR)/etc/tinyproxy/filter-updates
	install -m 0755 -D network/iptables-updates-proxy $(DESTDIR)$(LIBDIR)/qubes/iptables-updates-proxy
	install -d $(DESTDIR)/etc/xdg/autostart
	install -m 0755 network/show-hide-nm-applet.sh $(DESTDIR)$(LIBDIR)/qubes/show-hide-nm-applet.sh
	install -m 0644 network/show-hide-nm-applet.desktop $(DESTDIR)/etc/xdg/autostart/00-qubes-show-hide-nm-applet.desktop

	install -d $(DESTDIR)/$(SBINDIR)
	install network/qubes-firewall $(DESTDIR)/$(SBINDIR)/
	install network/qubes-netwatcher $(DESTDIR)/$(SBINDIR)/

	install -d $(DESTDIR)/usr/bin

	install qubes-rpc/{qvm-open-in-dvm,qvm-open-in-vm,qvm-copy-to-vm,qvm-move-to-vm,qvm-run,qvm-mru-entry} $(DESTDIR)/usr/bin
	install qubes-rpc/wrap-in-html-if-url.sh $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/qvm-copy-to-vm.kde $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/qvm-copy-to-vm.gnome $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/qvm-move-to-vm.kde $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/qvm-move-to-vm.gnome $(DESTDIR)$(LIBDIR)/qubes
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

	install -d $(DESTDIR)/usr/share/nautilus-python/extensions
	install -m 0644 qubes-rpc/*_nautilus.py $(DESTDIR)/usr/share/nautilus-python/extensions

	install -D -m 0755 misc/qubes-desktop-run $(DESTDIR)/usr/bin/qubes-desktop-run

	install -d $(DESTDIR)/mnt/removable

	install -D -m 0644 misc/xorg-preload-apps.conf $(DESTDIR)/etc/X11/xorg-preload-apps.conf

	install -d $(DESTDIR)/var/run/qubes
	install -d $(DESTDIR)/home_volatile/user
	install -d $(DESTDIR)/rw

install-deb:
	mkdir -p $(DESTDIR)/etc/apt/sources.list.d
	sed -e "s/@DIST@/`lsb_release -cs`/" misc/qubes-r2.list.in > $(DESTDIR)/etc/apt/sources.list.d/qubes-r2.list
	install -D -m 644 misc/qubes-archive-keyring.gpg $(DESTDIR)/etc/apt/trusted.gpg.d/qubes-archive-keyring.gpg
	install -D -m 644 network/iptables $(DESTDIR)/etc/iptables/rules.v4
	install -D -m 644 network/ip6tables $(DESTDIR)/etc/iptables/rules.v6
	install -d $(DESTDIR)/etc/sysctl.d
	install -m 644 network/80-qubes.conf $(DESTDIR)/etc/sysctl.d/
	install -D -m 644 misc/profile.d_qt_x11_no_mitshm.sh $(DESTDIR)/etc/profile.d/qt_x11_no_mitshm.sh
	install -D -m 440 misc/sudoers.d_umask $(DESTDIR)/etc/sudoers.d/umask
	install -D -m 440 misc/sudoers.d_qt_x11_no_mitshm $(DESTDIR)/etc/sudoers.d/qt_x11_no_mitshm

install-vm: install-rh install-common
