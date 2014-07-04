RPMS_DIR=rpm/

VERSION := $(shell cat version)

DIST ?= fc18
KDESERVICEDIR ?= /usr/share/kde4/services
SBINDIR ?= /usr/sbin

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
	make -C dom0/qmemman clean
	make -C dom0/restore clean
	make -C misc clean
	make -C qrexec clean
	make -C u2mfn clean
	make -C vchan -f Makefile.linux clean

install-vm:
	install -m 0644 -D misc/fstab $(DESTDIR)/etc/fstab
	install -d $(DESTDIR)/etc/init.d
	install vm-init.d/* $(DESTDIR)/etc/init.d/

	install -d $(DESTDIR)/lib/systemd/system $(DESTDIR)/usr/lib/qubes/init
	install -m 0755 vm-systemd/*.sh $(DESTDIR)/usr/lib/qubes/init/
	install -m 0644 vm-systemd/qubes-*.service $(DESTDIR)/lib/systemd/system/
	install -m 0644 vm-systemd/qubes-*.timer $(DESTDIR)/lib/systemd/system/
	install -m 0644 vm-systemd/ModemManager.service $(DESTDIR)/usr/lib/qubes/init/
	install -m 0644 vm-systemd/NetworkManager.service $(DESTDIR)/usr/lib/qubes/init/
	install -m 0644 vm-systemd/NetworkManager-wait-online.service $(DESTDIR)/usr/lib/qubes/init/
	install -m 0644 vm-systemd/cups.* $(DESTDIR)/usr/lib/qubes/init/
	install -m 0644 vm-systemd/ntpd.service $(DESTDIR)/usr/lib/qubes/init/
	install -m 0644 vm-systemd/chronyd.service $(DESTDIR)/usr/lib/qubes/init/

	install -D -m 0440 misc/qubes.sudoers $(DESTDIR)/etc/sudoers.d/qubes
	install -D -m 0644 misc/qubes-r2.repo $(DESTDIR)/etc/yum.repos.d/qubes-r2.repo
	install -D -m 0644 misc/serial.conf $(DESTDIR)/usr/share/qubes/serial.conf
	install -D misc/qubes-serial-login $(DESTDIR)/$(SBINDIR)/qubes-serial-login
	install -d $(DESTDIR)/usr/share/glib-2.0/schemas/
	install -m 0644 misc/org.gnome.settings-daemon.plugins.updates.gschema.override $(DESTDIR)/usr/share/glib-2.0/schemas/
	install -m 0644 misc/org.gnome.nautilus.gschema.override $(DESTDIR)/usr/share/glib-2.0/schemas/
	install -d $(DESTDIR)/usr/lib/yum-plugins/
	install -m 0644 misc/yum-qubes-hooks.py* $(DESTDIR)/usr/lib/yum-plugins/
	install -D -m 0644 misc/yum-qubes-hooks.conf $(DESTDIR)/etc/yum/pluginconf.d/yum-qubes-hooks.conf
	install -D misc/close-window $(DESTDIR)/usr/lib/qubes/close-window

	install -d $(DESTDIR)/var/lib/qubes

	install -d -m 755 $(DESTDIR)/etc/pki/rpm-gpg
	install -m 644 misc/RPM-GPG-KEY-qubes* $(DESTDIR)/etc/pki/rpm-gpg/
	install -D misc/xenstore-watch $(DESTDIR)/usr/bin/xenstore-watch-qubes
	install -d $(DESTDIR)/etc/udev/rules.d
	install -m 0644 misc/udev-qubes-misc.rules $(DESTDIR)/etc/udev/rules.d/50-qubes-misc.rules
	install -d $(DESTDIR)/usr/lib/qubes/
	install misc/qubes-download-dom0-updates.sh $(DESTDIR)/usr/lib/qubes/
	install misc/vusb-ctl.py $(DESTDIR)/usr/lib/qubes/
	install misc/qubes-trigger-sync-appmenus.sh $(DESTDIR)/usr/lib/qubes/
	install -D -m 0644 misc/qubes-trigger-sync-appmenus.action $(DESTDIR)/etc/yum/post-actions/qubes-trigger-sync-appmenus.action
	install -D misc/polkit-1-qubes-allow-all.pkla $(DESTDIR)/etc/polkit-1/localauthority/50-local.d/qubes-allow-all.pkla
	install -D misc/polkit-1-qubes-allow-all.rules $(DESTDIR)/etc/polkit-1/rules.d/00-qubes-allow-all.rules
	install -D -m 0644 misc/mime-globs $(DESTDIR)/usr/share/qubes/mime-override/globs

	mkdir -p $(DESTDIR)/usr/lib/qubes

	if [ -r misc/dispvm-dotfiles.$(DIST).tbz ] ; \
	then \
		install misc/dispvm-dotfiles.$(DIST).tbz $(DESTDIR)/etc/dispvm-dotfiles.tbz ; \
	else \
		install misc/dispvm-dotfiles.tbz $(DESTDIR)/etc/dispvm-dotfiles.tbz ; \
	fi;

	install misc/dispvm-prerun.sh $(DESTDIR)/usr/lib/qubes/dispvm-prerun.sh

	install -D misc/qubes-core.modules $(DESTDIR)/etc/sysconfig/modules/qubes-core.modules
	install -D misc/qubes-misc.modules $(DESTDIR)/etc/sysconfig/modules/qubes-misc.modules

	install -m 0644 network/udev-qubes-network.rules $(DESTDIR)/etc/udev/rules.d/99-qubes-network.rules
	install network/qubes-setup-dnat-to-ns $(DESTDIR)/usr/lib/qubes
	install network/qubes-fix-nm-conf.sh $(DESTDIR)/usr/lib/qubes
	install network/setup-ip $(DESTDIR)/usr/lib/qubes/
	install network/network-manager-prepare-conf-dir $(DESTDIR)/usr/lib/qubes/
	install -d $(DESTDIR)/etc/dhclient.d
	ln -s /usr/lib/qubes/qubes-setup-dnat-to-ns $(DESTDIR)/etc/dhclient.d/qubes-setup-dnat-to-ns.sh
	install -d $(DESTDIR)/etc/NetworkManager/dispatcher.d/
	install network/{qubes-nmhook,30-qubes-external-ip} $(DESTDIR)/etc/NetworkManager/dispatcher.d/
	install -D network/vif-route-qubes $(DESTDIR)/etc/xen/scripts/vif-route-qubes
	install -m 0400 -D network/iptables $(DESTDIR)/etc/sysconfig/iptables
	install -m 0400 -D network/ip6tables $(DESTDIR)/etc/sysconfig/ip6tables
	install -m 0644 -D network/tinyproxy-qubes-yum.conf $(DESTDIR)/etc/tinyproxy/tinyproxy-qubes-yum.conf
	install -m 0644 -D network/filter-qubes-yum $(DESTDIR)/etc/tinyproxy/filter-qubes-yum
	install -m 0755 -D network/iptables-yum-proxy $(DESTDIR)/usr/lib/qubes/iptables-yum-proxy
	install -d $(DESTDIR)/etc/xdg/autostart
	install -m 0755 network/show-hide-nm-applet.sh $(DESTDIR)/usr/lib/qubes/show-hide-nm-applet.sh
	install -m 0644 network/show-hide-nm-applet.desktop $(DESTDIR)/etc/xdg/autostart/00-qubes-show-hide-nm-applet.desktop

	install -d $(DESTDIR)/etc/yum.conf.d
	touch $(DESTDIR)/etc/yum.conf.d/qubes-proxy.conf

	install -d $(DESTDIR)/$(SBINDIR)
	install network/qubes-firewall $(DESTDIR)/$(SBINDIR)/
	install network/qubes-netwatcher $(DESTDIR)/$(SBINDIR)/

	install -d $(DESTDIR)/usr/bin

	install qubes-rpc/{qvm-open-in-dvm,qvm-open-in-vm,qvm-copy-to-vm,qvm-move-to-vm,qvm-run,qvm-mru-entry} $(DESTDIR)/usr/bin
	install qubes-rpc/wrap-in-html-if-url.sh $(DESTDIR)/usr/lib/qubes
	install qubes-rpc/qvm-copy-to-vm.kde $(DESTDIR)/usr/lib/qubes
	install qubes-rpc/qvm-copy-to-vm.gnome $(DESTDIR)/usr/lib/qubes
	install qubes-rpc/qvm-move-to-vm.kde $(DESTDIR)/usr/lib/qubes
	install qubes-rpc/qvm-move-to-vm.gnome $(DESTDIR)/usr/lib/qubes
	install qubes-rpc/{vm-file-editor,qfile-agent,qopen-in-vm} $(DESTDIR)/usr/lib/qubes
	install qubes-rpc/tar2qfile $(DESTDIR)/usr/lib/qubes
	# Install qfile-unpacker as SUID - because it will fail to receive files from other vm
	install -m 4755  qubes-rpc/qfile-unpacker $(DESTDIR)/usr/lib/qubes
	install qubes-rpc/qrun-in-vm $(DESTDIR)/usr/lib/qubes
	install qubes-rpc/sync-ntp-clock $(DESTDIR)/usr/lib/qubes
	install qubes-rpc/prepare-suspend $(DESTDIR)/usr/lib/qubes
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

	install -d $(DESTDIR)/usr/share/file-manager/actions
	install -m 0644 qubes-rpc/*-gnome.desktop $(DESTDIR)/usr/share/file-manager/actions

	install -D misc/nautilus-actions.conf $(DESTDIR)/etc/xdg/nautilus-actions/nautilus-actions.conf

	install -d $(DESTDIR)/mnt/removable
	install -d $(DESTDIR)/var/lib/qubes/dom0-updates

	install -D -m 0644 misc/xorg-preload-apps.conf $(DESTDIR)/etc/X11/xorg-preload-apps.conf

	install -d $(DESTDIR)/var/run/qubes
	install -d $(DESTDIR)/home_volatile/user
