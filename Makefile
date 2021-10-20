VERSION := $(file <version)

ifneq (,$(wildcard /etc/fedora-release))
DIST = fc$(shell rpm --eval %{fedora})
else ifneq (,$(wildcard /etc/centos-release))
ifeq (CentOSStream, $(shell lsb_release -is))
DIST = centos-stream
else
DIST = centos
endif
else ifneq (,$(wildcard /etc/os-release))
DIST = $(shell grep VERSION_CODENAME= /etc/os-release | cut -d'=' -f2)
endif

ifeq (,$(DIST))
# On debian if previous attempt failed
# it means we are on sid
ifneq (,$(wildcard /etc/debian_version))
DIST = $(shell cut -d'/' -f1 /etc/debian_version)
endif
endif

DIST ?= fc33
KDESERVICEDIR ?= /usr/share/kde4/services
KDE5SERVICEDIR ?= /usr/share/kservices5/ServiceMenus/
APPLICATIONSDIR ?= /usr/share/applications
SBINDIR ?= /usr/sbin
BINDIR ?= /usr/bin
LIBDIR ?= /usr/lib
SYSLIBDIR ?= /lib

PYTHON ?= /usr/bin/python3
PYTHON_SITEARCH = $(shell python2 -c 'import distutils.sysconfig; print distutils.sysconfig.get_python_lib(1)')
PYTHON2_SITELIB = $(shell python2 -c 'import distutils.sysconfig; print distutils.sysconfig.get_python_lib()')
PYTHON3_SITELIB = $(shell $(PYTHON) -c 'import distutils.sysconfig; print(distutils.sysconfig.get_python_lib())')
ifeq ($(shell rpm --eval %{centos_ver} 2>/dev/null),8)
PLATFORM_PYTHON3_SITELIB = $(shell /usr/libexec/platform-python -c 'import distutils.sysconfig; print(distutils.sysconfig.get_python_lib())')
endif

# This makefile uses some bash-isms, make uses /bin/sh by default.
SHELL = /bin/bash

clean:
	make -C misc clean
	make -C qrexec clean
	make -C qubes-rpc clean
	make -C doc clean
	rm -rf qubesagent/*.pyc qubesagent/__pycache__
	rm -rf test-packages/__pycache__
	rm -rf test-packages/qubesagent.egg-info
	rm -rf __pycache__
	rm -rf debian/changelog.*
	rm -rf pkgs
	rm -f .coverage

all:
	make -C misc
	make -C qrexec
	make -C qubes-rpc

# Dropin Directory
SYSTEM_DROPIN_DIR ?= "lib/systemd/system"
USER_DROPIN_DIR ?= "usr/lib/systemd/user"

SYSTEM_DROPINS := boot.automount chronyd.service crond.service
SYSTEM_DROPINS += cups.service cups-browsed.service cups.path cups.socket ModemManager.service
SYSTEM_DROPINS += getty@tty.service
SYSTEM_DROPINS += tmp.mount
SYSTEM_DROPINS += org.cups.cupsd.service org.cups.cupsd.path org.cups.cupsd.socket
SYSTEM_DROPINS += systemd-random-seed.service
SYSTEM_DROPINS += tor.service tor@default.service
SYSTEM_DROPINS += systemd-timesyncd.service
SYSTEM_DROPINS += systemd-logind.service

SYSTEM_DROPINS_NETWORKING := NetworkManager.service NetworkManager-wait-online.service
SYSTEM_DROPINS_NETWORKING += tinyproxy.service

USER_DROPINS := pulseaudio.service pulseaudio.socket

# Ubuntu Dropins
ifeq ($(shell lsb_release -is), Ubuntu)

    # 'crond.service' is named 'cron.service in Debian
    SYSTEM_DROPINS := $(strip $(patsubst crond.service, cron.service, $(SYSTEM_DROPINS)))
    SYSTEM_DROPINS += anacron.service
    SYSTEM_DROPINS += anacron-resume.service
    SYSTEM_DROPINS += netfilter-persistent.service
    SYSTEM_DROPINS += exim4.service
    SYSTEM_DROPINS += avahi-daemon.service

endif

# Debian Dropins
ifeq ($(shell lsb_release -is), Debian)
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

install-systemd-networking-dropins:
	# Install system dropins
	@for dropin in $(SYSTEM_DROPINS_NETWORKING); do \
	    install -d $(DESTDIR)/$(SYSTEM_DROPIN_DIR)/$${dropin}.d ;\
	    install -m 0644 vm-systemd/$${dropin}.d/*.conf $(DESTDIR)/$(SYSTEM_DROPIN_DIR)/$${dropin}.d/ ;\
	done

install-init:
	install -d $(DESTDIR)$(LIBDIR)/qubes/init
	# FIXME: do a source code move vm-systemd/*.sh to init/
	# since those scripts are shared between sysvinit and systemd.
	install -m 0755 init/*.sh vm-systemd/*.sh $(DESTDIR)$(LIBDIR)/qubes/init/
	install -m 0644 init/functions $(DESTDIR)$(LIBDIR)/qubes/init/

# Systemd service files
SYSTEMD_ALL_SERVICES := $(wildcard vm-systemd/qubes-*.service)
SYSTEMD_NETWORK_SERVICES := vm-systemd/qubes-firewall.service vm-systemd/qubes-iptables.service vm-systemd/qubes-updates-proxy.service
SYSTEMD_CORE_SERVICES := $(filter-out $(SYSTEMD_NETWORK_SERVICES), $(SYSTEMD_ALL_SERVICES))

install-systemd: install-init
	install -d $(DESTDIR)$(SYSLIBDIR)/systemd/system{,-preset} $(DESTDIR)$(LIBDIR)/qubes/init $(DESTDIR)$(SYSLIBDIR)/modules-load.d
	install -m 0644 $(SYSTEMD_CORE_SERVICES) $(DESTDIR)$(SYSLIBDIR)/systemd/system/
	install -m 0644 vm-systemd/qubes-*.timer $(DESTDIR)$(SYSLIBDIR)/systemd/system/
	install -m 0644 vm-systemd/75-qubes-vm.preset $(DESTDIR)$(SYSLIBDIR)/systemd/system-preset/
	install -m 0644 vm-systemd/qubes-core.conf $(DESTDIR)$(SYSLIBDIR)/modules-load.d/

install-sysvinit: install-init
	install -d $(DESTDIR)/etc/init.d
	install vm-init.d/qubes-sysinit $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-core-early $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-core $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-core-netvm $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-firewall $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-qrexec-agent $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-updates-proxy $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-updates-proxy-forwarder $(DESTDIR)/etc/init.d/
	install -D vm-init.d/qubes-core.modules $(DESTDIR)/etc/sysconfig/modules/qubes-core.modules
	install network/qubes-iptables $(DESTDIR)/etc/init.d/

install-rh: install-systemd install-systemd-dropins install-sysvinit
	install -D -m 0644 misc/qubes-r4.repo.in $(DESTDIR)/etc/yum.repos.d/qubes-r4.repo
	DIST='$(DIST)'; sed -i "s/@DIST@/$${DIST%%[0-9]*}/g" $(DESTDIR)/etc/yum.repos.d/qubes-r4.repo
	install -d $(DESTDIR)$(LIBDIR)/yum-plugins/
	install -d -m 755 $(DESTDIR)/etc/pki/rpm-gpg
	install -m 644 misc/RPM-GPG-KEY-qubes* $(DESTDIR)/etc/pki/rpm-gpg/
	install -D -m 644 misc/session-stop-timeout.conf $(DESTDIR)$(LIBDIR)/systemd/system/user@.service.d/90-session-stop-timeout.conf

	install -d $(DESTDIR)/etc/yum.conf.d
	touch $(DESTDIR)/etc/yum.conf.d/qubes-proxy.conf

	install -D -m 0644 misc/grub.qubes $(DESTDIR)/etc/default/grub.qubes
	install -D -m 0644 misc/serial.conf $(DESTDIR)/usr/share/qubes/serial.conf
	install -D misc/qubes-serial-login $(DESTDIR)/$(SBINDIR)/qubes-serial-login
	install -D -m 0644 misc/dracut-qubes.conf \
		$(DESTDIR)/usr/lib/dracut/dracut.conf.d/30-qubes.conf
ifeq ($(shell rpm --eval %{centos_ver}),7)
	install -D -m 0644 misc/yum-qubes-hooks.py $(DESTDIR)$(LIBDIR)/yum-plugins/
	install -D -m 0644 misc/yum-qubes-hooks.conf $(DESTDIR)/etc/yum/pluginconf.d/yum-qubes-hooks.conf
endif
	install -D -m 0644 misc/dnf-qubes-hooks.py \
		$(DESTDIR)$(PYTHON2_SITELIB)/dnf-plugins/qubes-hooks.py
ifeq ($(shell rpm --eval %{centos_ver}),8)
# we need to stick to related DNF python version
# which is given by plateform-python
	install -D -m 0644 misc/dnf-qubes-hooks.py \
		$(DESTDIR)$(PLATFORM_PYTHON3_SITELIB)/dnf-plugins/qubes-hooks.py
else
	install -D -m 0644 misc/dnf-qubes-hooks.py \
		$(DESTDIR)$(PYTHON3_SITELIB)/dnf-plugins/qubes-hooks.py
endif
	install -D -m 0644 misc/dnf-qubes-hooks.conf $(DESTDIR)/etc/dnf/plugins/qubes-hooks.conf

install-doc:
	$(MAKE) -C doc install

install-common: install-doc
	$(MAKE) -C autostart-dropins install
	install -m 0644 -D misc/fstab $(DESTDIR)/etc/fstab

	# force /usr/bin before /bin to have /usr/bin/python instead of /bin/python
	PATH="/usr/bin:$(PATH)" $(PYTHON) setup.py install $(PYTHON_PREFIX_ARG) -O1 --root $(DESTDIR)
	mkdir -p $(DESTDIR)$(SBINDIR)

	install -d -m 0750 $(DESTDIR)/etc/sudoers.d/
	if [ -f /etc/redhat-release ] || [ -f /etc/debian_version ]; then \
		exec install -D -m 0440 misc/qubes.sudoers $(DESTDIR)/etc/sudoers.d/qubes; \
	else \
		sed -E '/^[^#]/s/\<(ROLE|TYPE)=[A-Za-z0-9_]+[[:space:]]+//g' misc/qubes.sudoers | \
		install -D -m 0440 /dev/stdin $(DESTDIR)/etc/sudoers.d/qubes; \
	fi
	install -D -m 0440 misc/sudoers.d_qt_x11_no_mitshm $(DESTDIR)/etc/sudoers.d/qt_x11_no_mitshm
	install -D -m 0644 misc/20_tcp_timestamps.conf $(DESTDIR)/etc/sysctl.d/20_tcp_timestamps.conf

	install -d $(DESTDIR)/var/lib/qubes

	install -D misc/xenstore-watch $(DESTDIR)$(BINDIR)/xenstore-watch-qubes
	install -d $(DESTDIR)/etc/udev/rules.d
	install -m 0644 misc/udev-qubes-misc.rules $(DESTDIR)/etc/udev/rules.d/50-qubes-misc.rules
	install -d $(DESTDIR)$(LIBDIR)/qubes/
	install misc/qubes-trigger-sync-appmenus.sh $(DESTDIR)$(LIBDIR)/qubes/
	install -d -m 0750 $(DESTDIR)/etc/polkit-1/rules.d
	install -D -m 0644 misc/polkit-1-qubes-allow-all.pkla $(DESTDIR)/etc/polkit-1/localauthority/50-local.d/qubes-allow-all.pkla
	install -D -m 0644 misc/polkit-1-qubes-allow-all.rules $(DESTDIR)/etc/polkit-1/rules.d/00-qubes-allow-all.rules
	install -D -m 0644 misc/mime-globs $(DESTDIR)/usr/share/qubes/mime-override/globs
	install misc/qubes-download-dom0-updates.sh $(DESTDIR)$(LIBDIR)/qubes/
	install -d $(DESTDIR)/usr/share/glib-2.0/schemas/
	install -m 0644 \
		misc/20_org.gnome.settings-daemon.plugins.updates.qubes.gschema.override \
		misc/20_org.gnome.nautilus.qubes.gschema.override \
		misc/20_org.mate.NotificationDaemon.qubes.gschema.override \
		misc/20_org.gnome.desktop.wm.preferences.qubes.gschema.override \
		$(DESTDIR)/usr/share/glib-2.0/schemas/
	install -m 2775 -d $(DESTDIR)/var/lib/qubes/dom0-updates
	install -D -m 0644 misc/qubes-master-key.asc $(DESTDIR)/usr/share/qubes/qubes-master-key.asc
	install misc/resize-rootfs $(DESTDIR)$(LIBDIR)/qubes/

	install misc/close-window $(DESTDIR)$(LIBDIR)/qubes/close-window

	install misc/upgrades-installed-check $(DESTDIR)$(LIBDIR)/qubes/upgrades-installed-check
	install misc/upgrades-status-notify $(DESTDIR)$(LIBDIR)/qubes/upgrades-status-notify

	install -m 0644 network/udev-qubes-network.rules $(DESTDIR)/etc/udev/rules.d/99-qubes-network.rules
	install -m 0755 network/update-proxy-configs $(DESTDIR)$(LIBDIR)/qubes/

	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 misc/qubes-session-autostart $(DESTDIR)$(BINDIR)/qubes-session-autostart
	install -m 0755 misc/qvm-features-request $(DESTDIR)$(BINDIR)/qvm-features-request
	install -m 0755 misc/qubes-run-terminal $(DESTDIR)/$(BINDIR)
	install -D -m 0644 misc/qubes-run-terminal.desktop $(DESTDIR)/$(APPLICATIONSDIR)/qubes-run-terminal.desktop
	install -m 0755 qubes-rpc/qvm-sync-clock $(DESTDIR)$(BINDIR)/qvm-sync-clock
	install qubes-rpc/{qvm-open-in-dvm,qvm-open-in-vm,qvm-copy,qvm-run-vm} $(DESTDIR)/usr/bin
	ln -s qvm-copy $(DESTDIR)/usr/bin/qvm-move-to-vm
	ln -s qvm-copy $(DESTDIR)/usr/bin/qvm-move
	ln -s qvm-copy $(DESTDIR)/usr/bin/qvm-copy-to-vm
	install qubes-rpc/qvm-copy-to-vm.gnome $(DESTDIR)$(LIBDIR)/qubes
	ln -s qvm-copy-to-vm.gnome $(DESTDIR)$(LIBDIR)/qubes/qvm-move-to-vm.gnome
	ln -s qvm-copy-to-vm.gnome $(DESTDIR)$(LIBDIR)/qubes/qvm-copy-to-vm.kde
	ln -s qvm-copy-to-vm.gnome $(DESTDIR)$(LIBDIR)/qubes/qvm-move-to-vm.kde
	install qubes-rpc/qvm-actions.sh $(DESTDIR)$(LIBDIR)/qubes
	install -m 0644 misc/uca_qubes.xml $(DESTDIR)$(LIBDIR)/qubes
	mkdir -p $(DESTDIR)/etc/xdg/xfce4/xfconf/xfce-perchannel-xml
	install -m 0644 misc/thunar.xml $(DESTDIR)/etc/xdg/xfce4/xfconf/xfce-perchannel-xml
	install qubes-rpc/xdg-icon $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/{vm-file-editor,qfile-agent,qopen-in-vm} $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/qubes-open $(DESTDIR)$(BINDIR)
	install qubes-rpc/tar2qfile $(DESTDIR)$(LIBDIR)/qubes
	# Install qfile-unpacker as SUID - because it will fail to receive files from other vm
	install -m 4755  qubes-rpc/qfile-unpacker $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/qrun-in-vm $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/prepare-suspend $(DESTDIR)$(LIBDIR)/qubes
	install qubes-rpc/qubes-sync-clock $(DESTDIR)$(LIBDIR)/qubes
	install -m 0644 misc/qubes-suspend-module-blacklist $(DESTDIR)/etc/qubes-suspend-module-blacklist
	install -d $(DESTDIR)/$(KDESERVICEDIR)
	install -m 0644 qubes-rpc/{qvm-copy.desktop,qvm-move.desktop,qvm-dvm.desktop} $(DESTDIR)/$(KDESERVICEDIR)
	install -d $(DESTDIR)/$(KDE5SERVICEDIR)
	install -m 0644 qubes-rpc/{qvm-copy.desktop,qvm-move.desktop,qvm-dvm.desktop} $(DESTDIR)/$(KDE5SERVICEDIR)
	install -d $(DESTDIR)/etc/qubes-rpc
	install -m 0755 qubes-rpc/{qubes.Filecopy,qubes.OpenInVM,qubes.VMShell} $(DESTDIR)/etc/qubes-rpc
	install -m 0755 qubes-rpc/qubes.VMRootShell $(DESTDIR)/etc/qubes-rpc
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
	install -m 0755 qubes-rpc/qubes.ResizeDisk $(DESTDIR)/etc/qubes-rpc
	install -m 0755 qubes-rpc/qubes.StartApp $(DESTDIR)/etc/qubes-rpc
	install -m 0755 qubes-rpc/qubes.PostInstall $(DESTDIR)/etc/qubes-rpc
	install -m 0755 qubes-rpc/qubes.GetDate $(DESTDIR)/etc/qubes-rpc
	install -m 0755 qubes-rpc/qubes.ShowInTerminal $(DESTDIR)/etc/qubes-rpc
	install -m 0755 qubes-rpc/qubes.ConnectTCP $(DESTDIR)/etc/qubes-rpc
	install -d $(DESTDIR)/etc/qubes/rpc-config
	install -m 0644 qubes-rpc/rpc-config.README $(DESTDIR)/etc/qubes/rpc-config/README
	for config in qubes-rpc/*.config; do \
		install -m 0644 $$config $(DESTDIR)/etc/qubes/rpc-config/`basename $$config .config`; \
	done

	install -d $(DESTDIR)/etc/qubes/suspend-pre.d
	install -m 0644 qubes-rpc/suspend-pre.README $(DESTDIR)/etc/qubes/suspend-pre.d/README
	install -d $(DESTDIR)/etc/qubes/suspend-post.d
	install -m 0644 qubes-rpc/suspend-post.README $(DESTDIR)/etc/qubes/suspend-post.d/README
	install -m 0755 qubes-rpc/suspend-post-qvm-sync-clock.sh \
		$(DESTDIR)/etc/qubes/suspend-post.d/qvm-sync-clock.sh
	install -d $(DESTDIR)/etc/qubes/post-install.d
	install -m 0644 post-install.d/README $(DESTDIR)/etc/qubes/post-install.d/
	install -m 0755 post-install.d/*.sh $(DESTDIR)/etc/qubes/post-install.d/
	install -d $(DESTDIR)/usr/share/nautilus-python/extensions
	install -m 0644 qubes-rpc/*_nautilus.py $(DESTDIR)/usr/share/nautilus-python/extensions

	install -D -m 0644 misc/dconf-db-local-dpi $(DESTDIR)/etc/dconf/db/local.d/dpi

	install -D -m 0755 misc/qubes-desktop-run $(DESTDIR)$(BINDIR)/qubes-desktop-run

	install -d $(DESTDIR)/mnt/removable

	install -d $(DESTDIR)/usr/lib/qubes-bind-dirs.d
	install -D -m 0644 misc/30_cron.conf $(DESTDIR)/usr/lib/qubes-bind-dirs.d/30_cron.conf

	install -D -m 0644 misc/marker-vm $(DESTDIR)/usr/share/qubes/marker-vm
	cut -f 1,2 -d . version >> $(DESTDIR)/usr/share/qubes/marker-vm
	
	install -m 0755 misc/tinyproxy-wrapper $(DESTDIR)/usr/lib/qubes/tinyproxy-wrapper

	install -m 0755 misc/qvm-console $(DESTDIR)$(BINDIR)/qvm-console
	install -m 0755 misc/qvm-connect-tcp $(DESTDIR)$(BINDIR)/qvm-connect-tcp

	install -d $(DESTDIR)/var/run/qubes
	install -d $(DESTDIR)/rw

# Networking install target includes:
# * basic network functionality (setting IP address, DNS, default gateway)
# * package update proxy client
install-networking:
	install -d $(DESTDIR)$(SYSLIBDIR)/systemd/system
	install -m 0644 vm-systemd/qubes-*.socket $(DESTDIR)$(SYSLIBDIR)/systemd/system/

	install -d $(DESTDIR)$(LIBDIR)/qubes/
	install network/setup-ip $(DESTDIR)$(LIBDIR)/qubes/

# Netvm install target includes:
# * qubes-firewall service (FirewallVM)
# * DNS redirection setup
# * proxy service used by TemplateVMs to download updates
install-netvm:
	install -D -m 0644 $(SYSTEMD_NETWORK_SERVICES) $(DESTDIR)$(SYSLIBDIR)/systemd/system/

	install -D -m 0755 network/qubes-iptables $(DESTDIR)$(LIBDIR)/qubes/init/qubes-iptables

	install -D -m 0644 vm-systemd/qubes-core-agent-linux.tmpfiles \
		$(DESTDIR)/usr/lib/tmpfiles.d/qubes-core-agent-linux.conf

	mkdir -p $(DESTDIR)$(SBINDIR)

ifneq ($(SBINDIR),/usr/bin)
	mv $(DESTDIR)/usr/bin/qubes-firewall $(DESTDIR)$(SBINDIR)/qubes-firewall
endif

	install -D network/qubes-setup-dnat-to-ns $(DESTDIR)$(LIBDIR)/qubes/qubes-setup-dnat-to-ns

	install -d $(DESTDIR)/etc/dhclient.d
	ln -s /usr/lib/qubes/qubes-setup-dnat-to-ns $(DESTDIR)/etc/dhclient.d/qubes-setup-dnat-to-ns.sh

	install -D network/vif-route-qubes $(DESTDIR)/etc/xen/scripts/vif-route-qubes
	install -D network/vif-qubes-nat.sh $(DESTDIR)/etc/xen/scripts/vif-qubes-nat.sh
	install -m 0644 -D network/tinyproxy-updates.conf $(DESTDIR)/etc/tinyproxy/tinyproxy-updates.conf
	install -m 0644 -D network/updates-blacklist $(DESTDIR)/etc/tinyproxy/updates-blacklist
	install -m 0755 -D network/iptables-updates-proxy $(DESTDIR)$(LIBDIR)/qubes/iptables-updates-proxy

	install -m 0400 -D network/iptables $(DESTDIR)/etc/qubes/iptables.rules
	install -m 0400 -D network/ip6tables $(DESTDIR)/etc/qubes/ip6tables.rules
	install -m 0400 -D network/ip6tables-enabled $(DESTDIR)/etc/qubes/ip6tables-enabled.rules

	install -m 0755 -D qubes-rpc/qubes.UpdatesProxy $(DESTDIR)/etc/qubes-rpc/qubes.UpdatesProxy

# networkmanager install target allow integration of NetworkManager for Qubes VM:
# * make connections config persistent
# * adjust DNS redirections when needed
# * show/hide NetworkManager applet icon
install-networkmanager:
	install -d $(DESTDIR)$(LIBDIR)/qubes/
	install network/qubes-fix-nm-conf.sh $(DESTDIR)$(LIBDIR)/qubes/
	install network/network-manager-prepare-conf-dir $(DESTDIR)$(LIBDIR)/qubes/

	install -d $(DESTDIR)/etc/NetworkManager/dispatcher.d/
	install network/{qubes-nmhook,30-qubes-external-ip} $(DESTDIR)/etc/NetworkManager/dispatcher.d/

	install -d $(DESTDIR)/usr/lib/NetworkManager/conf.d
	install -m 0644 network/nm-30-qubes.conf $(DESTDIR)/usr/lib/NetworkManager/conf.d/30-qubes.conf

	install -d $(DESTDIR)/etc/xdg/autostart
	install -m 0755 network/show-hide-nm-applet.sh $(DESTDIR)$(LIBDIR)/qubes/
	install -m 0644 network/show-hide-nm-applet.desktop $(DESTDIR)/etc/xdg/autostart/00-qubes-show-hide-nm-applet.desktop

install-deb: install-common install-systemd install-systemd-dropins install-systemd-networking-dropins install-networking install-networkmanager install-netvm
	mkdir -p $(DESTDIR)/etc/apt/sources.list.d
	sed -e "s/@DIST@/`lsb_release -cs`/" misc/qubes-r4.list.in \
		> $(DESTDIR)/etc/apt/sources.list.d/qubes-r4.list
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
	install -D -m 0644 misc/grub.qubes $(DESTDIR)/etc/default/grub.d/30-qubes.cfg
	install -D -m 0644 misc/apt-conf-70no-unattended $(DESTDIR)/etc/apt/apt.conf.d/70no-unattended
	install -D -m 0644 misc/apt-conf-10no-cache $(DESTDIR)/etc/apt/apt.conf.d/10no-cache

install-corevm: install-rh install-common install-systemd install-sysvinit install-systemd-dropins install-networking

install-netvm: install-systemd-networking-dropins install-networkmanager

install-vm: install-corevm install-netvm
