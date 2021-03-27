VERSION := $(shell cat version)

LIBDIR ?= /usr/lib
SYSLIBDIR ?= /lib

PYTHON ?= /usr/bin/python3

# This makefile uses some bash-isms, make uses /bin/sh by default.
SHELL = /bin/bash

clean:
	make -C misc clean
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
	$(MAKE) -C misc VERSION=$(VERSION)
	$(MAKE) -C qubes-rpc

# Dropin Directory
SYSTEM_DROPIN_DIR ?= "lib/systemd/system"
USER_DROPIN_DIR ?= "usr/lib/systemd/user"

SYSTEM_DROPINS := boot.automount chronyd.service crond.service
SYSTEM_DROPINS += cups.service cups-browsed.service cups.path cups.socket ModemManager.service
SYSTEM_DROPINS += getty@tty.service serial-getty@.service
SYSTEM_DROPINS += tmp.mount
SYSTEM_DROPINS += org.cups.cupsd.service org.cups.cupsd.path org.cups.cupsd.socket
SYSTEM_DROPINS += systemd-random-seed.service
SYSTEM_DROPINS += tor.service tor@default.service
SYSTEM_DROPINS += systemd-timesyncd.service

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
SYSTEMD_ALL_SERVICES := $(wildcard vm-systemd/qubes-*.service) vm-systemd/dev-xvdc1-swap.service
SYSTEMD_NETWORK_SERVICES := vm-systemd/qubes-firewall.service vm-systemd/qubes-iptables.service vm-systemd/qubes-updates-proxy.service
SYSTEMD_CORE_SERVICES := $(filter-out $(SYSTEMD_NETWORK_SERVICES), $(SYSTEMD_ALL_SERVICES))

install-systemd: install-init
	install -d $(DESTDIR)$(SYSLIBDIR)/systemd/system{,-preset} $(DESTDIR)$(LIBDIR)/qubes/init $(DESTDIR)$(SYSLIBDIR)/modules-load.d $(DESTDIR)/etc/systemd/system
	install -m 0644 $(SYSTEMD_CORE_SERVICES) $(DESTDIR)$(SYSLIBDIR)/systemd/system/
	install -m 0644 vm-systemd/qubes-*.timer $(DESTDIR)$(SYSLIBDIR)/systemd/system/
	install -m 0644 vm-systemd/75-qubes-vm.preset $(DESTDIR)$(SYSLIBDIR)/systemd/system-preset/
	install -m 0644 vm-systemd/qubes-core.conf $(DESTDIR)$(SYSLIBDIR)/modules-load.d/
	install -m 0644 vm-systemd/xendriverdomain.service $(DESTDIR)/etc/systemd/system/

install-sysvinit: install-init
	install -d $(DESTDIR)/etc/init.d
	install vm-init.d/qubes-sysinit $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-core-early $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-core $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-core-netvm $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-firewall $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-updates-proxy $(DESTDIR)/etc/init.d/
	install vm-init.d/qubes-updates-proxy-forwarder $(DESTDIR)/etc/init.d/
	install -D vm-init.d/qubes-core.modules $(DESTDIR)/etc/sysconfig/modules/qubes-core.modules
	install network/qubes-iptables $(DESTDIR)/etc/init.d/

install-rh: install-systemd install-systemd-dropins install-sysvinit

install-doc:
	$(MAKE) -C doc install

install-common: install-doc
	$(MAKE) -C autostart-dropins install
	$(MAKE) -C applications-dropins install

	# force /usr/bin before /bin to have /usr/bin/python instead of /bin/python
	PATH="/usr/bin:$(PATH)" $(PYTHON) setup.py install $(PYTHON_PREFIX_ARG) -O1 --root $(DESTDIR)


# Networking install target includes:
# * basic network functionality (setting IP address, DNS, default gateway)
# * package update proxy client
install-networking:
	install -d $(DESTDIR)$(SYSLIBDIR)/systemd/system
	install -m 0644 vm-systemd/qubes-*.socket $(DESTDIR)$(SYSLIBDIR)/systemd/system/

# Netvm install target includes:
# * qubes-firewall service (FirewallVM)
# * DNS redirection setup
# * proxy service used by TemplateVMs to download updates
install-netvm:
	install -D -m 0644 $(SYSTEMD_NETWORK_SERVICES) $(DESTDIR)$(SYSLIBDIR)/systemd/system/

	install -D -m 0755 network/qubes-iptables $(DESTDIR)$(LIBDIR)/qubes/init/qubes-iptables

	install -D -m 0644 vm-systemd/qubes-core-agent-linux.tmpfiles \
		$(DESTDIR)/usr/lib/tmpfiles.d/qubes-core-agent-linux.conf

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
	install -m 0644 network/nm-31-randomize-mac.conf $(DESTDIR)/usr/lib/NetworkManager/conf.d/31-randomize-mac.conf

	install -d $(DESTDIR)/etc/xdg/autostart
	install -m 0755 network/show-hide-nm-applet.sh $(DESTDIR)$(LIBDIR)/qubes/
	install -m 0644 network/show-hide-nm-applet.desktop $(DESTDIR)/etc/xdg/autostart/00-qubes-show-hide-nm-applet.desktop

install-deb: install-common install-systemd install-systemd-dropins install-systemd-networking-dropins install-networking install-networkmanager install-netvm
	install -d $(DESTDIR)/etc/sysctl.d
	install -m 644 network/80-qubes.conf $(DESTDIR)/etc/sysctl.d/
	install -d $(DESTDIR)/etc/needrestart/conf.d
	install -D -m 0644 misc/50_qubes.conf $(DESTDIR)/etc/needrestart/conf.d/50_qubes.conf

install-corevm: install-rh install-common install-systemd install-sysvinit install-systemd-dropins install-networking

install-netvm: install-systemd-networking-dropins install-networkmanager

install-vm: install-corevm install-netvm
