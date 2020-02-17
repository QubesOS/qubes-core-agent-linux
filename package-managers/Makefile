LIBDIR ?= /usr/lib
STATEDIR ?= /var/lib
SYSCONFDIR ?= /etc
PYTHON2_SITELIB = $(shell python2 -c 'import distutils.sysconfig; print distutils.sysconfig.get_python_lib()')
PYTHON3_SITELIB = $(shell python3 -c 'import distutils.sysconfig; print(distutils.sysconfig.get_python_lib())')
APTCONFDIR = $(SYSCONFDIR)/apt
YUMCONFDIR = $(SYSCONFDIR)/yum.conf.d
QUBESLIBDIR = $(LIBDIR)/qubes
QUBESSTATEDIR = $(STATEDIR)/qubes

DIST ?= fc18

.PHONY: install install-apt install-dnf install-rpm install-yum

install:
	install -d $(DESTDIR)$(QUBESLIBDIR)
	install -t $(DESTDIR)$(QUBESLIBDIR) \
		qubes-download-dom0-updates.sh \
		upgrades-installed-check \
		upgrades-status-notify
	install -d -m 2775 $(DESTDIR)$(QUBESSTATEDIR)/dom0-updates

install-apt:
	install -d $(DESTDIR)$(APTCONFDIR)/sources.list.d
	sed -e "s/@DIST@/`lsb_release -cs`/" apt-qubes-r4.list.in \
		> $(DESTDIR)$(APTCONFDIR)/sources.list.d/qubes-r4.list
	install -D -m 0644 apt-qubes-archive-keyring.gpg \
		$(DESTDIR)$(APTCONFDIR)/trusted.gpg.d/qubes-archive-keyring.gpg
	install -D -m 0644 apt-conf-00notify-hook \
		$(DESTDIR)$(APTCONFDIR)/apt.conf.d/00notify-hook
	install -D -m 0644 apt-conf-70no-unattended \
		$(DESTDIR)$(APTCONFDIR)/apt.conf.d/70no-unattended
	install -D -m 0644 apt-conf-10no-cache \
		$(DESTDIR)$(APTCONFDIR)/apt.conf.d/10no-cache

install-dnf: install-rpm
	install -D -m 0644 dnf-qubes-hooks.py \
		$(DESTDIR)$(PYTHON2_SITELIB)/dnf-plugins/qubes-hooks.py
	install -D -m 0644 dnf-qubes-hooks.py \
		$(DESTDIR)$(PYTHON3_SITELIB)/dnf-plugins/qubes-hooks.py
	install -D -m 0644 dnf-qubes-hooks.conf $(DESTDIR)$(SYSCONFDIR)/dnf/plugins/qubes-hooks.conf

install-yum: install-rpm
	install -d $(DESTDIR)$(LIBDIR)/yum-plugins
	install -D -m 0644 yum-qubes-hooks.py \
		$(DESTDIR)$(LIBDIR)/yum-plugins/yum-qubes-hooks.py
	install -D -m 0644 yum-qubes-hooks.conf \
		$(DESTDIR)$(SYSCONFDIR)/yum/pluginconf.d/yum-qubes-hooks.conf

install-rpm:
	install -d $(DESTDIR)$(SYSCONFDIR)/yum.repos.d
	DIST='$(DIST)'; sed -e "s/@DIST@/$${DIST%%[0-9]*}/g" yum-qubes-r4.repo.in \
		> $(DESTDIR)$(SYSCONFDIR)/yum.repos.d/qubes-r4.repo
	install -d $(DESTDIR)$(SYSCONFDIR)/pki/rpm-gpg
	install -t $(DESTDIR)$(SYSCONFDIR)/pki/rpm-gpg -m 0644 RPM-GPG-KEY-qubes*
	install -d $(DESTDIR)$(YUMCONFDIR)
	> $(DESTDIR)$(YUMCONFDIR)/qubes-proxy.conf
