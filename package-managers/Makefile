LIBDIR ?= /usr/lib
STATEDIR ?= /var/lib
SYSCONFDIR ?= /etc
PYTHON2_SITELIB = $(shell python2 -c 'import distutils.sysconfig; print distutils.sysconfig.get_python_lib()')
PYTHON3_SITELIB = $(shell $(PYTHON) -c 'import distutils.sysconfig; print(distutils.sysconfig.get_python_lib())')
ifeq ($(shell rpm --eval %{centos_ver} 2>/dev/null),8)
PLATEFORM_PYTHON3_SITELIB = $(shell /usr/libexec/platform-python -c 'import distutils.sysconfig; print(distutils.sysconfig.get_python_lib())')
endif
APTCONFDIR = $(SYSCONFDIR)/apt
YUMCONFDIR = $(SYSCONFDIR)/yum.conf.d
QUBESLIBDIR = $(LIBDIR)/qubes
QUBESSTATEDIR = $(STATEDIR)/qubes

DIST_NAME =
ifneq (,$(wildcard /etc/fedora-release))
DIST = fc$(shell rpm --eval %{fedora})
DIST_NAME = fedora
else ifneq (,$(wildcard /etc/centos-release))
ifeq (CentOSStream, $(shell lsb_release -is))
DIST = centos-stream
DIST_NAME = centos-stream
else
DIST = centos
DIST_NAME = centos
endif
else ifneq (,$(wildcard /etc/os-release))
DIST = $(shell grep VERSION_CODENAME= /etc/os-release | cut -d'=' -f2)
DIST_NAME = $(shell grep ^NAME= /etc/os-release | cut -d'=' -f2)
endif

ifeq (,$(DIST))
# On debian if previous attempt failed
# it means we are on sid
ifneq (,$(wildcard /etc/debian_version))
DIST = $(shell cut -d'/' -f1 /etc/debian_version)
DIST_NAME = debian
endif
endif

DIST ?= fc33

# Ensure to remove quotes
DIST := $(shell echo $(DIST) | tr -d '"')
DIST_NAME := $(shell echo $(DIST_NAME) | tr -d '"')

.PHONY: install install-apt install-dnf install-dnf5 install-rpm install-yum

install:
	install -d $(DESTDIR)$(QUBESLIBDIR)
	install -t $(DESTDIR)$(QUBESLIBDIR) \
		qubes-download-dom0-updates.sh \
		upgrades-installed-check \
		upgrades-status-notify
	install -d -m 2775 $(DESTDIR)$(QUBESSTATEDIR)/dom0-updates
	install -D -m 0644 dnf-plugin-downloadurl.py \
		$(DESTDIR)$(QUBESLIBDIR)/dnf-plugins/downloadurl.py
	install -D -m 0644 gnome-software-fix.conf \
		$(DESTDIR)/usr/lib/environment.d/60-gnome-software-fix.conf

install-apt:
	install -d $(DESTDIR)$(APTCONFDIR)/sources.list.d
ifeq ($(DIST_NAME),Ubuntu)
	sed "s/@DIST@/$(DIST)/" apt-qubes-r4-ubuntu.list.in \
		> $(DESTDIR)$(APTCONFDIR)/sources.list.d/qubes-r4.list
else
	sed "s/@DIST@/$(DIST)/" apt-qubes-r4.list.in \
		> $(DESTDIR)$(APTCONFDIR)/sources.list.d/qubes-r4.list
endif
	install -D -m 0644 apt-qubes-archive-keyring-4.3.gpg \
		$(DESTDIR)/usr/share/keyrings/qubes-archive-keyring-4.3.gpg
	ln -s qubes-archive-keyring-4.3.gpg \
		$(DESTDIR)/usr/share/keyrings/qubes-archive-keyring.gpg
	install -D -m 0644 apt-qubes-ubuntu-archive-keyring-4.3.gpg \
		$(DESTDIR)/usr/share/keyrings/qubes-ubuntu-archive-keyring-4.3.gpg
	ln -s qubes-ubuntu-archive-keyring-4.3.gpg \
		$(DESTDIR)/usr/share/keyrings/qubes-ubuntu-archive-keyring.gpg
	install -D -m 0644 apt-conf-00notify-hook \
		$(DESTDIR)$(APTCONFDIR)/apt.conf.d/00notify-hook
	install -D -m 0644 apt-conf-70no-unattended \
		$(DESTDIR)$(APTCONFDIR)/apt.conf.d/70no-unattended
	install -D -m 0644 apt-conf-10no-cache \
		$(DESTDIR)$(APTCONFDIR)/apt.conf.d/10no-cache
	install -D -m 0644 apt-conf-41error-on-any \
		$(DESTDIR)$(APTCONFDIR)/apt.conf.d/41error-on-any

install-dnf: install-rpm
ifeq ($(shell rpm --eval %{centos_ver} 2>/dev/null),8)
# we need to stick to related DNF python version
# which is given by platform-python
	install -D -m 0644 dnf-qubes-hooks.py \
		$(DESTDIR)$(PLATEFORM_PYTHON3_SITELIB)/dnf-plugins/qubes-hooks.py
else
	install -D -m 0644 dnf-qubes-hooks.py \
		$(DESTDIR)$(PYTHON3_SITELIB)/dnf-plugins/qubes-hooks.py
endif
	install -D -m 0644 dnf-qubes-hooks.conf $(DESTDIR)$(SYSCONFDIR)/dnf/plugins/qubes-hooks.conf

install-dnf5: install-rpm
	install -D -m 0644 qubes-post-update.actions \
		$(DESTDIR)$(SYSCONFDIR)/dnf/libdnf5-plugins/actions.d/qubes-post-update.actions
	install -D -m 0644 dnf-harden.conf \
		$(DESTDIR)$(SYSCONFDIR)/dnf/libdnf5.conf.d/10-qubes.conf

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
