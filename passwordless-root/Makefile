SYSCONFDIR ?= /etc
SUDOERSDIR = $(SYSCONFDIR)/sudoers.d
POLKIT1DIR = $(SYSCONFDIR)/polkit-1
PAMDIR = $(SYSCONFDIR)/pam.d
PAMCONFIGSDIR = /usr/share/pam-configs/

.PHONY: install install-debian install-rh

install:
	install -d -m 0750 $(DESTDIR)$(SUDOERSDIR)
	if [ -f /etc/redhat-release ] || [ -f /etc/debian_version ]; then \
		exec install -D -m 0440 qubes.sudoers $(DESTDIR)$(SUDOERSDIR)/qubes; \
	else \
		sed -E '/^[^#]/s/\<(ROLE|TYPE)=[A-Za-z0-9_]+[[:space:]]+//g' qubes.sudoers | \
		install -D -m 0440 /dev/stdin $(DESTDIR)$(SUDOERSDIR)/qubes; \
	fi
	install -d -m 0750 $(DESTDIR)$(POLKIT1DIR)/rules.d
	install -D -m 0644 polkit-1-qubes-allow-all.rules $(DESTDIR)$(POLKIT1DIR)/rules.d/00-qubes-allow-all.rules

install-rh:
	install -D -m 0644 pam.d_su.qubes $(DESTDIR)$(PAMDIR)/su.qubes

install-debian:
	install -D -m 0644 pam-configs_su.qubes $(DESTDIR)$(PAMCONFIGSDIR)/su.qubes
