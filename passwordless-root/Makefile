SYSCONFDIR ?= /etc
SUDOERSDIR = $(SYSCONFDIR)/sudoers.d
POLKIT1DIR = $(SYSCONFDIR)/polkit-1
PAMDIR = $(SYSCONFDIR)/pam.d
PAMCONFIGSDIR = /usr/share/pam-configs/

.PHONY: install install-debian install-rh

install:
	install -d -m 0750 $(DESTDIR)$(SUDOERSDIR)
	install -D -m 0440 qubes.sudoers $(DESTDIR)$(SUDOERSDIR)/qubes
	install -D -m 0644 polkit-1-qubes-allow-all.pkla $(DESTDIR)$(POLKIT1DIR)/localauthority/50-local.d/qubes-allow-all.pkla
	install -d -m 0750 $(DESTDIR)$(POLKIT1DIR)/rules.d
	install -D -m 0644 polkit-1-qubes-allow-all.rules $(DESTDIR)$(POLKIT1DIR)/rules.d/00-qubes-allow-all.rules

install-rh:
	install -D -m 0644 pam.d_su.qubes $(DESTDIR)$(PAMDIR)/su.qubes

install-debian:
	install -D -m 0644 pam-configs_su.qubes $(DESTDIR)$(PAMCONFIGSDIR)/su.qubes
