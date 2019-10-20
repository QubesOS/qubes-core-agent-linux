SYSCONFDIR ?= /etc
SUDOERSDIR = $(SYSCONFDIR)/sudoers.d
POLKIT1DIR = $(SYSCONFDIR)/polkit-1

.PHONY: install

install:
	install -d -m 0750 $(DESTDIR)$(SUDOERSDIR)
	install -D -m 0440 qubes.sudoers $(DESTDIR)$(SUDOERSDIR)/qubes
	install -D -m 0644 polkit-1-qubes-allow-all.pkla $(DESTDIR)$(POLKIT1DIR)/localauthority/50-local.d/qubes-allow-all.pkla
	install -d -m 0750 $(DESTDIR)$(POLKIT1DIR)/rules.d
	install -D -m 0644 polkit-1-qubes-allow-all.rules $(DESTDIR)$(POLKIT1DIR)/rules.d/00-qubes-allow-all.rules
