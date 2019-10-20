SYSCONFDIR ?= /etc
PAMDIR ?= $(SYSCONFDIR)/pam.d

.PHONY: install

install:
	install -D -m 0644 pam.d_su.qubes $(DESTDIR)$(PAMDIR)/su.qubes
