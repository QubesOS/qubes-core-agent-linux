LIBDIR ?= /usr/lib
SYSTEM_DROPIN_DIR ?= /lib/systemd/system
SYSCONFDIR ?= /etc
GRUBCONFDIR ?= $(SYSCONFDIR)/default
DRACUTCONFDIR ?= $(LIBDIR)/dracut/dracut.conf.d
GRUBCFGNAME ?= grub.qubes

.PHONY: install

install:
	install -D -m 0644 session-stop-timeout.conf \
		$(DESTDIR)$(SYSTEM_DROPIN_DIR)/user@.service.d/90-session-stop-timeout.conf
	install -D -m 0644 grub.qubes $(DESTDIR)$(GRUBCONFDIR)/$(GRUBCFGNAME)
	install -D -m 0644 dracut-qubes.conf $(DESTDIR)$(DRACUTCONFDIR)/30-qubes.conf
