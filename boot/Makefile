LIBDIR ?= /usr/lib
SYSCONFDIR ?= /etc
GRUBCONFDIR ?= $(SYSCONFDIR)/default
DRACUTCONFDIR ?= $(LIBDIR)/dracut/dracut.conf.d
GRUBCFGNAME ?= grub.qubes

.PHONY: install

install:
	install -D -m 0644 grub.qubes $(DESTDIR)$(GRUBCONFDIR)/$(GRUBCFGNAME)
	install -D -m 0644 dracut-qubes.conf $(DESTDIR)$(DRACUTCONFDIR)/30-qubes.conf
