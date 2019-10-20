LIBDIR ?= /usr/lib
SYSCONFDIR ?= /etc
GRUBCONFDIR ?= $(SYSCONFDIR)/grub.d
DRACUTCONFDIR ?= $(LIBDIR)/dracut/dracut.conf.d

.PHONY: install

install:
	install -D -m 0644 grub.qubes $(DESTDIR)$(GRUBCONFDIR)/30_qubes
	install -D -m 0644 dracut-qubes.conf $(DESTDIR)$(DRACUTCONFDIR)/30-qubes.conf
