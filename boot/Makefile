LIBDIR ?= /usr/lib
SYSCONFDIR ?= /etc
GRUBCONFDIR ?= $(SYSCONFDIR)/default
GRUBCFGNAME ?= grub.qubes
DRACUTDIR ?= $(LIBDIR)/dracut
DRACUTCONFDIR ?= $(DRACUTDIR)/dracut.conf.d
DRACUTMODDIR ?= $(DRACUTDIR)/modules.d

.PHONY: install

install:
	install -D -m 0644 grub.qubes $(DESTDIR)$(GRUBCONFDIR)/$(GRUBCFGNAME)
	install -D -m 0644 dracut-qubes.conf $(DESTDIR)$(DRACUTCONFDIR)/30-qubes.conf
	install -D -m 0755 module-setup.sh $(DESTDIR)$(DRACUTMODDIR)/99qubes/module-setup.sh
