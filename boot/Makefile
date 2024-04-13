LIBDIR ?= /usr/lib
SYSCONFDIR ?= /etc
GRUBCONFDIR ?= $(SYSCONFDIR)/grub.d
DRACUTDIR ?= $(LIBDIR)/dracut
DRACUTCONFDIR ?= $(DRACUTDIR)/dracut.conf.d
DRACUTMODDIR ?= $(DRACUTDIR)/modules.d

.PHONY: install

install:
	install -D -m 0644 grub.qubes $(DESTDIR)$(GRUBCONFDIR)/30_qubes
	install -D -m 0644 dracut-qubes.conf $(DESTDIR)$(DRACUTCONFDIR)/30-qubes.conf
	install -D -m 0755 modules-setup.sh $(DESTDIR)$(DRACUTMODDIR)/99qubes/module-setup.sh
