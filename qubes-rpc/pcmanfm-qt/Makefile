LIBDIR ?= /usr/lib
DATADIR ?= /usr/share

.PHONY: install

install:
	install -d $(DESTDIR)$(DATADIR)
	install -d $(DESTDIR)/etc/xdg/pcmanfm-qt/default
	install -D -m644 -t $(DESTDIR)$(DATADIR)/file-manager/actions/ qvm-copy-pcmanfm-qt.desktop
	install -D -m644 -t $(DESTDIR)$(DATADIR)/file-manager/actions/ qvm-edit-dvm-pcmanfm-qt.desktop
	install -D -m644 -t $(DESTDIR)$(DATADIR)/file-manager/actions/ qvm-move-pcmanfm-qt.desktop
	install -D -m644 -t $(DESTDIR)$(DATADIR)/file-manager/actions/ qvm-open-pcmanfm-qt.desktop
	install -D -m644 -t $(DESTDIR)$(DATADIR)/file-manager/actions/ qvm-open-dvm-pcmanfm-qt.desktop
	install -D -m644 -t $(DESTDIR)/etc/xdg/pcmanfm-qt/default/ settings.conf
