KDESERVICEDIR ?= /usr/share/kde4/services
KDE5SERVICEDIR ?= /usr/share/kservices5/ServiceMenus

.PHONY: install install-kde4 install-kde5

install-kde4:
	install -d $(DESTDIR)$(KDESERVICEDIR)
	install -t $(DESTDIR)$(KDESERVICEDIR) -m 0644 *.desktop

install-kde5:
	install -d $(DESTDIR)$(KDE5SERVICEDIR)
	install -t $(DESTDIR)$(KDE5SERVICEDIR) -m 0644 *.desktop

install: install-kde4 install-kde5
