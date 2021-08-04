APPLICATIONSDIR ?= /usr/share/applications
BINDIR ?= /usr/bin
LIBDIR ?= /usr/lib
QUBESLIBDIR = $(LIBDIR)/qubes

.PHONY: install

install:
	install -d $(DESTDIR)$(QUBESLIBDIR)
	install -t $(DESTDIR)$(QUBESLIBDIR) \
		qubes-trigger-sync-appmenus.sh
	install -d $(DESTDIR)$(BINDIR)
	install -t $(DESTDIR)$(BINDIR) \
		qubes-desktop-run \
		qubes-run-gnome-terminal \
		qubes-run-terminal \
		qubes-session-autostart
	install -d $(DESTDIR)/$(APPLICATIONSDIR)
	install -t $(DESTDIR)/$(APPLICATIONSDIR) -m 0644 qubes-run-terminal.desktop
	install -t $(DESTDIR)/$(APPLICATIONSDIR) -m 0644 qubes-open-file-manager.desktop
	install -t $(DESTDIR)/$(APPLICATIONSDIR) -m 0644 qvm-open-in-dvm.desktop
