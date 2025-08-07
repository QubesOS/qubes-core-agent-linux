DATADIR ?= /usr/share
LIBDIR ?= /usr/lib
BINDIR ?= /usr/bin
SYSCONFDIR ?= /etc
QUBESDATADIR = $(DATADIR)/qubes

.PHONY: install

install:
	install -D -m 0644 session-stop-timeout.conf \
		$(DESTDIR)$(LIBDIR)/systemd/system/user@.service.d/90-session-stop-timeout.conf
	install -D -m 0644 serial.conf $(DESTDIR)$(QUBESDATADIR)/serial.conf
	install -D qubes-serial-login $(DESTDIR)$(BINDIR)/qubes-serial-login
