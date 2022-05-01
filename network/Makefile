BINDIR ?= /usr/bin
LIBDIR ?= /usr/lib
SYSCONFDIR ?= /etc
QUBESLIBDIR = $(LIBDIR)/qubes
UDEVRULESDIR = $(SYSCONFDIR)/udev/rules.d

.PHONY: install

install:
	install -D -m 0644 udev-qubes-network.rules $(DESTDIR)$(UDEVRULESDIR)/99-qubes-network.rules
	install -d $(DESTDIR)$(QUBESLIBDIR)
	install -t $(DESTDIR)$(QUBESLIBDIR) \
		setup-ip \
		tinyproxy-wrapper \
		get-dns-from-resolved \
		update-proxy-configs
	install -d $(DESTDIR)$(BINDIR)
	install -t $(DESTDIR)$(BINDIR) \
		qvm-connect-tcp
