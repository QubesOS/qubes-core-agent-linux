BINDIR ?= /usr/bin
LIBDIR ?= /usr/lib
QUBESLIBDIR = $(LIBDIR)/qubes
UDEVRULESDIR = $(LIBDIR)/udev/rules.d

.PHONY: install

install:
	install -D -m 0644 udev-qubes-network.rules $(DESTDIR)$(UDEVRULESDIR)/99-qubes-network.rules
	install -d $(DESTDIR)$(QUBESLIBDIR)
	install -t $(DESTDIR)$(QUBESLIBDIR) \
		setup-ip \
		update-proxy-configs
	install -d $(DESTDIR)$(BINDIR)
	install -t $(DESTDIR)$(BINDIR) \
		qvm-connect-tcp
