NAUTILUSPYEXTDIR ?= /usr/share/nautilus-python/extensions
QUBESLIBDIR ?= /usr/lib/qubes

.PHONY: install

install:
	install -d $(DESTDIR)$(NAUTILUSPYEXTDIR)
	install -t $(DESTDIR)$(NAUTILUSPYEXTDIR) -m 0644 *.py
	install -d $(DESTDIR)$(QUBESLIBDIR)
	install -t $(DESTDIR)$(QUBESLIBDIR) -m 0755 *.sh
