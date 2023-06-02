CAJAPYEXTDIR ?= /usr/share/caja-python/extensions
QUBESLIBDIR ?= /usr/lib/qubes

.PHONY: install

install:
	install -d $(DESTDIR)$(CAJAPYEXTDIR)
	install -t $(DESTDIR)$(CAJAPYEXTDIR) -m 0644 *.py
