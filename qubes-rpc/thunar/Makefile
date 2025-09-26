SYSCONFDIR ?= /etc
LIBDIR ?= /usr/lib
QUBESLIBDIR = $(LIBDIR)/qubes

.PHONY: install

install:
	install -d $(DESTDIR)$(QUBESLIBDIR)
	install -D -t $(DESTDIR)$(QUBESLIBDIR) -m 0644 uca_qubes.xml
	install -d $(DESTDIR)$(SYSCONFDIR)/xdg/xfce4/xfconf/xfce-perchannel-xml
	install -D -t $(DESTDIR)$(SYSCONFDIR)/xdg/xfce4/xfconf/xfce-perchannel-xml -m 0644 thunar.xml
