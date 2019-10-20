BINDIR ?= /usr/bin
SYSCONFDIR ?= /etc
UDEVRULESDIR = $(SYSCONFDIR)/udev/rules.d
QUBESDATADIR = /usr/share/qubes

.PHONY: all clean install

all: marker-vm

clean:
	-$(RM) marker-vm

install:
	install -d $(DESTDIR)$(UDEVRULESDIR)
	install -t $(DESTDIR)$(UDEVRULESDIR) -m 0644 50-qubes-mem-hotplug.rules
	install -d $(DESTDIR)$(QUBESDATADIR)
	install -D -t $(DESTDIR)$(QUBESDATADIR) -m 0644 \
	    marker-vm \
	    qubes-master-key.asc
	install -D -m 0644 mime-globs $(DESTDIR)$(QUBESDATADIR)/mime-override/globs
	install -d $(DESTDIR)$(BINDIR)
	install -t $(DESTDIR)$(BINDIR) qvm-features-request

marker-vm: marker-vm.in
	printf "$(VERSION)" | cut -f 1,2 -d . | cat $< - > marker-vm
