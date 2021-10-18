BINDIR ?= /usr/bin
DATADIR ?= /usr/share
SYSLIBDIR ?= /lib
UDEVRULESDIR := $(SYSLIBDIR)/udev/rules.d
QUBESDATADIR := $(DATADIR)/qubes
QUBESMIMEDIR := $(QUBESDATADIR)/xdg-override

.PHONY: all clean install

all: marker-vm
	umask 022 && export XDG_DATA_HOME=. && \
	update-desktop-database applications && \
	update-mime-database mime && \
	$(RM) mime/icons && \
	sed '1s/^\[MIME Cache]$$/[Default Applications]/;s/;$$//' \
		applications/mimeinfo.cache > applications/mimeapps.list && \
	cp applications/mimeapps.list applications/defaults.list

clean:
	-$(RM) marker-vm

install:
	install -m 0755 -d $(DESTDIR)$(UDEVRULESDIR)
	install -t $(DESTDIR)$(UDEVRULESDIR) -m 0644 50-qubes-mem-hotplug.rules
	install -m 0755 -d $(DESTDIR)$(QUBESMIMEDIR)
	install -D -t $(DESTDIR)$(QUBESDATADIR) -m 0644 \
	    marker-vm \
	    qubes-master-key.asc
	install -D -m 0644 mime-globs $(DESTDIR)$(QUBESDATADIR)/mime-override/globs
	for i in X11 aclocal appdata augeas backgrounds bash-completion desktop-directories dict doc empty games gnome help icons idl info licenses locale man metainfo mime-info misc omf pixmaps sounds themes wayland-sessions xsessions; do \
		ln -sf "../../$$i" $(DESTDIR)$(QUBESMIMEDIR)/"$$i"; \
	done
	$(RM) mime/icons
	umask 022 && cp -r applications mime '$(DESTDIR)$(QUBESMIMEDIR)'
	install -m 0755 -d $(DESTDIR)$(BINDIR)
	install -m 0755 -t $(DESTDIR)$(BINDIR) qvm-features-request

marker-vm: marker-vm.in
	printf "$(VERSION)" | cut -f 1,2 -d . | cat $< - > marker-vm
