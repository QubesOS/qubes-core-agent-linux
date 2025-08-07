
DROPINS_DIR = /etc/qubes/autostart

dist := $(shell grep ^ID= /etc/os-release | cut -d = -f 2)
dist_codename := $(shell grep ^VERSION_CODENAME= /etc/os-release | cut -d = -f 2)

install:
	for f in *.desktop; do install -m 0644 -D $$f $(DESTDIR)$(DROPINS_DIR)/$$f.d/30_qubes.conf; done
	install -m 0644 README.txt $(DESTDIR)$(DROPINS_DIR)/
	if [ "$(dist)" = "fedora" ] || ( [ "$(dist)" = "debian" ] && [ "$(dist_codename)" != "bookworm" ] ); then \
		rm -rf $(DESTDIR)$(DROPINS_DIR)/xfce4-notifyd.desktop.d; \
	fi
