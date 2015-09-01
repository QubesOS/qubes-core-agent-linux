
DROPINS_DIR = /etc/qubes/autostart

install:
	for f in *.desktop; do install -m 0644 -D $$f $(DESTDIR)$(DROPINS_DIR)/$$f.d/30_qubes.conf; done
	install -m 0644 README.txt $(DESTDIR)$(DROPINS_DIR)/
