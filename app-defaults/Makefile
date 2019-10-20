GLIBSCHEMAS ?= /usr/share/glib-2.0/schemas

.PHONY: install

install:
	install -d $(DESTDIR)$(GLIBSCHEMAS)
	install -t $(DESTDIR)$(GLIBSCHEMAS) -m 0644 \
		20_org.gnome.desktop.wm.preferences.qubes.gschema.override \
		20_org.gnome.nautilus.qubes.gschema.override \
		20_org.gnome.settings-daemon.plugins.updates.qubes.gschema.override \
		20_org.mate.NotificationDaemon.qubes.gschema.override
