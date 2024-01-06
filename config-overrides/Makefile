DATADIR ?= /usr/share
GLIBSCHEMAS ?= $(DATADIR)/glib-2.0/schemas
SYSCONFDIR ?= /etc
SUDOERSDIR = $(SYSCONFDIR)/sudoers.d

.PHONY: install

install:
	install -D -m 0644 profile.d_qt_x11_no_mitshm.sh $(DESTDIR)$(SYSCONFDIR)/profile.d/qt_x11_no_mitshm.sh
	install -D -m 0644 profile.d_qubes_disable_lesspipe.sh $(DESTDIR)$(SYSCONFDIR)/profile.d/zqubes_disable_lesspipe.sh
	install -d -m 0750 $(DESTDIR)$(SUDOERSDIR)
	install -D -m 0440 sudoers.d_qt_x11_no_mitshm $(DESTDIR)$(SUDOERSDIR)/qt_x11_no_mitshm
	install -D -m 0440 sudoers.d_umask $(DESTDIR)$(SUDOERSDIR)/umask
	install -D -m 0644 20_tcp_timestamps.conf $(DESTDIR)$(SYSCONFDIR)/sysctl.d/20_tcp_timestamps.conf
	install -D -m 0644 dconf-db-local-dpi $(DESTDIR)$(SYSCONFDIR)/dconf/db/local.d/dpi
	install -d $(DESTDIR)$(GLIBSCHEMAS)
	install -t $(DESTDIR)$(GLIBSCHEMAS) -m 0644 \
		20_org.gnome.desktop.wm.preferences.qubes.gschema.override \
		20_org.gnome.nautilus.qubes.gschema.override \
		20_org.gnome.settings-daemon.plugins.updates.qubes.gschema.override \
		20_org.mate.NotificationDaemon.qubes.gschema.override
	install -D -m 0644 portals.conf $(DESTDIR)/usr/share/xdg-desktop-portal/portals.conf
