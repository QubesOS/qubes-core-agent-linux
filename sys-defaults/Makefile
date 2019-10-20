SYSCONFDIR ?= /etc
SUDOERSDIR = $(SYSCONFDIR)/sudoers.d

.PHONY: install

install:
	install -D -m 0644 profile.d_qt_x11_no_mitshm.sh $(DESTDIR)$(SYSCONFDIR)/profile.d/qt_x11_no_mitshm.sh
	install -d -m 0750 $(DESTDIR)$(SUDOERSDIR)
	install -D -m 0440 sudoers.d_qt_x11_no_mitshm $(DESTDIR)$(SUDOERSDIR)/qt_x11_no_mitshm
	install -D -m 0440 sudoers.d_umask $(DESTDIR)$(SUDOERSDIR)/umask
	install -D -m 0644 20_tcp_timestamps.conf $(DESTDIR)$(SYSCONFDIR)/sysctl.d/20_tcp_timestamps.conf
	install -D -m 0644 dconf-db-local-dpi $(DESTDIR)$(SYSCONFDIR)/dconf/db/local.d/dpi
