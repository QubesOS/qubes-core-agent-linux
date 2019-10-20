LIBDIR ?= /usr/lib
STATEDIR ?= /var/lib
SYSCONFDIR ?= /etc
QUBESBINDSDIR = $(LIBDIR)/qubes-bind-dirs.d
QUBESSTATEDIR = $(STATEDIR)/qubes

.PHONY: install

install:
	install -D -m 0644 fstab $(DESTDIR)$(SYSCONFDIR)/fstab
	install -d $(DESTDIR)$(QUBESBINDSDIR)
	install -t $(DESTDIR)$(QUBESBINDSDIR) -m 0644 30_cron.conf
	install -d $(DESTDIR)$(QUBESSTATEDIR)
	install -d $(DESTDIR)/mnt/removable
	install -d $(DESTDIR)/rw
