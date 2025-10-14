BINDIR ?= /usr/bin
SYSCONFDIR ?= /etc
SUDOERSDIR = $(SYSCONFDIR)/sudoers.d
PAMDIR = $(SYSCONFDIR)/pam.d
PAMCONFIGSDIR = /usr/share/pam-configs/
SYSLIBDIR ?= /lib

ifneq ($(DEB_HOST_MULTIARCH),)
  PAM_MOD_DIR = /usr/lib/$(DEB_HOST_MULTIARCH)/security
else
  PAM_MOD_DIR = /usr/lib64/security
endif

.PHONY: install install-debian install-rh all

all: qubes-admin-authzd pam_qubes_admin_authz.so

qubes-admin-authzd: qubes-admin-authzd.c qubes-admin-authz-common.h
	gcc -O2 -Wall -Wextra -Werror -fPIC -pie $< -o $@

pam_qubes_admin_authz.so: pam_qubes_admin_authz.c qubes-admin-authz-common.h
	gcc -O2 -Wall -Wextra -Werror -fPIC -pie -shared $< -o $@ -lpam

install:
	install -d -m 0750 $(DESTDIR)$(SUDOERSDIR)
	if [ -f /etc/redhat-release ] || [ -f /etc/debian_version ]; then \
		exec install -D -m 0440 qubes.sudoers $(DESTDIR)$(SUDOERSDIR)/qubes; \
	else \
		sed -E '/^[^#]/s/\<(ROLE|TYPE)=[A-Za-z0-9_]+[[:space:]]+//g' qubes.sudoers | \
		install -D -m 0440 /dev/stdin $(DESTDIR)$(SUDOERSDIR)/qubes; \
	fi
	install -D -t $(DESTDIR)$(PAM_MOD_DIR) pam_qubes_admin_authz.so
	install -D -t $(DESTDIR)$(BINDIR) qubes-admin-authzd
	install -D -m 0644 -t $(DESTDIR)$(SYSLIBDIR)/systemd/system qubes-admin-authzd.service
	install -D -m 0644 -t $(DESTDIR)$(SYSCONFDIR)/qubes/ admin-authzd.conf
	install -D -m 0644 -t $(DESTDIR)/usr/share/doc/qubes-core-agent-passwordless-root README.md

install-rh:
	install -D -m 0644 -t $(DESTDIR)$(SYSLIBDIR)/systemd/system-preset 75-qubes-admin-authz.preset
	install -d $(DESTDIR)/usr/share/authselect/vendor
	for i in \
		local \
		nis \
		sssd \
		winbind \
		; do \
		install -D -t $(DESTDIR)/usr/share/authselect/vendor/$$i \
			authselect/$$i/system-auth authselect/$$i/password-auth || exit 1; \
		for j in \
			README \
			REQUIREMENTS \
			dconf-db \
			dconf-locks \
			fingerprint-auth \
			nsswitch.conf \
			postlogin \
			smartcard-auth \
			; do \
			ln -s ../../default/$$i/$$j $(DESTDIR)/usr/share/authselect/vendor/$$i/$$j || exit 1; \
		done; \
	done

install-debian:
	install -D -m 0644 pam-configs-qubes-admin-authz $(DESTDIR)$(PAMCONFIGSDIR)/qubes-admin-authz
