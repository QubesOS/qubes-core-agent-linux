DOMAIN = qubes-core-agent-linux
LOCALEDIR ?= /usr/share/locale
MSGFMT ?= msgfmt
XGETTEXT ?= xgettext

LANGUAGES := $(shell cat LINGUAS)
MO_FILES := $(addsuffix .mo,$(LANGUAGES))

PY_SOURCES := $(wildcard ../qubes-rpc/nautilus/*.py ../qubes-rpc/caja/*.py)
SH_SOURCES := ../qubes-rpc/qvm-actions.sh ../qubes-rpc/qvm-copy-to-vm.gnome \
	../qubes-rpc/qvm-open-in-vm \
	../package-managers/qubes-download-dom0-updates.sh

.PHONY: all install clean update-pot

all: $(MO_FILES)

%.mo: %.po
	$(MSGFMT) -c -o $@ $<

install: all
	for lang in $(LANGUAGES); do \
		install -D -m 0644 $$lang.mo \
			$(DESTDIR)$(LOCALEDIR)/$$lang/LC_MESSAGES/$(DOMAIN).mo || exit 1; \
	done

update-pot:
	cd .. && $(XGETTEXT) --package-name=$(DOMAIN) --from-code=UTF-8 \
		--sort-by-file -o po/$(DOMAIN).pot -L Python \
		$(patsubst ../%,%,$(PY_SOURCES))
	cd .. && $(XGETTEXT) -j --from-code=UTF-8 --sort-by-file \
		-o po/$(DOMAIN).pot -L Shell --keyword=gettext \
		--keyword=tr_printf $(patsubst ../%,%,$(SH_SOURCES))

clean:
	rm -f *.mo
