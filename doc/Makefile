VM_DIR=vm-tools
PANDOC=pandoc -s -f rst -t man
RPMS_DIR=rpm/

VM_DOCS=$(patsubst %.rst,%.1.gz,$(wildcard $(VM_DIR)/*.rst))

help:
	@echo "make rpms			-- generate manpages and create RPM package"
	@echo "make rst=example.rst preview	-- generate manpage preview from example.rst"
	@echo "make manpages			-- generate manpages"
	@echo "make install			-- generate VM manpages and copy them to /usr/share/man"

install: manpages
	mkdir -p $(DESTDIR)/usr/share/man/man1
	cp $(VM_DOCS) $(DESTDIR)/usr/share/man/man1/

%.1: %.rst
	$(PANDOC) $< > $@

%.1.gz: %.1
	gzip -f $<

manpages: $(QVM_DOCS) $(QUBES_DOCS) $(VM_DOCS)

preview:	$(rst)
	$(PANDOC) $(rst) | groff -mandoc -Tlatin1 | less -R

clean:
	rm -f $(VM_DOCS)
