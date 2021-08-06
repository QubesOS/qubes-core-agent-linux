BINDIR ?= /usr/bin
LIBDIR ?= /usr/lib
SYSCONFDIR ?= /etc
QUBESLIBDIR = $(LIBDIR)/qubes
QUBESRPCCMDDIR = $(SYSCONFDIR)/qubes-rpc
QUBESCONFDIR = $(SYSCONFDIR)/qubes
QUBESRPCCONFDIR = $(QUBESCONFDIR)/rpc-config

ifneq ($(DEBUG),0)
DEBUG_FLAGS := -g
endif
CPPFLAGS := -I.
CFLAGS := $(DEBUG_FLAGS) -O2 -Wall -Wextra -Werror -fPIC -pie $(CFLAGS)
LDFLAGS := $(DEBUG_FLAGS) -pie $(LDFLAGS)
LDLIBS := -lqubes-rpc-filecopy

.PHONY: all clean install

all:	vm-file-editor qopen-in-vm qfile-agent qfile-unpacker tar2qfile

vm-file-editor: vm-file-editor.o
qopen-in-vm: qopen-in-vm.o gui-fatal.o
qfile-agent: qfile-agent.o gui-fatal.o
qfile-unpacker: qfile-unpacker.o gui-fatal.o
tar2qfile: tar2qfile.o gui-fatal.o

clean:
	-$(RM) qopen-in-vm qfile-agent qfile-unpacker tar2qfile vm-file-editor *.o

install:
	install -d $(DESTDIR)$(BINDIR)
	install -t $(DESTDIR)$(BINDIR) \
		qubes-open \
		qvm-open-in-dvm qvm-open-in-vm qvm-run-vm qvm-sync-clock
	install -t $(DESTDIR)$(BINDIR) qvm-copy
	ln -s qvm-copy $(DESTDIR)$(BINDIR)/qvm-move-to-vm
	ln -s qvm-copy $(DESTDIR)$(BINDIR)/qvm-move
	ln -s qvm-copy $(DESTDIR)$(BINDIR)/qvm-copy-to-vm
	install -d $(DESTDIR)$(QUBESLIBDIR)
	install -t $(DESTDIR)$(QUBESLIBDIR) qvm-copy-to-vm.gnome
	ln -s qvm-copy-to-vm.gnome $(DESTDIR)$(QUBESLIBDIR)/qvm-move-to-vm.gnome
	ln -s qvm-copy-to-vm.gnome $(DESTDIR)$(QUBESLIBDIR)/qvm-copy-to-vm.kde
	ln -s qvm-copy-to-vm.gnome $(DESTDIR)$(QUBESLIBDIR)/qvm-move-to-vm.kde
	install -t $(DESTDIR)$(QUBESLIBDIR) \
		prepare-suspend resize-rootfs \
		qfile-agent qopen-in-vm qrun-in-vm qubes-sync-clock \
		tar2qfile vm-file-editor xdg-icon qvm-template-repo-query
	# Install qfile-unpacker as SUID, because it will fail to receive
	# files from other vm.
	install -t $(DESTDIR)$(QUBESLIBDIR) -m 4755 qfile-unpacker
	install -d $(DESTDIR)$(QUBESRPCCMDDIR)
	install -t $(DESTDIR)$(QUBESRPCCMDDIR) \
		qubes.Filecopy qubes.OpenInVM qubes.VMShell \
		qubes.VMRootShell \
		qubes.VMExec \
		qubes.OpenURL \
		qubes.SuspendPre qubes.SuspendPost qubes.GetAppmenus \
		qubes.SuspendPreAll \
		qubes.SuspendPostAll \
		qubes.WaitForSession \
		qubes.DetachPciDevice \
		qubes.Backup qubes.Restore \
		qubes.RegisterBackupLocation \
		qubes.RestoreById \
		qubes.SelectFile qubes.SelectDirectory \
		qubes.GetImageRGBA \
		qubes.SetDateTime \
		qubes.InstallUpdatesGUI \
		qubes.ResizeDisk \
		qubes.StartApp \
		qubes.Syslog \
		qubes.PostInstall \
		qubes.GetDate \
		qubes.ShowInTerminal \
		qubes.ConnectTCP \
		qubes.TemplateSearch \
		qubes.TemplateDownload
	ln -s qubes.VMExec $(DESTDIR)$(QUBESRPCCMDDIR)/qubes.VMExecGUI
	for config in *.config; do \
		install -D -m 0644 "$$config" "$(DESTDIR)$(QUBESRPCCONFDIR)/$${config%.config}"; \
	done
	install -d $(DESTDIR)$(SYSCONFDIR)
	install -t $(DESTDIR)$(SYSCONFDIR) -m 0644 qubes-suspend-module-blacklist
	install -d $(DESTDIR)/etc/qubes/suspend-pre.d
	install -t $(DESTDIR)$(QUBESCONFDIR)/suspend-pre.d -m 0644 suspend-pre.d/README
	install -d $(DESTDIR)/etc/qubes/suspend-post.d
	install -t $(DESTDIR)$(QUBESCONFDIR)/suspend-post.d -m 0644 suspend-post.d/README
	install -t $(DESTDIR)$(QUBESCONFDIR)/suspend-post.d suspend-post.d/*.sh
	install -d $(DESTDIR)/etc/qubes/post-install.d
	install -t $(DESTDIR)$(QUBESCONFDIR)/post-install.d -m 0644 post-install.d/README
	install -t $(DESTDIR)$(QUBESCONFDIR)/post-install.d post-install.d/*.sh
