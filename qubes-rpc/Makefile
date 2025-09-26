BINDIR ?= /usr/bin
LIBDIR ?= /usr/lib
SYSCONFDIR ?= /etc
QUBESLIBDIR = $(LIBDIR)/qubes
QUBESRPCCMDDIR = $(SYSCONFDIR)/qubes-rpc
QUBESCONFDIR = $(SYSCONFDIR)/qubes
QUBESRPCCONFDIR = $(QUBESCONFDIR)/rpc-config
LN := ln -sf

ifneq ($(DEBUG),0)
DEBUG_FLAGS := -g
endif
CPPFLAGS := -I.
CFLAGS := $(DEBUG_FLAGS) -O2 -Wall -Wextra -Werror -fPIC -pie $(CFLAGS)
LDFLAGS := $(DEBUG_FLAGS) -pie $(LDFLAGS)
LDLIBS := -lqubes-rpc-filecopy -lqubes-pure

.PHONY: all clean install

all:	vm-file-editor qopen-in-vm qfile-agent qfile-unpacker tar2qfile qubes-fs-tree-check bin-qfile-unpacker

ifdef DEVEL_BUILD
# Ensure that these programs can find their shared libraries,
# even when installed in e.g. a TemplateBasedVM to somewhere other
# than /usr.
vm-file-editor qopen-in-vm qfile-agent qfile-unpacker tar2qfile qubes-fs-tree-check: LDFLAGS += '-Wl,-rpath,$$ORIGIN/../../$$LIB'
# This is installed in /usr/bin, not /usr/lib/qubes, so it needs a different rpath.
bin-qfile-unpacker: LDFLAGS += '-Wl,-rpath,$$ORIGIN/../$$LIB'
endif

bin-qfile-unpacker: qfile-unpacker.o gui-fatal.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
qubes-fs-tree-check: LDLIBS := -lqubes-pure
qubes-fs-tree-check: qubes-fs-tree-check.o
vm-file-editor: vm-file-editor.o
qopen-in-vm: qopen-in-vm.o gui-fatal.o
qfile-agent: qfile-agent.o gui-fatal.o
qfile-unpacker: qfile-unpacker.o gui-fatal.o
tar2qfile: tar2qfile.o gui-fatal.o

clean:
	-$(RM) -- qopen-in-vm qfile-agent qfile-unpacker tar2qfile vm-file-editor qubes-fs-tree-check bin-qfile-unpacker *.o

install:
	install -d $(DESTDIR)$(BINDIR)
	install -t $(DESTDIR)$(BINDIR) \
		qubes-open \
		qvm-open-in-vm qvm-run-vm qvm-sync-clock
	$(LN) qvm-open-in-vm $(DESTDIR)$(BINDIR)/qvm-open-in-dvm
	install -t $(DESTDIR)$(BINDIR) qvm-copy
	$(LN) qvm-copy $(DESTDIR)$(BINDIR)/qvm-move-to-vm
	$(LN) qvm-copy $(DESTDIR)$(BINDIR)/qvm-move
	$(LN) qvm-copy $(DESTDIR)$(BINDIR)/qvm-copy-to-vm
	install -d $(DESTDIR)$(QUBESLIBDIR)
	install -t $(DESTDIR)$(QUBESLIBDIR) qvm-copy-to-vm.gnome
	install -t $(DESTDIR)$(QUBESLIBDIR) qvm-actions.sh
	$(LN) qvm-copy-to-vm.gnome $(DESTDIR)$(QUBESLIBDIR)/qvm-move-to-vm.gnome
	$(LN) qvm-copy-to-vm.gnome $(DESTDIR)$(QUBESLIBDIR)/qvm-copy-to-vm.kde
	$(LN) qvm-copy-to-vm.gnome $(DESTDIR)$(QUBESLIBDIR)/qvm-move-to-vm.kde
	install -t $(DESTDIR)$(QUBESLIBDIR) \
		prepare-suspend resize-rootfs \
		qfile-agent qopen-in-vm qrun-in-vm qubes-sync-clock \
		tar2qfile vm-file-editor xdg-icon qvm-template-repo-query \
		qubes-fs-tree-check
	# Install qfile-unpacker as SUID, because it will fail to receive
	# files from other vm.
	install -t $(DESTDIR)$(QUBESLIBDIR) -m 4755 qfile-unpacker
	# This version isn't confined by SELinux, so it supports other
	# home directories.
	install -m 4755 bin-qfile-unpacker $(DESTDIR)$(BINDIR)/qfile-unpacker
	install -d $(DESTDIR)$(QUBESRPCCMDDIR)
	install -t $(DESTDIR)$(QUBESRPCCMDDIR) \
		qubes.Filecopy qubes.OpenInVM qubes.VMShell \
		qubes.VMRootShell \
		qubes.VMExec \
		qubes.VMRootExec \
		qubes.OpenURL \
		qubes.SuspendPre qubes.SuspendPost qubes.GetAppmenus \
		qubes.SuspendPreAll \
		qubes.SuspendPostAll \
		qubes.WaitForSession \
		qubes.WaitForRunningSystem \
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
		qubes.PostInstall \
		qubes.GetDate \
		qubes.ShowInTerminal \
		qubes.TemplateSearch \
		qubes.TemplateDownload
	$(LN) qubes.VMExec $(DESTDIR)$(QUBESRPCCMDDIR)/qubes.VMExecGUI
	$(LN) /dev/tcp/127.0.0.1 $(DESTDIR)$(QUBESRPCCMDDIR)/qubes.ConnectTCP
	$(LN) /dev/tcp/127.0.0.1/8082 $(DESTDIR)$(QUBESRPCCMDDIR)/qubes.UpdatesProxy
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
