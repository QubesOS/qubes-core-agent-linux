CC=gcc
CFLAGS+=-I. -g -Wall -Wextra -Werror -pie -fPIC
XENLIBS=-lvchan -lxenstore -lxenctrl
LIBS=$(XENLIBS) -lqrexec-utils

all: qrexec-agent qrexec-client-vm
qrexec-daemon: qrexec-daemon.o
	$(CC) -pie -g -o qrexec-daemon qrexec-daemon.o $(LIBS)
qrexec-agent: qrexec-agent.o
	$(CC) -pie -g -o qrexec-agent qrexec-agent.o $(LIBS)
qrexec-client: qrexec-client.o
	$(CC) -pie -g -o qrexec-client qrexec-client.o $(LIBS)
qrexec-client-vm: qrexec-client-vm.o
	$(CC) -pie -g -o qrexec-client-vm qrexec-client-vm.o
clean:
	rm -f *.o *~ qrexec-agent qrexec-client-vm

install:
	install -d $(DESTDIR)/etc/qubes-rpc
	install -d $(DESTDIR)/usr/lib/qubes
	install -d $(DESTDIR)/usr/bin
	install qrexec-agent $(DESTDIR)/usr/lib/qubes
	install qrexec-client-vm $(DESTDIR)/usr/bin
	ln -s ../../bin/qrexec-client-vm $(DESTDIR)/usr/lib/qubes/qrexec-client-vm
	ln -s ../../bin/qrexec-client-vm $(DESTDIR)/usr/lib/qubes/qrexec_client_vm
	install qubes-rpc-multiplexer $(DESTDIR)/usr/lib/qubes

