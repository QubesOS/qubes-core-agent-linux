CC=gcc
CFLAGS+=-I. -g -O2 -Wall -Wextra -Werror -pie -fPIC `pkg-config --cflags vchan-$(BACKEND_VMM)`
LDFLAGS=-pie
LDLIBS=`pkg-config --libs vchan-$(BACKEND_VMM)` -lqrexec-utils -lpam

all: qrexec-agent qrexec-client-vm qrexec-fork-server
qrexec-agent: qrexec-agent.o qrexec-agent-data.o
qrexec-fork-server: qrexec-fork-server.o qrexec-agent-data.o
qrexec-client-vm: qrexec-client-vm.o qrexec-agent-data.o
clean:
	rm -f *.o *~ qrexec-agent qrexec-client-vm

install:
	install -d $(DESTDIR)/etc/qubes-rpc
	install -d $(DESTDIR)/usr/lib/qubes $(DESTDIR)/usr/bin
	install qrexec-agent $(DESTDIR)/usr/lib/qubes
	install qrexec-client-vm $(DESTDIR)/usr/bin
	ln -s ../../bin/qrexec-client-vm $(DESTDIR)/usr/lib/qubes/qrexec-client-vm
	ln -s ../../bin/qrexec-client-vm $(DESTDIR)/usr/lib/qubes/qrexec_client_vm
	install qrexec-fork-server $(DESTDIR)/usr/bin
	install qubes-rpc-multiplexer $(DESTDIR)/usr/lib/qubes
ifeq ($(shell lsb_release -is), Debian)
	install -D -m 0644 qrexec.pam.debian $(DESTDIR)/etc/pam.d/qrexec
else
	install -D -m 0644 qrexec.pam $(DESTDIR)/etc/pam.d/qrexec
endif

