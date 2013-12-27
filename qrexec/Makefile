CC=gcc
CFLAGS+=-I. -g -Wall -Wextra -Werror -pie -fPIC `pkg-config --cflags vchan-$(BACKEND_VMM)`
LIBS=`pkg-config --libs vchan-$(BACKEND_VMM)` -lqrexec-utils

all: qrexec-agent qrexec-client-vm
qrexec-agent: qrexec-agent.o
	$(CC) -pie -g -o qrexec-agent qrexec-agent.o $(LIBS)
qrexec-client-vm: qrexec-client-vm.o
	$(CC) -pie -g -o qrexec-client-vm qrexec-client-vm.o
clean:
	rm -f *.o *~ qrexec-agent qrexec-client-vm

install:
	install -d $(DESTDIR)/etc/qubes-rpc
	install -d $(DESTDIR)/usr/lib/qubes
	install qrexec-agent $(DESTDIR)/usr/lib/qubes
	install qrexec-client-vm $(DESTDIR)/usr/lib/qubes
	ln -s qrexec-client-vm $(DESTDIR)/usr/lib/qubes/qrexec_client_vm
	install qubes-rpc-multiplexer $(DESTDIR)/usr/lib/qubes

