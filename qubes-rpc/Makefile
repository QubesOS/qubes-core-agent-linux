CC=gcc
CFLAGS=-g -Wall -I. -fPIC -pie
all:	vm-file-editor qopen-in-vm qfile-agent qfile-unpacker
vm-file-editor: vm-file-editor.o ioall.o
	$(CC) -pie -g -o $@ $^
qopen-in-vm: qopen-in-vm.o ioall.o gui-fatal.o
	$(CC) -pie -g -o $@ $^
qfile-agent: qfile-agent.o gui-fatal.o
	$(CC) -pie -g -o $@ $^ -lqubes-rpc-filecopy
qfile-unpacker: qfile-unpacker.o gui-fatal.o
	$(CC) -pie -g -o $@ $^ -lqubes-rpc-filecopy

clean:
	rm -f qopen-in-vm qfile-agent qfile-unpacker vm-file-editor *.o *~
