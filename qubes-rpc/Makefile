CC=gcc
CFLAGS=-g -O2 -Wall -Wextra -Werror -I. -fPIC -pie
all:	vm-file-editor qopen-in-vm qfile-agent qfile-unpacker tar2qfile
vm-file-editor: vm-file-editor.o
	$(CC) -pie -g -o $@ $^ -lqubes-rpc-filecopy
qopen-in-vm: qopen-in-vm.o gui-fatal.o
	$(CC) -pie -g -o $@ $^ -lqubes-rpc-filecopy
qfile-agent: qfile-agent.o gui-fatal.o
	$(CC) -pie -g -o $@ $^ -lqubes-rpc-filecopy
qfile-unpacker: qfile-unpacker.o gui-fatal.o
	$(CC) -pie -g -o $@ $^ -lqubes-rpc-filecopy
tar2qfile: tar2qfile.o gui-fatal.o
	$(CC) -pie -g -o $@ $^ -lqubes-rpc-filecopy

clean:
	rm -f qopen-in-vm qfile-agent qfile-unpacker tar2qfile vm-file-editor *.o *~
