CC=gcc
CFLAGS=-Wall -Wextra -Werror -g -O3

_XENSTORE_H=$(wildcard /usr/include/xenstore.h)
ifneq "$(_XENSTORE_H)" ""
	CFLAGS+= -DUSE_XENSTORE_H
endif

all:	xenstore-watch python close-window
xenstore-watch: xenstore-watch.o
	$(CC) -o xenstore-watch xenstore-watch.o -lxenstore
close-window: close-window.c
	$(CC) -o $@ $< -lX11
python: python2 python3
python2:
	rm -rf py2
	mkdir -p py2
	cp *.py py2/
	python2 -m compileall py2
	python2 -O -m compileall py2

# Only some scripts does support python3 for now
python3:
	rm -rf py3
	mkdir -p py3
	cp dnf-qubes-hooks.py qubesxdg.py py3/
	python3 -m compileall py3
	python3 -O -m compileall py3

clean:
	rm -f xenstore-watch *.o *~ *.pyc *.pyo
