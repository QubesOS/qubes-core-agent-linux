CC=gcc
CFLAGS=-Wall -Wextra -Werror -g -O3
all:	xenstore-watch python close-window
xenstore-watch: xenstore-watch.o
	$(CC) -o xenstore-watch xenstore-watch.o -lxenstore
close-window: close-window.c
	$(CC) -lX11 -o $@ $<
python:
	python -m compileall .
	python -O -m compileall .
clean:
	rm -f xenstore-watch *.o *~ *.pyc *.pyo
