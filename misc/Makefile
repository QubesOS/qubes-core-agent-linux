CC=gcc
CFLAGS=-Wall -Wextra -Werror -g -O3
all:	xenstore-watch python
xenstore-watch: xenstore-watch.o
	$(CC) -o xenstore-watch xenstore-watch.o -lxenstore
python:
	python -m compileall .
	python -O -m compileall .
clean:
	rm -f xenstore-watch *.o *~ *.pyc *.pyo
