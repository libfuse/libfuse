CC = gcc
CFLAGS = -Wall -W -g `glib-config --cflags`
LDFLAGS = `glib-config --libs`
CPPFLAGS = -Iinclude



all: kernel/fuse.o fusepro

kernel/fuse.o: FORCE
	make -C kernel fuse.o

lib/libfuse.a: FORCE
	make -C lib libfuse.a

fusepro: fusepro.o lib/libfuse.a

clean:
	make -C kernel clean
	make -C lib clean
	rm -f *.o
	rm -f fusepro
	rm -f *~

FORCE:
