CC = gcc
CFLAGS = -Wall -W -g `glib-config --cflags`
LDFLAGS = `glib-config --libs`
CPPFLAGS = -I../include


all: libfuse.a

libfuse_objs = mount.o fuse.o

libfuse.a: $(libfuse_objs)
	ar cr libfuse.a $(libfuse_objs)

clean:
	rm -f *.o *.a
	rm -f *~
