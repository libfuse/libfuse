CC = gcc
CFLAGS = -Wall -W -g `glib-config --cflags` -fPIC
LDFLAGS = `glib-config --libs`
CPPFLAGS = -I../include

all: libfuse.a libfuse.so

libfuse_objs = mount.o fuse.o

libfuse.a: $(libfuse_objs)
	ar cr libfuse.a $(libfuse_objs)

libfuse.so: $(libfuse_objs)
	gcc -shared -o libfuse.so $(libfuse_objs)

clean:
	rm -f *.o *.a
	rm -f *~
