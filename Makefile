CC = gcc
CFLAGS = -Wall -g `glib-config --cflags`
LDFLAGS = `glib-config --libs` -ldl -L ../avfs/libneon/
#LIBXML = -lxml
LIBXML = -lxmltok -lxmlparse
LDLIBS = -lneon $(LIBXML) -lpthread
CPPFLAGS = -Iinclude -I ../avfs/include



all: kernel/fuse.o fusepro avfsd

kernel/fuse.o: FORCE
	make -C kernel fuse.o

lib/libfuse.a: FORCE
	make -C lib libfuse.a

fusepro: fusepro.o lib/libfuse.a

avfsd: usermux.o avfsd.o ../avfs/lib/avfs.o lib/libfuse.a 

clean:
	make -C kernel clean
	make -C lib clean
	rm -f *.o
	rm -f fusepro avfsd
	rm -f *~

FORCE:
