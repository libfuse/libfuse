CC = gcc
CFLAGS = -Wall -g `glib-config --cflags`
LDFLAGS = `glib-config --libs` -ldl -L ../avfs/libneon/ -L lib
#LIBXML = -lxml
LIBXML = -lxmltok -lxmlparse
LDLIBS = -lneon $(LIBXML) -lfuse -lpthread
CPPFLAGS = -Iinclude -I ../avfs/include

all: kernel/fuse.o fusexmp avfsd

kernel/fuse.o: FORCE
	make -C kernel fuse.o

lib/libfuse.a: FORCE
	make -C lib libfuse.a

lib/libfuse.so: FORCE
	make -C lib libfuse.so

fusexmp: fusexmp.o lib/libfuse.so
	gcc $(CFLAGS) $(LDFLAGS) -o fusexmp fusexmp.o $(LDLIBS)

avfsd_objs = usermux.o avfsd.o ../avfs/lib/avfs.o
avfsd: $(avfsd_objs) lib/libfuse.so
	gcc $(CFLAGS) $(LDFLAGS) -o avfsd $(avfsd_objs) $(LDLIBS)

clean:
	make -C kernel clean
	make -C lib clean
	rm -f *.o
	rm -f fusexmp avfsd
	rm -f *~

FORCE:
