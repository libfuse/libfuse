CC = gcc

KCFLAGS = -O2 -Wall -Wstrict-prototypes -fno-strict-aliasing -pipe
KCPPFLAGS = -I /lib/modules/`uname -r`/build/include/ -D__KERNEL__ -DMODULE -D_LOOSE_KERNEL_NAMES

CFLAGS = -Wall -W -g `glib-config --cflags`
LDFLAGS = `glib-config --libs`
CPPFLAGS = 

all: fuse.o fusemount

dev.o: dev.c
	$(CC) $(KCFLAGS) $(KCPPFLAGS) -c dev.c

inode.o: inode.c
	$(CC) $(KCFLAGS) $(KCPPFLAGS) -c inode.c

dir.o: dir.c
	$(CC) $(KCFLAGS) $(KCPPFLAGS) -c dir.c

util.o: util.c
	$(CC) $(KCFLAGS) $(KCPPFLAGS) -c util.c

fuse_objs = dev.o inode.o dir.o util.o

fuse.o: $(fuse_objs)
	ld -r -o fuse.o $(fuse_objs)

fusemount: fusemount.o

clean:
	rm -f *.o
	rm -f fusemount
	rm -f *~
