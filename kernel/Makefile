CC = gcc
CFLAGS = -O2 -Wall -Wstrict-prototypes -fno-strict-aliasing -pipe
CPPFLAGS = -I /lib/modules/`uname -r`/build/include/ -D__KERNEL__ -DMODULE -D_LOOSE_KERNEL_NAMES -I../include


all: fuse.o

fuse_objs = dev.o inode.o dir.o file.o util.o

fuse.o: $(fuse_objs)
	ld -r -o fuse.o $(fuse_objs)


clean:
	rm -f *.o
	rm -f *~
