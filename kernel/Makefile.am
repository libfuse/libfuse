## Process this file with automake to produce Makefile.in

EXTRA_DIST = dev.c dir.c file.c inode.c util.c fuse_i.h

all-local: fuse.o

clean-local:
	rm -f *.o *.s

CFLAGS = -O2 -Wall -Wstrict-prototypes -fno-strict-aliasing -pipe
CPPFAGS = -I@KERNINCLUDE@ -I../include -D__KERNEL__ -DMODULE -D_LOOSE_KERNEL_NAMES

SUFFIXES = .c .o .s

.c.o:
	$(CC) $(CFLAGS) $(CPPFAGS) -c $<

fuse_objs = dev.o dir.o file.o inode.o util.o

fuse.o: $(fuse_objs)
	ld -r -o fuse.o $(fuse_objs)
