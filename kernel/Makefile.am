## Process this file with automake to produce Makefile.in

EXTRA_DIST = dev.c dir.c file.c inode.c util.c fuse_i.h

CC = @CC@
CFLAGS = -O2 -Wall -Wstrict-prototypes -fno-strict-aliasing -pipe
CPPFAGS = -I@KERNINCLUDE@ -I../include -D__KERNEL__ -DMODULE -D_LOOSE_KERNEL_NAMES
INSTALL = @INSTALL@
fusemoduledir = @kmoduledir@/kernel/fs/fuse

SUFFIXES = .c .o .s


all-local: fuse.o

install-exec-local: fuse.o
	$(mkinstalldirs) $(DESTDIR)$(fusemoduledir)
	$(INSTALL) -m 644 fuse.o $(DESTDIR)$(fusemoduledir)/fuse.o
	/sbin/depmod -a

clean-local:
	rm -f *.o *.s


.c.o:
	$(CC) $(CFLAGS) $(CPPFAGS) -c $<

fuse_objs = dev.o dir.o file.o inode.o util.o

fuse.o: $(fuse_objs)
	ld -r -o fuse.o $(fuse_objs)
