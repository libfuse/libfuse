## Process this file with automake to produce Makefile.in

EXTRA_DIST = dev.c dir.c file.c inode.c util.c fuse_i.h

CC = @CC@
LD = @LD@
CFLAGS = -O2 -Wall -Wstrict-prototypes -fno-strict-aliasing -pipe
CPPFLAGS = -I@KERNINCLUDE@ -I../include -D__KERNEL__ -DMODULE -D_LOOSE_KERNEL_NAMES
INSTALL = @INSTALL@
fusemoduledir = @kmoduledir@/kernel/fs/fuse

SUFFIXES = .c .o .s


all-local: fuse.o

install-exec-local: fuse.o
	$(mkinstalldirs) $(DESTDIR)$(fusemoduledir)
	$(INSTALL) -m 644 fuse.o $(DESTDIR)$(fusemoduledir)/fuse.o
	-/sbin/depmod -a

uninstall-local:
	rm -f $(DESTDIR)$(fusemoduledir)/fuse.o
	-/sbin/depmod -a

clean-local:
	rm -f *.o *.s

.c.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<

fuse_objs = dev.o dir.o file.o inode.o util.o

fuse.o: $(fuse_objs)
	$(LD) -r -o fuse.o $(fuse_objs)

fuse_headers = fuse_i.h ../include/linux/fuse.h

dev.o: $(fuse_headers)
dir.o: $(fuse_headers)
file.o: $(fuse_headers)
inode.o: $(fuse_headers)
util.o: $(fuse_headers)
