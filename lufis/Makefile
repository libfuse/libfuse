CC = gcc
CFLAGS = -Wall -W -g
LDLIBS = -lfuse -lpthread -ldl -rdynamic
CPPFLAGS := -D_FILE_OFFSET_BITS=64
#CPPFLAGS += -DDEBUG

lufis: lufis.o options.o dircache.o

clean:
	rm -f *.o lufis
