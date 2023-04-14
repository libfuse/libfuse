#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdlib.h>

/*
gcc -W -Wall -fPIC -Wl,-init,test746_init -Wl,-z,initfirst -shared -o test746.so test746.c -l dl

sudo LD_PRELOAD=/workspaces/libfuse/test/test746.so ./passthrough_fh -f -d /mnt/temp

sudo bash -c 'T=`mktemp -d /mnt/temp/tmp/test746-XXXX` ; cd $T ; python3 -c "import os; f=open(\"test\", \"xt\"); f.close(); os.remove(\"test\");" ; ls -al'

set TEST746_DELAY_DISABLE env variable to disable the delay on demand at runtime
*/

static int (*original_close)(int fd) = NULL;
static int (*original_rename)(const char *oldpath, const char *newpath) = NULL;

void test746_init(void)
{
	fprintf(stderr, "*** TEST746 PRELOAD ACTIVE ***\n");

	original_close = dlsym(RTLD_NEXT, "close");
	original_rename = dlsym(RTLD_NEXT, "rename");
}

int close(int fd)
{
	if(!getenv("TEST746_DELAY_DISABLE")) usleep(100000);
	return original_close(fd);
}

int rename(const char *oldpath, const char *newpath)
{
	if(!getenv("TEST746_DELAY_DISABLE")) usleep(100000);
	return original_rename(oldpath, newpath);
}
