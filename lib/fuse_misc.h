/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2006  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB
*/

#include "config.h"
#include <pthread.h>

#ifndef USE_UCLIBC
#define fuse_mutex_init(mut) pthread_mutex_init(mut, NULL)
#else
static inline void fuse_mutex_init(pthread_mutex_t *mut)
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ADAPTIVE_NP);
    pthread_mutex_init(mut, &attr);
    pthread_mutexattr_destroy(&attr);
}
#endif




