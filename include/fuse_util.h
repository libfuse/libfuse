/*
  FUSE: Filesystem in Userspace

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

#ifndef _FUSE_UTIL_H_
#define _FUSE_UTIL_H_

#include <stdbool.h>

int libfuse_strtol(const char *str, long *res);

#endif /* _FUSE_UTIL_H_ */
