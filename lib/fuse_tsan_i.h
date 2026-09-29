/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2026 Bernd Schubert <bsbernd.com>
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file COPYING.LIB.
 *
 */

#ifndef FUSE_TSAN_I_H_
#define FUSE_TSAN_I_H_

#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define FUSE_TSAN 1
#endif
#endif
#if defined(__SANITIZE_THREAD__)
#define FUSE_TSAN 1
#endif

/*
 * The kernel sends a request that depends on a reply, e.g. RELEASE after
 * FLUSH, only after that reply. Tell tsan, which cannot see /dev/fuse or the
 * ring, so it does not report the two handlers as a race.
 */
#ifdef FUSE_TSAN
#include <sanitizer/tsan_interface.h>
#define tsan_release_reply(se)   __tsan_release(se)
#define tsan_acquire_request(se) __tsan_acquire(se)
#else
#define tsan_release_reply(se)   ((void)(se))
#define tsan_acquire_request(se) ((void)(se))
#endif

#endif /* FUSE_TSAN_I_H_ */
