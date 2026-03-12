/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2026 Bernd Schubert <bsbernd.com>
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file COPYING.LIB.
 *
 */

#ifndef FUSE_DAEMONIZE_H_
#define FUSE_DAEMONIZE_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Flags for fuse_daemonize_start()
 */
#define FUSE_DAEMONIZE_NO_CHDIR      (1 << 0)
#define FUSE_DAEMONIZE_NO_BACKGROUND (1 << 1)

/**
 * Start daemonization process.
 *
 * Unless FUSE_DAEMONIZE_NO_BACKGROUND is set, this forks the process.
 * The parent waits for a signal from the child via fuse_daemonize_success()
 * or fuse_daemonize_fail().
 * The child returns from this call and continues setup.
 *
 * Unless FUSE_DAEMONIZE_NO_CHDIR is set, changes directory to "/".
 *
 * Must be called before fuse_session_mount().
 *
 * @param flags combination of FUSE_DAEMONIZE_* flags
 * @return 0 on success, negative errno on error
 */
int fuse_daemonize_early_start(unsigned int flags);

/**
 * Signal daemonization failure to parent and cleanup.
 *
 * To be called from the child process on any kind of error.
 *
 * @param err Error code passed to the parent and used as process exit code.

 */
void fuse_daemonize_early_fail(int err);

/**
 * Check if daemonization is active and waiting for signal.
 *
 * Can be called from the child process to check state of daemonization.
 *
 * @return true if active, false otherwise
 */
bool fuse_daemonize_early_is_active(void);

#ifdef __cplusplus
}
#endif

#endif /* FUSE_DAEMONIZE_H_ */

