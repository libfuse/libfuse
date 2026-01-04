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
 * Status values for fuse_daemonize_signal()
 */
#define FUSE_DAEMONIZE_SUCCESS 0
#define FUSE_DAEMONIZE_FAILURE 1

/**
 * Start daemonization process.
 *
 * Unless FUSE_DAEMONIZE_NO_BACKGROUND is set, this forks the process.
 * The parent waits for a signal from the child via fuse_daemonize_signal().
 * The child returns from this call and continues setup.
 *
 * Unless FUSE_DAEMONIZE_NO_CHDIR is set, changes directory to "/".
 *
 * Must be called before fuse_session_mount().
 *
 * @param flags combination of FUSE_DAEMONIZE_* flags
 * @return 0 on success, negative errno on error
 */
int fuse_daemonize_start(unsigned int flags);

/**
 * Signal daemonization status to parent and cleanup.
 *
 * The child calls this after setup is complete (or failed).
 * The parent receives the status and exits with it.
 * Safe to call multiple times or if start failed.
 *
 * @param status FUSE_DAEMONIZE_SUCCESS or FUSE_DAEMONIZE_FAILURE
 */
void fuse_daemonize_signal(int status);

/**
 * Check if daemonization is active and waiting for signal.
 *
 * @return true if active, false otherwise
 */
bool fuse_daemonize_active(void);

#ifdef __cplusplus
}
#endif

#endif /* FUSE_DAEMONIZE_H_ */

