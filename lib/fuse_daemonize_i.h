/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2026 Bernd Schubert <bsbernd.com>
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file COPYING.LIB.
 *
 */

#ifndef FUSE_DAEMONIZE_I_H_
#define FUSE_DAEMONIZE_I_H_

#include <stdint.h>
#include <stdbool.h>

/**
 * Set mounted flag.
 *
 * Called from fuse_session_mount().
 */
void fuse_daemonize_early_set_mounted(void);

/**
 * Signal daemonization success to parent and cleanup.
 *
 * To be called from the child process after successful mount, when
 * sychronous FUSE_INIT is used (FUSE_INIT as part of the mount)
 * Automatically called for async FUSE_INIT.
 *
 * Not exposed to the ABI yet, as sync FUSE_INIT is not implemented yet.
 */
void fuse_daemonize_early_success(void);

/*
 * Check if daemonization is used.
 *
 * @return true if used, false otherwise
 */
bool fuse_daemonize_is_used(void);

#endif /* FUSE_DAEMONIZE_I_H_ */

