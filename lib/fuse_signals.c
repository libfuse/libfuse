/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Utility functions for setting signal handlers.

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#include "fuse_config.h"
#include "fuse_lowlevel.h"
#include "fuse_i.h"

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>

#ifdef HAVE_BACKTRACE
#include <execinfo.h>
#endif

static int teardown_sigs[] = { SIGHUP, SIGINT, SIGTERM };
static int ignore_sigs[] = { SIGPIPE};
static int fail_sigs[] = { SIGILL, SIGTRAP, SIGABRT, SIGBUS, SIGFPE, SIGSEGV };
static struct fuse_session *fuse_instance;

#define BT_STACK_SZ (1024 * 1024)
static void *backtrace_buffer[BT_STACK_SZ];

static void dump_stack(void)
{
#ifdef HAVE_BACKTRACE
	char **strings;

	int nptrs = backtrace(backtrace_buffer, BT_STACK_SZ);
	strings = backtrace_symbols(backtrace_buffer, nptrs);

	if (strings == NULL) {
		fuse_log(FUSE_LOG_ERR, "Failed to get backtrace symbols: %s\n",
			 strerror(errno));
		return;
	}

	for (int idx = 0; idx < nptrs; idx++)
		fuse_log(FUSE_LOG_ERR, "%s\n", strings[idx]);

	free(strings);
#endif
}

static void exit_handler(int sig)
{
	if (fuse_instance == NULL)
		return;

	fuse_session_exit(fuse_instance);

	if (sig < 0) {
		fuse_log(FUSE_LOG_ERR,
				"assertion error: signal value <= 0\n");
		dump_stack();
		abort();
		fuse_instance->error = sig;
	}

	fuse_instance->error = sig;
}

static void exit_backtrace(int sig)
{
	if (fuse_instance == NULL)
		return;

	fuse_session_exit(fuse_instance);

	fuse_remove_signal_handlers(fuse_instance);
	fuse_log(FUSE_LOG_ERR, "Got signal: %d\n", sig);
	dump_stack();
	abort();
}


static void do_nothing(int sig)
{
	(void) sig;
}

static int set_one_signal_handler(int sig, void (*handler)(int), int remove)
{
	struct sigaction sa;
	struct sigaction old_sa;

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = remove ? SIG_DFL : handler;
	sigemptyset(&(sa.sa_mask));
	sa.sa_flags = 0;

	if (sigaction(sig, NULL, &old_sa) == -1) {
		perror("fuse: cannot get old signal handler");
		return -1;
	}

	if (old_sa.sa_handler == (remove ? handler : SIG_DFL) &&
	    sigaction(sig, &sa, NULL) == -1) {
		perror("fuse: cannot set signal handler");
		return -1;
	}
	return 0;
}

static int _fuse_set_signal_handlers(int signals[], int nr_signals,
				     void (*handler)(int))
{
	for (int idx = 0; idx < nr_signals; idx++) {
		int signal = signals[idx];

		/*
		 * If we used SIG_IGN instead of the do_nothing function,
		 * then we would be unable to tell if we set SIG_IGN (and
		 * thus should reset to SIG_DFL in fuse_remove_signal_handlers)
		 * or if it was already set to SIG_IGN (and should be left
		 * untouched.
		*/
		if (set_one_signal_handler(signal, handler, 0) == -1) {
			fuse_log(FUSE_LOG_ERR,
				 "Failed to install signal handler for sig %d\n",
				 signal);
			return -1;
		}
	}

	return 0;
}

int fuse_set_signal_handlers(struct fuse_session *se)
{
	size_t nr_signals;
	int rc;

	nr_signals = sizeof(teardown_sigs) / sizeof(teardown_sigs[0]);
	rc = _fuse_set_signal_handlers(teardown_sigs, nr_signals, exit_handler);
	if (rc < 0)
		return rc;

	nr_signals = sizeof(ignore_sigs) / sizeof(ignore_sigs[0]);
	rc = _fuse_set_signal_handlers(ignore_sigs, nr_signals, do_nothing);
	if (rc < 0)
		return rc;

	if (fuse_instance == NULL)
		fuse_instance = se;
	return 0;
}

int fuse_set_fail_signal_handlers(struct fuse_session *se)
{
	size_t nr_signals = sizeof(fail_sigs) / sizeof(fail_sigs[0]);

	int rc = _fuse_set_signal_handlers(fail_sigs, nr_signals,
					   exit_backtrace);
	if (rc < 0)
		return rc;

	if (fuse_instance == NULL)
		fuse_instance = se;

	return 0;
}

static void _fuse_remove_signal_handlers(int signals[], int nr_signals,
					 void (*handler)(int))
{
	for (int idx = 0; idx < nr_signals; idx++)
		set_one_signal_handler(signals[idx], handler, 1);
}

void fuse_remove_signal_handlers(struct fuse_session *se)
{
	size_t nr_signals;

	if (fuse_instance != se)
		fuse_log(FUSE_LOG_ERR,
			"fuse: fuse_remove_signal_handlers: unknown session\n");
	else
		fuse_instance = NULL;

	nr_signals = sizeof(teardown_sigs) / sizeof(teardown_sigs[0]);
	_fuse_remove_signal_handlers(teardown_sigs, nr_signals, exit_handler);

	nr_signals = sizeof(ignore_sigs) / sizeof(ignore_sigs[0]);
	_fuse_remove_signal_handlers(ignore_sigs, nr_signals, do_nothing);

	nr_signals = sizeof(fail_sigs) / sizeof(fail_sigs[0]);
	_fuse_remove_signal_handlers(fail_sigs, nr_signals, exit_backtrace);
}
