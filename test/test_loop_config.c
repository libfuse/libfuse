/*
 * Unit tests for fuse_loop_cfg_set_idle_threads() /
 * fuse_loop_cfg_set_max_threads() interaction.
 *
 * No FUSE mount is needed; the tests exercise the setter logic directly.
 */

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 12)

#include "fuse_i.h"          /* internal struct fuse_loop_config (v2) */
#include "fuse_lowlevel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* ------------------------------------------------------------------ */
/* Log capture                                                         */
/* ------------------------------------------------------------------ */

static char last_log_msg[512];
static enum fuse_log_level last_log_level;

static void test_log_handler(enum fuse_log_level level, const char *fmt,
			     va_list ap)
{
	last_log_level = level;
	vsnprintf(last_log_msg, sizeof(last_log_msg), fmt, ap);
}

static void clear_log(void)
{
	last_log_msg[0] = '\0';
	last_log_level = FUSE_LOG_DEBUG;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

#define PASS(name) do { printf("PASS: %s\n", name); } while (0)
#define FAIL(name, fmt, ...) \
	do { fprintf(stderr, "FAIL: %s — " fmt "\n", name, ##__VA_ARGS__); \
	     exit(1); } while (0)

#define CHECK(name, cond) \
	do { if (!(cond)) FAIL(name, "assertion failed: %s", #cond); } while (0)

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

/*
 * Normal case: set_max_threads with no idle constraint → value accepted as-is.
 */
static void test_max_threads_normal(void)
{
	const char *name = "max_threads_normal";
	struct fuse_loop_config *cfg = fuse_loop_cfg_create();

	clear_log();
	fuse_loop_cfg_set_max_threads(cfg, 20);

	CHECK(name, cfg->max_threads == 20);
	CHECK(name, last_log_msg[0] == '\0'); /* no warning */

	fuse_loop_cfg_destroy(cfg);
	PASS(name);
}

/*
 * idle disabled (default -1): set_max_threads to any value is accepted.
 */
static void test_max_threads_idle_disabled(void)
{
	const char *name = "max_threads_idle_disabled";
	struct fuse_loop_config *cfg = fuse_loop_cfg_create();

	/* default max_idle_threads == -1 (disabled) */
	clear_log();
	fuse_loop_cfg_set_max_threads(cfg, 5);

	CHECK(name, cfg->max_threads == 5);
	CHECK(name, last_log_msg[0] == '\0'); /* no warning */

	fuse_loop_cfg_destroy(cfg);
	PASS(name);
}

/*
 * idle == 0 (disabled): set_max_threads to a small value is accepted.
 */
static void test_max_threads_idle_zero(void)
{
	const char *name = "max_threads_idle_zero";
	struct fuse_loop_config *cfg = fuse_loop_cfg_create();

	fuse_loop_cfg_set_idle_threads(cfg, 0);
	clear_log();
	fuse_loop_cfg_set_max_threads(cfg, 5);

	CHECK(name, cfg->max_threads == 5);
	CHECK(name, last_log_msg[0] == '\0'); /* no warning */

	fuse_loop_cfg_destroy(cfg);
	PASS(name);
}

/*
 * Warning: set_idle(100) then set_max(5) → value is set but a warning is logged.
 * The resulting config is technically invalid (idle reaping can never trigger)
 * but we honour the caller's explicit request.
 */
static void test_warn_max_below_idle(void)
{
	const char *name = "warn_max_below_idle";
	struct fuse_loop_config *cfg = fuse_loop_cfg_create();

	fuse_loop_cfg_set_idle_threads(cfg, 100);
	clear_log();
	fuse_loop_cfg_set_max_threads(cfg, 5);

	/* value is set as requested */
	CHECK(name, cfg->max_threads == 5);
	CHECK(name, cfg->max_idle_threads == 100);
	/* a warning must have been logged */
	CHECK(name, last_log_level == FUSE_LOG_WARNING);
	CHECK(name, strstr(last_log_msg, "max_threads") != NULL);

	fuse_loop_cfg_destroy(cfg);
	PASS(name);
}

/*
 * set_idle(100) then set_max(100) → exact equality is valid, no warning.
 */
static void test_max_equals_idle(void)
{
	const char *name = "max_equals_idle";
	struct fuse_loop_config *cfg = fuse_loop_cfg_create();

	fuse_loop_cfg_set_idle_threads(cfg, 100);
	clear_log();
	fuse_loop_cfg_set_max_threads(cfg, 100);

	CHECK(name, cfg->max_threads == 100);
	CHECK(name, last_log_msg[0] == '\0'); /* no warning */

	fuse_loop_cfg_destroy(cfg);
	PASS(name);
}

/*
 * set_idle(100) then set_max(200) → valid, no warning.
 */
static void test_max_above_idle(void)
{
	const char *name = "max_above_idle";
	struct fuse_loop_config *cfg = fuse_loop_cfg_create();

	fuse_loop_cfg_set_idle_threads(cfg, 100);
	clear_log();
	fuse_loop_cfg_set_max_threads(cfg, 200);

	CHECK(name, cfg->max_threads == 200);
	CHECK(name, cfg->max_idle_threads == 100);
	CHECK(name, last_log_msg[0] == '\0'); /* no warning */

	fuse_loop_cfg_destroy(cfg);
	PASS(name);
}

/*
 * helper.c order: set_max(200) first, then set_idle(100).
 * Neither setter should warn when called in this order.
 */
static void test_helper_order_no_warning(void)
{
	const char *name = "helper_order_no_warning";
	struct fuse_loop_config *cfg = fuse_loop_cfg_create();

	clear_log();
	fuse_loop_cfg_set_max_threads(cfg, 200);
	fuse_loop_cfg_set_idle_threads(cfg, 100);

	CHECK(name, cfg->max_threads == 200);
	CHECK(name, cfg->max_idle_threads == 100);
	CHECK(name, last_log_msg[0] == '\0');

	fuse_loop_cfg_destroy(cfg);
	PASS(name);
}

/*
 * Reverse order: set_max(10) first, then set_idle(100).
 * Value is set but a warning is logged.
 */
static void test_warn_idle_above_max(void)
{
	const char *name = "warn_idle_above_max";
	struct fuse_loop_config *cfg = fuse_loop_cfg_create();

	fuse_loop_cfg_set_max_threads(cfg, 10);
	clear_log();
	fuse_loop_cfg_set_idle_threads(cfg, 100);

	CHECK(name, cfg->max_threads == 10);
	CHECK(name, cfg->max_idle_threads == 100);
	CHECK(name, last_log_level == FUSE_LOG_WARNING);
	CHECK(name, strstr(last_log_msg, "max_idle_threads") != NULL);

	fuse_loop_cfg_destroy(cfg);
	PASS(name);
}

/*
 * v1 legacy API: fuse_loop_cfg_convert with max_idle_threads=100.
 * In v1 semantics, max_idle_threads WAS the effective pool cap.
 * convert() must set max_threads = max_idle_threads to preserve that.
 */
static void test_v1_convert_sets_max_threads(void)
{
	const char *name = "v1_convert_sets_max_threads";
	struct fuse_loop_config *cfg = fuse_loop_cfg_create();
	struct fuse_loop_config_v1 v1 = {
		.max_idle_threads = 100,
		.clone_fd = 0,
	};

	clear_log();
	fuse_loop_cfg_convert(cfg, &v1);

	/* both must be 100 — v1 max_idle_threads was the effective cap */
	CHECK(name, cfg->max_idle_threads == 100);
	CHECK(name, cfg->max_threads == 100);
	/* convert sets max_threads first, so no ordering warning */
	CHECK(name, last_log_msg[0] == '\0');

	fuse_loop_cfg_destroy(cfg);
	PASS(name);
}

/*
 * v1 legacy API: default max_idle_threads=10 (old libfuse default).
 * convert() → max_idle=10, max_threads=10.
 */
static void test_v1_convert_default(void)
{
	const char *name = "v1_convert_default";
	struct fuse_loop_config *cfg = fuse_loop_cfg_create();
	struct fuse_loop_config_v1 v1 = {
		.max_idle_threads = 10,  /* old libfuse default */
		.clone_fd = 0,
	};

	clear_log();
	fuse_loop_cfg_convert(cfg, &v1);

	CHECK(name, cfg->max_idle_threads == 10);
	CHECK(name, cfg->max_threads == 10);
	CHECK(name, last_log_msg[0] == '\0');

	fuse_loop_cfg_destroy(cfg);
	PASS(name);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
	fuse_set_log_func(test_log_handler);

	test_max_threads_normal();
	test_max_threads_idle_disabled();
	test_max_threads_idle_zero();
	test_warn_max_below_idle();
	test_max_equals_idle();
	test_max_above_idle();
	test_helper_order_no_warning();
	test_warn_idle_above_max();
	test_v1_convert_sets_max_threads();
	test_v1_convert_default();

	printf("All loop_config tests passed.\n");
	return 0;
}
