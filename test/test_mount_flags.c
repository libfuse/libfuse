/*
 * Unit tests for the 'safe' column of the shared mount_flags table.
 *
 * fusermount3 starts every unprivileged mount from MS_NOSUID | MS_NODEV and
 * lets -o options edit the flags from there, and mount.fuse3 re-applies the
 * same two flags for non-root callers.  Both decide what an unprivileged
 * caller may turn off by looking at 'safe', so an option that clears one of
 * those flags has to be marked unsafe.  No mount is needed; the table is
 * checked directly.
 */

#include "mount_util.h"
#include <stdio.h>
#include <string.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static const struct mount_flags *lookup(const char *opt)
{
	size_t i;

	for (i = 0; mount_flags[i].opt != NULL; i++)
		if (strcmp(mount_flags[i].opt, opt) == 0)
			return &mount_flags[i];

	return NULL;
}

static int fail(const char *test, const char *opt, const char *problem)
{
	fprintf(stderr, "FAIL: %s: option %s %s\n", test, opt, problem);
	return 1;
}

/*
 * An unprivileged caller must not be able to drop nosuid or nodev, so the
 * options that clear those flags have to be marked unsafe.
 */
static int test_hardening_opts_unsafe(void)
{
	static const char *const opts[] = { "suid", "dev" };
	const char *test = "hardening_opts_unsafe";
	size_t i;

	for (i = 0; i < ARRAY_SIZE(opts); i++) {
		const struct mount_flags *mf = lookup(opts[i]);

		if (!mf)
			return fail(test, opts[i], "is missing from the table");
		if (mf->on)
			return fail(test, opts[i], "no longer clears its flag");
		if (mf->safe)
			return fail(test, opts[i], "is marked safe");
	}

	printf("PASS: %s\n", test);
	return 0;
}

/*
 * The other direction stays available to everyone: asking for more
 * restrictions is always allowed.
 */
static int test_hardening_opts_grantable(void)
{
	static const char *const opts[] = { "nosuid", "nodev" };
	const char *test = "hardening_opts_grantable";
	size_t i;

	for (i = 0; i < ARRAY_SIZE(opts); i++) {
		const struct mount_flags *mf = lookup(opts[i]);

		if (!mf)
			return fail(test, opts[i], "is missing from the table");
		if (!mf->on)
			return fail(test, opts[i], "no longer sets its flag");
		if (!mf->safe)
			return fail(test, opts[i], "is marked unsafe");
	}

	printf("PASS: %s\n", test);
	return 0;
}

int main(void)
{
	if (test_hardening_opts_unsafe())
		return 1;
	if (test_hardening_opts_grantable())
		return 1;

	printf("All mount_flags tests passed\n");
	return 0;
}
