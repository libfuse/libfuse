/*
 * Unit tests for the fuse.conf parser.
 *
 * read_conf() opens FUSE_CONF, which this test overrides with a relative
 * name so it can point the parser at a file of its own in a private
 * directory.  Blank, all-whitespace and comment-only lines are the ones
 * worth covering: they are what the line trimmer degenerates on, and the
 * sanitizer CI leg is where a pointer that walks off the front of the
 * buffer is caught.
 *
 * A trailing blank is spelled \x20 throughout: checkpatch rejects a literal
 * space before \n inside a string, and here it is the test input.
 */

#include "mount_util.h"	/* struct mount_flags, for fuser_conf.h */
#include "fuser_conf.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static const char *const progname = "test_fuser_conf";

static int fail(const char *test, const char *problem)
{
	fprintf(stderr, "FAIL: %s: %s\n", test, problem);
	return 1;
}

static int write_conf(const char *contents)
{
	FILE *fp;

	fp = fopen(FUSE_CONF, "w");
	if (fp == NULL) {
		perror("fopen");
		return -1;
	}
	if (fputs(contents, fp) == EOF) {
		perror("write");
		fclose(fp);
		return -1;
	}
	if (fclose(fp) == EOF) {
		perror("close");
		return -1;
	}
	return 0;
}

/*
 * Every line here is one the trimmer has to reduce to nothing, so the
 * parser must come out of it with its defaults untouched.
 */
static int test_blank_lines(void)
{
	const char *test = "blank_lines";
	const int old_mount_max = mount_max;

	user_allow_other = 0;

	if (write_conf("\n"
		       "\x20\n"
		       "\t\t\n"
		       "# just a comment\n"
		       "   # indented comment\t\x20\n"
		       "\x20\t\x20\n") == -1)
		return fail(test, "could not write the config file");

	read_conf(progname);

	if (user_allow_other)
		return fail(test, "user_allow_other set by a blank config");
	if (mount_max != old_mount_max)
		return fail(test, "mount_max changed by a blank config");

	printf("PASS: %s\n", test);
	return 0;
}

/* The trimming itself: surrounding whitespace and a trailing comment. */
static int test_trimmed_options(void)
{
	const char *test = "trimmed_options";

	user_allow_other = 0;
	mount_max = 1000;

	if (write_conf("\n"
		       "  user_allow_other\t\x20\n"
		       "\n"
		       "\tmount_max = 42   # and a comment\n"
		       "\n") == -1)
		return fail(test, "could not write the config file");

	read_conf(progname);

	if (!user_allow_other)
		return fail(test, "user_allow_other was not recognised");
	if (mount_max != 42)
		return fail(test, "mount_max was not recognised");

	printf("PASS: %s\n", test);
	return 0;
}

int main(void)
{
	char tempdir[] = "/tmp/test_fuser_conf.XXXXXX";
	int result = 1;

	if (mkdtemp(tempdir) == NULL) {
		perror("mkdtemp");
		return 1;
	}
	if (chdir(tempdir) == -1) {
		perror("chdir");
		goto out_rmdir;
	}

	if (test_blank_lines())
		goto out_unlink;
	if (test_trimmed_options())
		goto out_unlink;

	printf("All fuse.conf parser tests passed\n");
	result = 0;

out_unlink:
	if (unlink(FUSE_CONF) == -1 && errno != ENOENT) {
		perror("unlink");
		result = 1;
	}
	if (chdir("/") == -1) {
		perror("chdir");
		return 1;
	}
out_rmdir:
	if (rmdir(tempdir) == -1) {
		perror("rmdir");
		result = 1;
	}

	return result;
}
