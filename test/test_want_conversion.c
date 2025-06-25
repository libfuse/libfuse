#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 17)

#include "util.h"
#include "fuse_i.h"
#include "fuse_lowlevel.h"
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <err.h>

static void print_conn_info(const char *prefix, struct fuse_conn_info *conn)
{
	struct fuse_session *se = container_of(conn, struct fuse_session, conn);

	printf("%s: want=0x%" PRIx32 " want_ext=0x%" PRIx64
		" want_default=0x%" PRIx32 " want_ext_default=0x%" PRIx64 "\n",
		prefix, conn->want, conn->want_ext, se->conn_want,
		se->conn_want_ext);
}

static void application_init_old_style(struct fuse_conn_info *conn)
{
	/* Simulate application init the old style */
	conn->want |= FUSE_CAP_ASYNC_READ;
	conn->want &= ~FUSE_CAP_SPLICE_READ;

	/*
	 * Also use new style API, as that might happen through
	 * fuse_apply_conn_info_opts()
	 */
	fuse_set_feature_flag(conn, FUSE_CAP_IOCTL_DIR);
}

static void application_init_new_style(struct fuse_conn_info *conn)
{
	/* Simulate application init the new style */
	fuse_set_feature_flag(conn, FUSE_CAP_ASYNC_READ);
	fuse_set_feature_flag(conn, FUSE_CAP_IOCTL_DIR);
	fuse_unset_feature_flag(conn, FUSE_CAP_SPLICE_READ);
}

static void test_fuse_fs_init(struct fuse_conn_info *conn, bool new_style)
{
	/* High-level init */
	fuse_set_feature_flag(conn, FUSE_CAP_EXPORT_SUPPORT);

	if (new_style)
		application_init_new_style(conn);
	else
		application_init_old_style(conn);
}

static void test_do_init(struct fuse_conn_info *conn, bool new_style)
{
	/* Initial setup */
	conn->capable_ext = FUSE_CAP_SPLICE_READ | FUSE_CAP_SPLICE_WRITE |
			    FUSE_CAP_SPLICE_MOVE | FUSE_CAP_POSIX_LOCKS |
			    FUSE_CAP_FLOCK_LOCKS | FUSE_CAP_EXPORT_SUPPORT |
			    FUSE_CAP_ASYNC_READ | FUSE_CAP_IOCTL_DIR;
	conn->capable = fuse_lower_32_bits(conn->capable_ext);

	fuse_set_feature_flag(conn, FUSE_CAP_SPLICE_READ |
				    FUSE_CAP_SPLICE_WRITE |
				    FUSE_CAP_SPLICE_MOVE);

	print_conn_info("Initial state", conn);

	int rc;

	test_fuse_fs_init(conn, new_style);
	print_conn_info("After init", conn);

	rc = fuse_convert_to_conn_want_ext(conn);
	assert(rc == 0);

	/* Verify all expected flags are set */
	assert(!(conn->want_ext & FUSE_CAP_SPLICE_READ));
	assert(conn->want_ext & FUSE_CAP_SPLICE_WRITE);
	assert(conn->want_ext & FUSE_CAP_SPLICE_MOVE);
	assert(conn->want_ext & FUSE_CAP_EXPORT_SUPPORT);
	assert(conn->want_ext & FUSE_CAP_ASYNC_READ);
	assert(conn->want_ext & FUSE_CAP_IOCTL_DIR);

	/* Verify no other flags are set */
	assert(conn->want_ext ==
	       (FUSE_CAP_SPLICE_WRITE | FUSE_CAP_SPLICE_MOVE |
		FUSE_CAP_EXPORT_SUPPORT | FUSE_CAP_ASYNC_READ |
		FUSE_CAP_IOCTL_DIR));

	print_conn_info("After init", conn);
}

static void test_want_conversion_basic(void)
{
	const struct fuse_lowlevel_ops ops = { 0 };
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	struct fuse_session *se;
	struct fuse_conn_info *conn;

	/* Add the program name to arg[0] */
	if (fuse_opt_add_arg(&args, "test_signals")) {
		fprintf(stderr, "Failed to add argument\n");
		errx(1, "Failed to add argument");
	}


	se = fuse_session_new(&args, &ops, sizeof(ops), NULL);
	assert(se);
	conn = &se->conn;
	printf("\nTesting basic want conversion, old style:\n");
	test_do_init(conn, false);
	fuse_session_destroy(se);

	se = fuse_session_new(&args, &ops, sizeof(ops), NULL);
	assert(se);
	conn = &se->conn;
	printf("\nTesting basic want conversion, new style:\n");
	test_do_init(conn, true);
	print_conn_info("After init", conn);
	fuse_session_destroy(se);

	fuse_opt_free_args(&args);

}

static void test_want_conversion_conflict(void)
{
	struct fuse_conn_info conn = { 0 };
	int rc;

	printf("\nTesting want conversion conflict:\n");

	/* Test conflicting values */
	/* Initialize like fuse_lowlevel.c does */
	conn.capable_ext = FUSE_CAP_SPLICE_READ | FUSE_CAP_SPLICE_WRITE |
			   FUSE_CAP_SPLICE_MOVE | FUSE_CAP_POSIX_LOCKS |
			   FUSE_CAP_FLOCK_LOCKS;
	conn.capable = fuse_lower_32_bits(conn.capable_ext);
	conn.want_ext = conn.capable_ext;
	conn.want = fuse_lower_32_bits(conn.want_ext);
	print_conn_info("Test conflict initial", &conn);

	/* Simulate application init modifying capabilities */
	conn.want_ext |= FUSE_CAP_ATOMIC_O_TRUNC; /* Add new capability */
	conn.want &= ~FUSE_CAP_SPLICE_READ; /* Remove a capability */

	rc = fuse_convert_to_conn_want_ext(&conn);
	assert(rc == -EINVAL);
	print_conn_info("Test conflict after", &conn);

	printf("Want conversion conflict test passed\n");
}

static void test_want_conversion_high_bits(void)
{
	struct fuse_conn_info conn = { 0 };
	int rc;

	printf("\nTesting want conversion high bits preservation:\n");

	/* Test high bits preservation */
	conn.want_ext = (1ULL << 33) | FUSE_CAP_ASYNC_READ;
	conn.want = fuse_lower_32_bits(conn.want_ext);
	print_conn_info("Test high bits initial", &conn);

	rc = fuse_convert_to_conn_want_ext(&conn);
	assert(rc == 0);
	assert(conn.want_ext == ((1ULL << 33) | FUSE_CAP_ASYNC_READ));
	print_conn_info("Test high bits after", &conn);

	printf("Want conversion high bits test passed\n");
}

int main(void)
{
	test_want_conversion_basic();
	test_want_conversion_conflict();
	test_want_conversion_high_bits();
	return 0;
}
