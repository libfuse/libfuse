#include "util.h"
#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 17)

#include "fuse_i.h"
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>

static void print_conn_info(const char *prefix, struct fuse_conn_info *conn)
{
	printf("%s: want=0x%" PRIx32 " want_ext=0x%" PRIx64 "\n", prefix,
	       conn->want, conn->want_ext);
}

static void application_init_old_style(struct fuse_conn_info *conn)
{
	/* Simulate application init the old style */
	conn->want |= FUSE_CAP_ASYNC_READ;
	conn->want &= ~FUSE_CAP_SPLICE_READ;
}

static void application_init_new_style(struct fuse_conn_info *conn)
{
	/* Simulate application init the new style */
	fuse_set_feature_flag(conn, FUSE_CAP_ASYNC_READ);
	fuse_unset_feature_flag(conn, FUSE_CAP_SPLICE_READ);
}

static void test_fuse_fs_init(struct fuse_conn_info *conn, bool new_style)
{
	uint64_t want_ext_default = conn->want_ext;
	uint32_t want_default = fuse_lower_32_bits(conn->want_ext);
	int rc;

	/* High-level init */
	fuse_set_feature_flag(conn, FUSE_CAP_EXPORT_SUPPORT);

	conn->want = want_default;

	if (new_style)
		application_init_new_style(conn);
	else
		application_init_old_style(conn);

	rc = convert_to_conn_want_ext(conn, want_ext_default, want_default);
	assert(rc == 0);
}

static void test_do_init(struct fuse_conn_info *conn, bool new_style)
{
	/* Initial setup */
	conn->capable_ext = FUSE_CAP_SPLICE_READ | FUSE_CAP_SPLICE_WRITE |
			    FUSE_CAP_SPLICE_MOVE | FUSE_CAP_POSIX_LOCKS |
			    FUSE_CAP_FLOCK_LOCKS | FUSE_CAP_EXPORT_SUPPORT |
			    FUSE_CAP_ASYNC_READ;
	conn->capable = fuse_lower_32_bits(conn->capable_ext);
	conn->want_ext = conn->capable_ext;

	print_conn_info("Initial state", conn);

	uint64_t want_ext_default = conn->want_ext;
	uint32_t want_default = fuse_lower_32_bits(conn->want_ext);
	int rc;

	conn->want = want_default;
	conn->capable = fuse_lower_32_bits(conn->capable_ext);

	test_fuse_fs_init(conn, new_style);

	rc = convert_to_conn_want_ext(conn, want_ext_default, want_default);
	assert(rc == 0);

	/* Verify all expected flags are set */
	assert(!(conn->want_ext & FUSE_CAP_SPLICE_READ));
	assert(conn->want_ext & FUSE_CAP_SPLICE_WRITE);
	assert(conn->want_ext & FUSE_CAP_SPLICE_MOVE);
	assert(conn->want_ext & FUSE_CAP_POSIX_LOCKS);
	assert(conn->want_ext & FUSE_CAP_FLOCK_LOCKS);
	assert(conn->want_ext & FUSE_CAP_EXPORT_SUPPORT);
	assert(conn->want_ext & FUSE_CAP_ASYNC_READ);
	/* Verify no other flags are set */
	assert(conn->want_ext ==
	       (FUSE_CAP_SPLICE_WRITE | FUSE_CAP_SPLICE_MOVE |
		FUSE_CAP_POSIX_LOCKS | FUSE_CAP_FLOCK_LOCKS |
		FUSE_CAP_EXPORT_SUPPORT | FUSE_CAP_ASYNC_READ));

	print_conn_info("After init", conn);
}

static void test_want_conversion_basic(void)
{
	struct fuse_conn_info conn = { 0 };

	printf("\nTesting basic want conversion:\n");
	test_do_init(&conn, false);
	test_do_init(&conn, true);
	print_conn_info("After init", &conn);
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

	/* Initialize default values like in basic test */
	uint64_t want_ext_default_ll = conn.want_ext;
	uint32_t want_default_ll = fuse_lower_32_bits(want_ext_default_ll);

	/* Simulate application init modifying capabilities */
	conn.want_ext |= FUSE_CAP_ATOMIC_O_TRUNC; /* Add new capability */
	conn.want &= ~FUSE_CAP_SPLICE_READ; /* Remove a capability */

	rc = convert_to_conn_want_ext(&conn, want_ext_default_ll,
				      want_default_ll);
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

	uint64_t want_ext_default_ll = conn.want_ext;
	uint32_t want_default_ll = fuse_lower_32_bits(want_ext_default_ll);

	rc = convert_to_conn_want_ext(&conn, want_ext_default_ll,
				      want_default_ll);
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
