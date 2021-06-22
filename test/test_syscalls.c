#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <utime.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>

#ifndef ALLPERMS
# define ALLPERMS (S_ISUID|S_ISGID|S_ISVTX|S_IRWXU|S_IRWXG|S_IRWXO)/* 07777 */
#endif


static const char *basepath;
static const char *basepath_r;
static char testfile[1024];
static char testfile2[1024];
static char testdir[1024];
static char testdir2[1024];
static char testsock[1024];
static char subfile[1280];

static char testfile_r[1024];
static char testfile2_r[1024];
static char testdir_r[1024];
static char testdir2_r[1024];
static char subfile_r[1280];

static char testname[256];
static char testdata[] = "abcdefghijklmnopqrstuvwxyz";
static char testdata2[] = "1234567890-=qwertyuiop[]\asdfghjkl;'zxcvbnm,./";
static const char *testdir_files[] = { "f1", "f2", NULL};
static long seekdir_offsets[4];
static char zerodata[4096];
static int testdatalen = sizeof(testdata) - 1;
static int testdata2len = sizeof(testdata2) - 1;
static unsigned int testnum = 0;
static unsigned int select_test = 0;
static unsigned int skip_test = 0;
static unsigned int unlinked_test = 0;

#define MAX_ENTRIES 1024
#define MAX_TESTS 100

static struct test {
	int fd;
	struct stat stat;
} tests[MAX_TESTS];

static void test_perror(const char *func, const char *msg)
{
	fprintf(stderr, "%s %s() - %s: %s\n", testname, func, msg,
		strerror(errno));
}

static void test_error(const char *func, const char *msg, ...)
	__attribute__ ((format (printf, 2, 3)));

static void __start_test(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));

static void test_error(const char *func, const char *msg, ...)
{
	va_list ap;
	fprintf(stderr, "%s %s() - ", testname, func);
	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

static int is_dot_or_dotdot(const char *name) {
    return name[0] == '.' &&
           (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

static void success(void)
{
	fprintf(stderr, "%s OK\n", testname);
}

#define this_test (&tests[testnum-1])
#define next_test (&tests[testnum])

static void __start_test(const char *fmt, ...)
{
	unsigned int n;
	va_list ap;
	n = sprintf(testname, "%3i [", testnum);
	va_start(ap, fmt);
	n += vsprintf(testname + n, fmt, ap);
	va_end(ap);
	sprintf(testname + n, "]");
	// Use dedicated testfile per test
	sprintf(testfile, "%s/testfile.%d", basepath, testnum);
	sprintf(testfile_r, "%s/testfile.%d", basepath_r, testnum);
	if (testnum > MAX_TESTS) {
		fprintf(stderr, "%s - too many tests\n", testname);
		exit(1);
	}
	this_test->fd = -1;
}

#define start_test(msg, args...) { \
	testnum++; \
	if ((select_test && testnum != select_test) || \
	    (testnum == skip_test)) { \
		return 0; \
	} \
	__start_test(msg, ##args);		\
}

#define PERROR(msg) test_perror(__FUNCTION__, msg)
#define ERROR(msg, args...) test_error(__FUNCTION__, msg, ##args)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static int st_check_size(struct stat *st, int len)
{
	if (st->st_size != len) {
		ERROR("length %u instead of %u", (int) st->st_size,
		      (int) len);
		return -1;
	}
	return 0;
}

static int check_size(const char *path, int len)
{
	struct stat stbuf;
	int res = stat(path, &stbuf);
	if (res == -1) {
		PERROR("stat");
		return -1;
	}
	return st_check_size(&stbuf, len);
}

static int check_testfile_size(const char *path, int len)
{
	this_test->stat.st_size = len;
	return check_size(path, len);
}

static int st_check_type(struct stat *st, mode_t type)
{
	if ((st->st_mode & S_IFMT) != type) {
		ERROR("type 0%o instead of 0%o", st->st_mode & S_IFMT, type);
		return -1;
	}
	return 0;
}

static int check_type(const char *path, mode_t type)
{
	struct stat stbuf;
	int res = lstat(path, &stbuf);
	if (res == -1) {
		PERROR("lstat");
		return -1;
	}
	return st_check_type(&stbuf, type);
}

static int st_check_mode(struct stat *st, mode_t mode)
{
	if ((st->st_mode & ALLPERMS) != mode) {
		ERROR("mode 0%o instead of 0%o", st->st_mode & ALLPERMS,
		      mode);
		return -1;
	}
	return 0;
}

static int check_mode(const char *path, mode_t mode)
{
	struct stat stbuf;
	int res = lstat(path, &stbuf);
	if (res == -1) {
		PERROR("lstat");
		return -1;
	}
	return st_check_mode(&stbuf, mode);
}

static int check_testfile_mode(const char *path, mode_t mode)
{
	this_test->stat.st_mode &= ~ALLPERMS;
	this_test->stat.st_mode |= mode;
	return check_mode(path, mode);
}

static int check_times(const char *path, time_t atime, time_t mtime)
{
	int err = 0;
	struct stat stbuf;
	int res = lstat(path, &stbuf);
	if (res == -1) {
		PERROR("lstat");
		return -1;
	}
	if (stbuf.st_atime != atime) {
		ERROR("atime %li instead of %li", stbuf.st_atime, atime);
		err--;
	}
	if (stbuf.st_mtime != mtime) {
		ERROR("mtime %li instead of %li", stbuf.st_mtime, mtime);
		err--;
	}
	if (err)
		return -1;

	return 0;
}

#if 0
static int fcheck_times(int fd, time_t atime, time_t mtime)
{
	int err = 0;
	struct stat stbuf;
	int res = fstat(fd, &stbuf);
	if (res == -1) {
		PERROR("fstat");
		return -1;
	}
	if (stbuf.st_atime != atime) {
		ERROR("atime %li instead of %li", stbuf.st_atime, atime);
		err--;
	}
	if (stbuf.st_mtime != mtime) {
		ERROR("mtime %li instead of %li", stbuf.st_mtime, mtime);
		err--;
	}
	if (err)
		return -1;

	return 0;
}
#endif

static int st_check_nlink(struct stat *st, nlink_t nlink)
{
	if (st->st_nlink != nlink) {
		ERROR("nlink %li instead of %li", (long) st->st_nlink,
		      (long) nlink);
		return -1;
	}
	return 0;
}

static int check_nlink(const char *path, nlink_t nlink)
{
	struct stat stbuf;
	int res = lstat(path, &stbuf);
	if (res == -1) {
		PERROR("lstat");
		return -1;
	}
	return st_check_nlink(&stbuf, nlink);
}

static int fcheck_stat(int fd, int flags, struct stat *st)
{
	struct stat stbuf;
	int res = fstat(fd, &stbuf);
	if (res == -1) {
		if (flags & O_PATH) {
			// With O_PATH fd, the server does not have to keep
			// the inode alive so FUSE inode may be stale or bad
			if (errno == ESTALE || errno == EIO || errno == ENOENT)
				return 0;
		}
		PERROR("fstat");
		return -1;
	}

	int err = 0;
	err += st_check_type(&stbuf, st->st_mode & S_IFMT);
	err += st_check_mode(&stbuf, st->st_mode & ALLPERMS);
	err += st_check_size(&stbuf, st->st_size);
	err += st_check_nlink(&stbuf, st->st_nlink);

	return err;
}

static int check_nonexist(const char *path)
{
	struct stat stbuf;
	int res = lstat(path, &stbuf);
	if (res == 0) {
		ERROR("file should not exist");
		return -1;
	}
	if (errno != ENOENT) {
		ERROR("file should not exist: %s", strerror(errno));
		return -1;
	}
	return 0;
}

static int check_buffer(const char *buf, const char *data, unsigned len)
{
	if (memcmp(buf, data, len) != 0) {
		ERROR("data mismatch");
		return -1;
	}
	return 0;
}

static int check_data(const char *path, const char *data, int offset,
		      unsigned len)
{
	char buf[4096];
	int res;
	int fd = open(path, O_RDONLY);
	if (fd == -1) {
		PERROR("open");
		return -1;
	}
	if (lseek(fd, offset, SEEK_SET) == (off_t) -1) {
		PERROR("lseek");
		close(fd);
		return -1;
	}
	while (len) {
		int rdlen = len < sizeof(buf) ? len : sizeof(buf);
		res = read(fd, buf, rdlen);
		if (res == -1) {
			PERROR("read");
			close(fd);
			return -1;
		}
		if (res != rdlen) {
			ERROR("short read: %u instead of %u", res, rdlen);
			close(fd);
			return -1;
		}
		if (check_buffer(buf, data, rdlen) != 0) {
			close(fd);
			return -1;
		}
		data += rdlen;
		len -= rdlen;
	}
	res = close(fd);
	if (res == -1) {
		PERROR("close");
		return -1;
	}
	return 0;
}

static int fcheck_data(int fd, const char *data, int offset,
		       unsigned len)
{
	char buf[4096];
	int res;
	if (lseek(fd, offset, SEEK_SET) == (off_t) -1) {
		PERROR("lseek");
		return -1;
	}
	while (len) {
		int rdlen = len < sizeof(buf) ? len : sizeof(buf);
		res = read(fd, buf, rdlen);
		if (res == -1) {
			PERROR("read");
			return -1;
		}
		if (res != rdlen) {
			ERROR("short read: %u instead of %u", res, rdlen);
			return -1;
		}
		if (check_buffer(buf, data, rdlen) != 0) {
			return -1;
		}
		data += rdlen;
		len -= rdlen;
	}
	return 0;
}

static int check_dir_contents(const char *path, const char **contents)
{
	int i;
	int res;
	int err = 0;
	int found[MAX_ENTRIES];
	const char *cont[MAX_ENTRIES];
	DIR *dp;

	for (i = 0; contents[i]; i++) {
		assert(i < MAX_ENTRIES - 3);
		found[i] = 0;
		cont[i] = contents[i];
	}
	cont[i] = NULL;

	dp = opendir(path);
	if (dp == NULL) {
		PERROR("opendir");
		return -1;
	}
	memset(found, 0, sizeof(found));
	while(1) {
		struct dirent *de;
		errno = 0;
		de = readdir(dp);
		if (de == NULL) {
			if (errno) {
				PERROR("readdir");
				closedir(dp);
				return -1;
			}
			break;
		}
		if (is_dot_or_dotdot(de->d_name))
			continue;
		for (i = 0; cont[i] != NULL; i++) {
			assert(i < MAX_ENTRIES);
			if (strcmp(cont[i], de->d_name) == 0) {
				if (found[i]) {
					ERROR("duplicate entry <%s>",
					      de->d_name);
					err--;
				} else
					found[i] = 1;
				break;
			}
		}
		if (!cont[i]) {
			ERROR("unexpected entry <%s>", de->d_name);
			err --;
		}
	}
	for (i = 0; cont[i] != NULL; i++) {
		if (!found[i]) {
			ERROR("missing entry <%s>", cont[i]);
			err--;
		}
	}
	res = closedir(dp);
	if (res == -1) {
		PERROR("closedir");
		return -1;
	}
	if (err)
		return -1;

	return 0;
}

static int create_file(const char *path, const char *data, int len)
{
	int res;
	int fd;

	unlink(path);
	fd = creat(path, 0644);
	if (fd == -1) {
		PERROR("creat");
		return -1;
	}
	if (len) {
		res = write(fd, data, len);
		if (res == -1) {
			PERROR("write");
			close(fd);
			return -1;
		}
		if (res != len) {
			ERROR("write is short: %u instead of %u", res, len);
			close(fd);
			return -1;
		}
	}
	res = close(fd);
	if (res == -1) {
		PERROR("close");
		return -1;
	}
	res = check_type(path, S_IFREG);
	if (res == -1)
		return -1;
	res = check_mode(path, 0644);
	if (res == -1)
		return -1;
	res = check_nlink(path, 1);
	if (res == -1)
		return -1;
	res = check_size(path, len);
	if (res == -1)
		return -1;

	if (len) {
		res = check_data(path, data, 0, len);
		if (res == -1)
			return -1;
	}

	return 0;
}

static int create_path_fd(const char *path, const char *data, int len)
{
	int path_fd;
	int res;

	res = create_file(path, data, len);
	if (res == -1)
		return -1;

	path_fd = open(path, O_PATH);
	if (path_fd == -1)
		PERROR("open(O_PATH)");

	return path_fd;
}

// Can be called once per test
static int create_testfile(const char *path, const char *data, int len)
{
	struct test *t = this_test;
	struct stat *st = &t->stat;
	int res, fd;

	if (t->fd > 0) {
		ERROR("testfile already created");
		return -1;
	}

	fd = create_path_fd(path, data, len);
	if (fd == -1)
		return -1;

	t->fd = fd;

	res = fstat(fd, st);
	if (res == -1) {
		PERROR("fstat");
		return -1;
	}

	return 0;
}

static int check_unlinked_testfile(int fd)
{
	struct stat *st = &this_test->stat;

	st->st_nlink = 0;
	return fcheck_stat(fd, O_PATH, st);
}

// Check recorded testfiles after all tests completed
static int check_unlinked_testfiles(void)
{
	int fd;
	int res, err = 0;
	int num = testnum;

	if (!unlinked_test)
		return 0;

	testnum = 0;
	while (testnum < num) {
		fd = next_test->fd;
		start_test("check_unlinked_testfile");
		if (fd == -1)
			continue;

		err += check_unlinked_testfile(fd);
		res = close(fd);
		if (res == -1) {
			PERROR("close(test_fd)");
			err--;
		}
	}

	if (err) {
		fprintf(stderr, "%i unlinked testfile checks failed\n", -err);
		return 1;
	}

	return err;
}

static int cleanup_dir(const char *path, const char **dir_files, int quiet)
{
	int i;
	int err = 0;

	for (i = 0; dir_files[i]; i++) {
		int res;
		char fpath[1280];
		sprintf(fpath, "%s/%s", path, dir_files[i]);
		res = unlink(fpath);
		if (res == -1 && !quiet) {
			PERROR("unlink");
			err --;
		}
	}
	if (err)
		return -1;

	return 0;
}

static int create_dir(const char *path, const char **dir_files)
{
	int res;
	int i;

	rmdir(path);
	res = mkdir(path, 0755);
	if (res == -1) {
		PERROR("mkdir");
		return -1;
	}
	res = check_type(path, S_IFDIR);
	if (res == -1)
		return -1;
	res = check_mode(path, 0755);
	if (res == -1)
		return -1;

	for (i = 0; dir_files[i]; i++) {
		char fpath[1280];
		sprintf(fpath, "%s/%s", path, dir_files[i]);
		res = create_file(fpath, "", 0);
		if (res == -1) {
			cleanup_dir(path, dir_files, 1);
			return -1;
		}
	}
	res = check_dir_contents(path, dir_files);
	if (res == -1) {
		cleanup_dir(path, dir_files, 1);
		return -1;
	}

	return 0;
}

static int test_truncate(int len)
{
	const char *data = testdata;
	int datalen = testdatalen;
	int res;

	start_test("truncate(%u)", (int) len);
	res = create_testfile(testfile, data, datalen);
	if (res == -1)
		return -1;

	res = truncate(testfile, len);
	if (res == -1) {
		PERROR("truncate");
		return -1;
	}
	res = check_testfile_size(testfile, len);
	if (res == -1)
		return -1;

	if (len > 0) {
		if (len <= datalen) {
			res = check_data(testfile, data, 0, len);
			if (res == -1)
				return -1;
		} else {
			res = check_data(testfile, data, 0, datalen);
			if (res == -1)
				return -1;
			res = check_data(testfile, zerodata, datalen,
					 len - datalen);
			if (res == -1)
				return -1;
		}
	}
	res = unlink(testfile);
	if (res == -1) {
		PERROR("unlink");
		return -1;
	}
	res = check_nonexist(testfile);
	if (res == -1)
		return -1;

	success();
	return 0;
}

static int test_ftruncate(int len, int mode)
{
	const char *data = testdata;
	int datalen = testdatalen;
	int res;
	int fd;

	start_test("ftruncate(%u) mode: 0%03o", len, mode);
	res = create_testfile(testfile, data, datalen);
	if (res == -1)
		return -1;

	fd = open(testfile, O_WRONLY);
	if (fd == -1) {
		PERROR("open");
		return -1;
	}

	res = fchmod(fd, mode);
	if (res == -1) {
		PERROR("fchmod");
		close(fd);
		return -1;
	}
	res = check_testfile_mode(testfile, mode);
	if (res == -1) {
		close(fd);
		return -1;
	}
	res = ftruncate(fd, len);
	if (res == -1) {
		PERROR("ftruncate");
		close(fd);
		return -1;
	}
	close(fd);
	res = check_testfile_size(testfile, len);
	if (res == -1)
		return -1;

	if (len > 0) {
		if (len <= datalen) {
			res = check_data(testfile, data, 0, len);
			if (res == -1)
				return -1;
		} else {
			res = check_data(testfile, data, 0, datalen);
			if (res == -1)
				return -1;
			res = check_data(testfile, zerodata, datalen,
					 len - datalen);
			if (res == -1)
				return -1;
		}
	}
	res = unlink(testfile);
	if (res == -1) {
		PERROR("unlink");
		return -1;
	}
	res = check_nonexist(testfile);
	if (res == -1)
		return -1;

	success();
	return 0;
}

static int test_seekdir(void)
{
	int i;
	int res;
	DIR *dp;
	struct dirent *de;

	start_test("seekdir");
	res = create_dir(testdir, testdir_files);
	if (res == -1)
		return res;

	dp = opendir(testdir);
	if (dp == NULL) {
		PERROR("opendir");
		return -1;
	}

	/* Remember dir offsets */
	for (i = 0; i < ARRAY_SIZE(seekdir_offsets); i++) {
		seekdir_offsets[i] = telldir(dp);
		errno = 0;
		de = readdir(dp);
		if (de == NULL) {
			if (errno) {
				PERROR("readdir");
				goto fail;
			}
			break;
		}
	}

	/* Walk until the end of directory */
	while (de)
		de = readdir(dp);

	/* Start from the last valid dir offset and seek backwards */
	for (i--; i >= 0; i--) {
		seekdir(dp, seekdir_offsets[i]);
		de = readdir(dp);
		if (de == NULL) {
			ERROR("Unexpected end of directory after seekdir()");
			goto fail;
		}
	}

	closedir(dp);
	res = cleanup_dir(testdir, testdir_files, 0);
	if (!res)
		success();
	return res;
fail:
	closedir(dp);
	cleanup_dir(testdir, testdir_files, 1);
	return -1;
}

#ifdef HAVE_COPY_FILE_RANGE
static int test_copy_file_range(void)
{
	const char *data = testdata;
	int datalen = testdatalen;
	int err = 0;
	int res;
	int fd_in, fd_out;
	off_t pos_in = 0, pos_out = 0;

	start_test("copy_file_range");
	unlink(testfile);
	fd_in = open(testfile, O_CREAT | O_RDWR, 0644);
	if (fd_in == -1) {
		PERROR("creat");
		return -1;
	}
	res = write(fd_in, data, datalen);
	if (res == -1) {
		PERROR("write");
		close(fd_in);
		return -1;
	}
	if (res != datalen) {
		ERROR("write is short: %u instead of %u", res, datalen);
		close(fd_in);
		return -1;
	}

	unlink(testfile2);
	fd_out = creat(testfile2, 0644);
	if (fd_out == -1) {
		PERROR("creat");
		close(fd_in);
		return -1;
	}
	res = copy_file_range(fd_in, &pos_in, fd_out, &pos_out, datalen, 0);
	if (res == -1) {
		PERROR("copy_file_range");
		close(fd_in);
		close(fd_out);
		return -1;
	}
	if (res != datalen) {
		ERROR("copy is short: %u instead of %u", res, datalen);
		close(fd_in);
		close(fd_out);
		return -1;
	}

	res = close(fd_in);
	if (res == -1) {
		PERROR("close");
		close(fd_out);
		return -1;
	}
	res = close(fd_out);
	if (res == -1) {
		PERROR("close");
		return -1;
	}

	err = check_data(testfile2, data, 0, datalen);

	res = unlink(testfile);
	if (res == -1) {
		PERROR("unlink");
		return -1;
	}
	res = check_nonexist(testfile);
	if (res == -1)
		return -1;
	if (err)
		return -1;

	res = unlink(testfile2);
	if (res == -1) {
		PERROR("unlink");
		return -1;
	}
	res = check_nonexist(testfile2);
	if (res == -1)
		return -1;
	if (err)
		return -1;

	success();
	return 0;
}
#else
static int test_copy_file_range(void)
{
	return 0;
}
#endif

static int test_utime(void)
{
	struct utimbuf utm;
	time_t atime = 987631200;
	time_t mtime = 123116400;
	int res;

	start_test("utime");
	res = create_testfile(testfile, NULL, 0);
	if (res == -1)
		return -1;

	utm.actime = atime;
	utm.modtime = mtime;
	res = utime(testfile, &utm);
	if (res == -1) {
		PERROR("utime");
		return -1;
	}
	res = check_times(testfile, atime, mtime);
	if (res == -1) {
		return -1;
	}
	res = unlink(testfile);
	if (res == -1) {
		PERROR("unlink");
		return -1;
	}
	res = check_nonexist(testfile);
	if (res == -1)
		return -1;

	success();
	return 0;
}

static int test_create(void)
{
	const char *data = testdata;
	int datalen = testdatalen;
	int err = 0;
	int res;
	int fd;

	start_test("create");
	unlink(testfile);
	fd = creat(testfile, 0644);
	if (fd == -1) {
		PERROR("creat");
		return -1;
	}
	res = write(fd, data, datalen);
	if (res == -1) {
		PERROR("write");
		close(fd);
		return -1;
	}
	if (res != datalen) {
		ERROR("write is short: %u instead of %u", res, datalen);
		close(fd);
		return -1;
	}
	res = close(fd);
	if (res == -1) {
		PERROR("close");
		return -1;
	}
	res = check_type(testfile, S_IFREG);
	if (res == -1)
		return -1;
	err += check_mode(testfile, 0644);
	err += check_nlink(testfile, 1);
	err += check_size(testfile, datalen);
	err += check_data(testfile, data, 0, datalen);
	res = unlink(testfile);
	if (res == -1) {
		PERROR("unlink");
		return -1;
	}
	res = check_nonexist(testfile);
	if (res == -1)
		return -1;
	if (err)
		return -1;

	success();
	return 0;
}

static int test_create_unlink(void)
{
	const char *data = testdata;
	int datalen = testdatalen;
	int err = 0;
	int res;
	int fd;

	start_test("create+unlink");
	unlink(testfile);
	fd = open(testfile, O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd == -1) {
		PERROR("creat");
		return -1;
	}
	res = unlink(testfile);
	if (res == -1) {
		PERROR("unlink");
		close(fd);
		return -1;
	}
	res = check_nonexist(testfile);
	if (res == -1) {
		close(fd);
		return -1;
	}
	res = write(fd, data, datalen);
	if (res == -1) {
		PERROR("write");
		close(fd);
		return -1;
	}
	if (res != datalen) {
		ERROR("write is short: %u instead of %u", res, datalen);
		close(fd);
		return -1;
	}
	struct stat st = {
		.st_mode = S_IFREG | 0644,
		.st_size = datalen,
	};
	err = fcheck_stat(fd, O_RDWR, &st);
	err += fcheck_data(fd, data, 0, datalen);
	res = close(fd);
	if (res == -1) {
		PERROR("close");
		err--;
	}
	if (err)
		return -1;

	success();
	return 0;
}

#ifndef __FreeBSD__
static int test_mknod(void)
{
	int err = 0;
	int res;

	start_test("mknod");
	unlink(testfile);
	res = mknod(testfile, 0644, 0);
	if (res == -1) {
		PERROR("mknod");
		return -1;
	}
	res = check_type(testfile, S_IFREG);
	if (res == -1)
		return -1;
	err += check_mode(testfile, 0644);
	err += check_nlink(testfile, 1);
	err += check_size(testfile, 0);
	res = unlink(testfile);
	if (res == -1) {
		PERROR("unlink");
		return -1;
	}
	res = check_nonexist(testfile);
	if (res == -1)
		return -1;
	if (err)
		return -1;

	success();
	return 0;
}
#endif

#define test_open(exist, flags, mode)  do_test_open(exist, flags, #flags, mode)

static int do_test_open(int exist, int flags, const char *flags_str, int mode)
{
	char buf[4096];
	const char *data = testdata;
	int datalen = testdatalen;
	unsigned currlen = 0;
	int err = 0;
	int res;
	int fd;
	off_t off;

	start_test("open(%s, %s, 0%03o)", exist ? "+" : "-", flags_str, mode);
	unlink(testfile);
	if (exist) {
		res = create_file(testfile_r, testdata2, testdata2len);
		if (res == -1)
			return -1;

		currlen = testdata2len;
	}

	fd = open(testfile, flags, mode);
	if ((flags & O_CREAT) && (flags & O_EXCL) && exist) {
		if (fd != -1) {
			ERROR("open should have failed");
			close(fd);
			return -1;
		} else if (errno == EEXIST)
			goto succ;
	}
	if (!(flags & O_CREAT) && !exist) {
		if (fd != -1) {
			ERROR("open should have failed");
			close(fd);
			return -1;
		} else if (errno == ENOENT)
			goto succ;
	}
	if (fd == -1) {
		PERROR("open");
		return -1;
	}

	if (flags & O_TRUNC)
		currlen = 0;

	err += check_type(testfile, S_IFREG);
	if (exist)
		err += check_mode(testfile, 0644);
	else
		err += check_mode(testfile, mode);
	err += check_nlink(testfile, 1);
	err += check_size(testfile, currlen);
	if (exist && !(flags & O_TRUNC) && (mode & S_IRUSR))
		err += check_data(testfile, testdata2, 0, testdata2len);

	res = write(fd, data, datalen);
	if ((flags & O_ACCMODE) != O_RDONLY) {
		if (res == -1) {
			PERROR("write");
			err --;
		} else if (res != datalen) {
			ERROR("write is short: %u instead of %u", res, datalen);
			err --;
		} else {
			if (datalen > (int) currlen)
				currlen = datalen;

			err += check_size(testfile, currlen);

			if (mode & S_IRUSR) {
				err += check_data(testfile, data, 0, datalen);
				if (exist && !(flags & O_TRUNC) &&
				    testdata2len > datalen)
					err += check_data(testfile,
							  testdata2 + datalen,
							  datalen,
							  testdata2len - datalen);
			}
		}
	} else {
		if (res != -1) {
			ERROR("write should have failed");
			err --;
		} else if (errno != EBADF) {
			PERROR("write");
			err --;
		}
	}
	off = lseek(fd, SEEK_SET, 0);
	if (off == (off_t) -1) {
		PERROR("lseek");
		err--;
	} else if (off != 0) {
		ERROR("offset should have returned 0");
		err --;
	}
	res = read(fd, buf, sizeof(buf));
	if ((flags & O_ACCMODE) != O_WRONLY) {
		if (res == -1) {
			PERROR("read");
			err--;
		} else {
			int readsize =
				currlen < sizeof(buf) ? currlen : sizeof(buf);
			if (res != readsize) {
				ERROR("read is short: %i instead of %u",
				      res, readsize);
				err--;
			} else {
				if ((flags & O_ACCMODE) != O_RDONLY) {
					err += check_buffer(buf, data, datalen);
					if (exist && !(flags & O_TRUNC) &&
					    testdata2len > datalen)
						err += check_buffer(buf + datalen,
								    testdata2 + datalen,
								    testdata2len - datalen);
				} else if (exist)
					err += check_buffer(buf, testdata2,
							    testdata2len);
			}
		}
	} else {
		if (res != -1) {
			ERROR("read should have failed");
			err --;
		} else if (errno != EBADF) {
			PERROR("read");
			err --;
		}
	}

	res = close(fd);
	if (res == -1) {
		PERROR("close");
		return -1;
	}
	res = unlink(testfile);
	if (res == -1) {
		PERROR("unlink");
		return -1;
	}
	res = check_nonexist(testfile);
	if (res == -1)
		return -1;
	res = check_nonexist(testfile_r);
	if (res == -1)
		return -1;
	if (err)
		return -1;

succ:
	success();
	return 0;
}

#define test_open_acc(flags, mode, err)	 \
	do_test_open_acc(flags, #flags, mode, err)

static int do_test_open_acc(int flags, const char *flags_str, int mode, int err)
{
	const char *data = testdata;
	int datalen = testdatalen;
	int res;
	int fd;

	start_test("open_acc(%s) mode: 0%03o message: '%s'", flags_str, mode,
		   strerror(err));
	unlink(testfile);
	res = create_testfile(testfile, data, datalen);
	if (res == -1)
		return -1;

	res = chmod(testfile, mode);
	if (res == -1) {
		PERROR("chmod");
		return -1;
	}

	res = check_testfile_mode(testfile, mode);
	if (res == -1)
		return -1;

	fd = open(testfile, flags);
	if (fd == -1) {
		if (err != errno) {
			PERROR("open");
			return -1;
		}
	} else {
		if (err) {
			ERROR("open should have failed");
			close(fd);
			return -1;
		}
		close(fd);
	}

	res = unlink(testfile);
	if (res == -1) {
		PERROR("unlink");
		return -1;
	}
	res = check_nonexist(testfile);
	if (res == -1)
		return -1;
	res = check_nonexist(testfile_r);
	if (res == -1)
		return -1;

	success();
	return 0;
}

static int test_symlink(void)
{
	char buf[1024];
	const char *data = testdata;
	int datalen = testdatalen;
	int linklen = strlen(testfile);
	int err = 0;
	int res;

	start_test("symlink");
	res = create_testfile(testfile, data, datalen);
	if (res == -1)
		return -1;

	unlink(testfile2);
	res = symlink(testfile, testfile2);
	if (res == -1) {
		PERROR("symlink");
		return -1;
	}
	res = check_type(testfile2, S_IFLNK);
	if (res == -1)
		return -1;
	err += check_mode(testfile2, 0777);
	err += check_nlink(testfile2, 1);
	res = readlink(testfile2, buf, sizeof(buf));
	if (res == -1) {
		PERROR("readlink");
		err--;
	}
	if (res != linklen) {
		ERROR("short readlink: %u instead of %u", res, linklen);
		err--;
	}
	if (memcmp(buf, testfile, linklen) != 0) {
		ERROR("link mismatch");
		err--;
	}
	err += check_size(testfile2, datalen);
	err += check_data(testfile2, data, 0, datalen);
	res = unlink(testfile2);
	if (res == -1) {
		PERROR("unlink");
		return -1;
	}
	res = check_nonexist(testfile2);
	if (res == -1)
		return -1;
	if (err)
		return -1;

	res = unlink(testfile);
	if (res == -1) {
		PERROR("unlink");
		return -1;
	}
	res = check_nonexist(testfile);
	if (res == -1)
		return -1;

	success();
	return 0;
}

static int test_link(void)
{
	const char *data = testdata;
	int datalen = testdatalen;
	int err = 0;
	int res;

	start_test("link");
	res = create_testfile(testfile, data, datalen);
	if (res == -1)
		return -1;

	unlink(testfile2);
	res = link(testfile, testfile2);
	if (res == -1) {
		PERROR("link");
		return -1;
	}
	res = check_type(testfile2, S_IFREG);
	if (res == -1)
		return -1;
	err += check_mode(testfile2, 0644);
	err += check_nlink(testfile2, 2);
	err += check_size(testfile2, datalen);
	err += check_data(testfile2, data, 0, datalen);
	res = unlink(testfile);
	if (res == -1) {
		PERROR("unlink");
		return -1;
	}
	res = check_nonexist(testfile);
	if (res == -1)
		return -1;

	err += check_nlink(testfile2, 1);
	res = unlink(testfile2);
	if (res == -1) {
		PERROR("unlink");
		return -1;
	}
	res = check_nonexist(testfile2);
	if (res == -1)
		return -1;
	if (err)
		return -1;

	success();
	return 0;
}

static int test_link2(void)
{
	const char *data = testdata;
	int datalen = testdatalen;
	int err = 0;
	int res;

	start_test("link-unlink-link");
	res = create_testfile(testfile, data, datalen);
	if (res == -1)
		return -1;

	unlink(testfile2);
	res = link(testfile, testfile2);
	if (res == -1) {
		PERROR("link");
		return -1;
	}
	res = unlink(testfile);
	if (res == -1) {
		PERROR("unlink");
		return -1;
	}
	res = check_nonexist(testfile);
	if (res == -1)
		return -1;
	res = link(testfile2, testfile);
	if (res == -1) {
		PERROR("link");
	}
	res = check_type(testfile, S_IFREG);
	if (res == -1)
		return -1;
	err += check_mode(testfile, 0644);
	err += check_nlink(testfile, 2);
	err += check_size(testfile, datalen);
	err += check_data(testfile, data, 0, datalen);

	res = unlink(testfile2);
	if (res == -1) {
		PERROR("unlink");
		return -1;
	}
	err += check_nlink(testfile, 1);
	res = unlink(testfile);
	if (res == -1) {
		PERROR("unlink");
		return -1;
	}
	res = check_nonexist(testfile);
	if (res == -1)
		return -1;
	if (err)
		return -1;

	success();
	return 0;
}

static int test_rename_file(void)
{
	const char *data = testdata;
	int datalen = testdatalen;
	int err = 0;
	int res;

	start_test("rename file");
	res = create_testfile(testfile, data, datalen);
	if (res == -1)
		return -1;

	unlink(testfile2);
	res = rename(testfile, testfile2);
	if (res == -1) {
		PERROR("rename");
		return -1;
	}
	res = check_nonexist(testfile);
	if (res == -1)
		return -1;
	res = check_type(testfile2, S_IFREG);
	if (res == -1)
		return -1;
	err += check_mode(testfile2, 0644);
	err += check_nlink(testfile2, 1);
	err += check_size(testfile2, datalen);
	err += check_data(testfile2, data, 0, datalen);
	res = unlink(testfile2);
	if (res == -1) {
		PERROR("unlink");
		return -1;
	}
	res = check_nonexist(testfile2);
	if (res == -1)
		return -1;
	if (err)
		return -1;

	success();
	return 0;
}

static int test_rename_dir(void)
{
	int err = 0;
	int res;

	start_test("rename dir");
	res = create_dir(testdir, testdir_files);
	if (res == -1)
		return -1;

	rmdir(testdir2);
	res = rename(testdir, testdir2);
	if (res == -1) {
		PERROR("rename");
		cleanup_dir(testdir, testdir_files, 1);
		return -1;
	}
	res = check_nonexist(testdir);
	if (res == -1) {
		cleanup_dir(testdir, testdir_files, 1);
		return -1;
	}
	res = check_type(testdir2, S_IFDIR);
	if (res == -1) {
		cleanup_dir(testdir2, testdir_files, 1);
		return -1;
	}
	err += check_mode(testdir2, 0755);
	err += check_dir_contents(testdir2, testdir_files);
	err += cleanup_dir(testdir2, testdir_files, 0);
	res = rmdir(testdir2);
	if (res == -1) {
		PERROR("rmdir");
		return -1;
	}
	res = check_nonexist(testdir2);
	if (res == -1)
		return -1;
	if (err)
		return -1;

	success();
	return 0;
}

static int test_rename_dir_loop(void)
{
#define PATH(p)		(snprintf(path, sizeof path, "%s/%s", testdir, p), path)
#define PATH2(p)	(snprintf(path2, sizeof path2, "%s/%s", testdir, p), path2)

	char path[1280], path2[1280];
	int err = 0;
	int res;

	start_test("rename dir loop");

	res = create_dir(testdir, testdir_files);
	if (res == -1)
		return -1;

	res = mkdir(PATH("a"), 0755);
	if (res == -1) {
		PERROR("mkdir");
		goto fail;
	}

	res = rename(PATH("a"), PATH2("a"));
	if (res == -1) {
		PERROR("rename");
		goto fail;
	}

	errno = 0;
	res = rename(PATH("a"), PATH2("a/b"));
	if (res == 0 || errno != EINVAL) {
		PERROR("rename");
		goto fail;
	}

	res = mkdir(PATH("a/b"), 0755);
	if (res == -1) {
		PERROR("mkdir");
		goto fail;
	}

	res = mkdir(PATH("a/b/c"), 0755);
	if (res == -1) {
		PERROR("mkdir");
		goto fail;
	}

	errno = 0;
	res = rename(PATH("a"), PATH2("a/b/c"));
	if (res == 0 || errno != EINVAL) {
		PERROR("rename");
		goto fail;
	}

	errno = 0;
	res = rename(PATH("a"), PATH2("a/b/c/a"));
	if (res == 0 || errno != EINVAL) {
		PERROR("rename");
		goto fail;
	}

	errno = 0;
	res = rename(PATH("a/b/c"), PATH2("a"));
	if (res == 0 || errno != ENOTEMPTY) {
		PERROR("rename");
		goto fail;
	}

	res = open(PATH("a/foo"), O_CREAT, 0644);
	if (res == -1) {
		PERROR("open");
		goto fail;
	}
	close(res);

	res = rename(PATH("a/foo"), PATH2("a/bar"));
	if (res == -1) {
		PERROR("rename");
		goto fail;
	}

	res = rename(PATH("a/bar"), PATH2("a/foo"));
	if (res == -1) {
		PERROR("rename");
		goto fail;
	}

	res = rename(PATH("a/foo"), PATH2("a/b/bar"));
	if (res == -1) {
		PERROR("rename");
		goto fail;
	}

	res = rename(PATH("a/b/bar"), PATH2("a/foo"));
	if (res == -1) {
		PERROR("rename");
		goto fail;
	}

	res = rename(PATH("a/foo"), PATH2("a/b/c/bar"));
	if (res == -1) {
		PERROR("rename");
		goto fail;
	}

	res = rename(PATH("a/b/c/bar"), PATH2("a/foo"));
	if (res == -1) {
		PERROR("rename");
		goto fail;
	}

	res = open(PATH("a/bar"), O_CREAT, 0644);
	if (res == -1) {
		PERROR("open");
		goto fail;
	}
	close(res);

	res = rename(PATH("a/foo"), PATH2("a/bar"));
	if (res == -1) {
		PERROR("rename");
		goto fail;
	}

	unlink(PATH("a/bar"));

	res = rename(PATH("a/b"), PATH2("a/d"));
	if (res == -1) {
		PERROR("rename");
		goto fail;
	}

	res = rename(PATH("a/d"), PATH2("a/b"));
	if (res == -1) {
		PERROR("rename");
		goto fail;
	}

	res = mkdir(PATH("a/d"), 0755);
	if (res == -1) {
		PERROR("mkdir");
		goto fail;
	}

	res = rename(PATH("a/b"), PATH2("a/d"));
	if (res == -1) {
		PERROR("rename");
		goto fail;
	}

	res = rename(PATH("a/d"), PATH2("a/b"));
	if (res == -1) {
		PERROR("rename");
		goto fail;
	}

	res = mkdir(PATH("a/d"), 0755);
	if (res == -1) {
		PERROR("mkdir");
		goto fail;
	}

	res = mkdir(PATH("a/d/e"), 0755);
	if (res == -1) {
		PERROR("mkdir");
		goto fail;
	}

	errno = 0;
	res = rename(PATH("a/b"), PATH2("a/d"));
	if (res == 0 || (errno != ENOTEMPTY && errno != EEXIST)) {
		PERROR("rename");
		goto fail;
	}

	rmdir(PATH("a/d/e"));
	rmdir(PATH("a/d"));

 	rmdir(PATH("a/b/c"));
	rmdir(PATH("a/b"));
	rmdir(PATH("a"));

	err += cleanup_dir(testdir, testdir_files, 0);
	res = rmdir(testdir);
	if (res == -1) {
		PERROR("rmdir");
		goto fail;
	}
	res = check_nonexist(testdir);
	if (res == -1)
		return -1;
	if (err)
		return -1;

	success();
	return 0;

fail:
	unlink(PATH("a/bar"));

	rmdir(PATH("a/d/e"));
	rmdir(PATH("a/d"));
 
 	rmdir(PATH("a/b/c"));
	rmdir(PATH("a/b"));
	rmdir(PATH("a"));

	cleanup_dir(testdir, testdir_files, 1);
	rmdir(testdir);

	return -1;

#undef PATH2
#undef PATH
}

#ifndef __FreeBSD__
static int test_mkfifo(void)
{
	int res;
	int err = 0;

	start_test("mkfifo");
	unlink(testfile);
	res = mkfifo(testfile, 0644);
	if (res == -1) {
		PERROR("mkfifo");
		return -1;
	}
	res = check_type(testfile, S_IFIFO);
	if (res == -1)
		return -1;
	err += check_mode(testfile, 0644);
	err += check_nlink(testfile, 1);
	res = unlink(testfile);
	if (res == -1) {
		PERROR("unlink");
		return -1;
	}
	res = check_nonexist(testfile);
	if (res == -1)
		return -1;
	if (err)
		return -1;

	success();
	return 0;
}
#endif

static int test_mkdir(void)
{
	int res;
	int err = 0;
	const char *dir_contents[] = {NULL};

	start_test("mkdir");
	rmdir(testdir);
	res = mkdir(testdir, 0755);
	if (res == -1) {
		PERROR("mkdir");
		return -1;
	}
	res = check_type(testdir, S_IFDIR);
	if (res == -1)
		return -1;
	err += check_mode(testdir, 0755);
	/* Some file systems (like btrfs) don't track link
	   count for directories */
	//err += check_nlink(testdir, 2);
	err += check_dir_contents(testdir, dir_contents);
	res = rmdir(testdir);
	if (res == -1) {
		PERROR("rmdir");
		return -1;
	}
	res = check_nonexist(testdir);
	if (res == -1)
		return -1;
	if (err)
		return -1;

	success();
	return 0;
}

static int test_socket(void)
{
	struct sockaddr_un su;
	int fd;
	int res;
	int err = 0;

	start_test("socket");
	if (strlen(testsock) + 1 > sizeof(su.sun_path)) {
		fprintf(stderr, "Need to shorten mount point by %zu chars\n",
			strlen(testsock) + 1 - sizeof(su.sun_path));
		return -1;
	}
	unlink(testsock);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		PERROR("socket");
		return -1;
	}
	su.sun_family = AF_UNIX;
	strncpy(su.sun_path, testsock, sizeof(su.sun_path) - 1);
	su.sun_path[sizeof(su.sun_path) - 1] = '\0';
	res = bind(fd, (struct sockaddr*)&su, sizeof(su));
	if (res == -1) {
		PERROR("bind");
		return -1;
	}

	res = check_type(testsock, S_IFSOCK);
	if (res == -1) {
		close(fd);
		return -1;
	}
	err += check_nlink(testsock, 1);
	close(fd);
	res = unlink(testsock);
	if (res == -1) {
		PERROR("unlink");
		return -1;
	}
	res = check_nonexist(testsock);
	if (res == -1)
		return -1;
	if (err)
		return -1;

	success();
	return 0;
}

#define test_create_ro_dir(flags)	 \
	do_test_create_ro_dir(flags, #flags)

static int do_test_create_ro_dir(int flags, const char *flags_str)
{
	int res;
	int err = 0;
	int fd;

	start_test("open(%s) in read-only directory", flags_str);
	rmdir(testdir);
	res = mkdir(testdir, 0555);
	if (res == -1) {
		PERROR("mkdir");
		return -1;
	}
	fd = open(subfile, flags, 0644);
	if (fd != -1) {
		close(fd);
		unlink(subfile);
		ERROR("open should have failed");
		err--;
	} else {
		res = check_nonexist(subfile);
		if (res == -1)
			err--;
	}
	unlink(subfile);
	res = rmdir(testdir);
	if (res == -1) {
		PERROR("rmdir");
		return -1;
	}
	res = check_nonexist(testdir);
	if (res == -1)
		return -1;
	if (err)
		return -1;

	success();
	return 0;
}

int main(int argc, char *argv[])
{
	int err = 0;
	int a;
	int is_root;

	umask(0);
	if (argc < 2 || argc > 4) {
		fprintf(stderr, "usage: %s testdir [:realdir] [[-]test#] [-u]\n", argv[0]);
		return 1;
	}
	basepath = argv[1];
	basepath_r = basepath;
	for (a = 2; a < argc; a++) {
		char *endptr;
		char *arg = argv[a];
		if (arg[0] == ':') {
			basepath_r = arg + 1;
		} else {
			if (arg[0] == '-') {
				arg++;
				if (arg[0] == 'u') {
					unlinked_test = 1;
					endptr = arg + 1;
				} else {
					skip_test = strtoul(arg, &endptr, 10);
				}
			} else {
				select_test = strtoul(arg, &endptr, 10);
			}
			if (arg[0] == '\0' || *endptr != '\0') {
				fprintf(stderr, "invalid option: '%s'\n", argv[a]);
				return 1;
			}
		}
	}
	assert(strlen(basepath) < 512);
	assert(strlen(basepath_r) < 512);
	if (basepath[0] != '/') {
		fprintf(stderr, "testdir must be an absolute path\n");
		return 1;
	}

	sprintf(testfile, "%s/testfile", basepath);
	sprintf(testfile2, "%s/testfile2", basepath);
	sprintf(testdir, "%s/testdir", basepath);
	sprintf(testdir2, "%s/testdir2", basepath);
	sprintf(subfile, "%s/subfile", testdir2);
	sprintf(testsock, "%s/testsock", basepath);

	sprintf(testfile_r, "%s/testfile", basepath_r);
	sprintf(testfile2_r, "%s/testfile2", basepath_r);
	sprintf(testdir_r, "%s/testdir", basepath_r);
	sprintf(testdir2_r, "%s/testdir2", basepath_r);
	sprintf(subfile_r, "%s/subfile", testdir2_r);

	is_root = (geteuid() == 0);

	err += test_create();
	err += test_create_unlink();
	err += test_symlink();
	err += test_link();
	err += test_link2();
#ifndef __FreeBSD__	
	err += test_mknod();
	err += test_mkfifo();
#endif
	err += test_mkdir();
	err += test_rename_file();
	err += test_rename_dir();
	err += test_rename_dir_loop();
	err += test_seekdir();
	err += test_socket();
	err += test_utime();
	err += test_truncate(0);
	err += test_truncate(testdatalen / 2);
	err += test_truncate(testdatalen);
	err += test_truncate(testdatalen + 100);
	err += test_ftruncate(0, 0600);
	err += test_ftruncate(testdatalen / 2, 0600);
	err += test_ftruncate(testdatalen, 0600);
	err += test_ftruncate(testdatalen + 100, 0600);
	err += test_ftruncate(0, 0400);
	err += test_ftruncate(0, 0200);
	err += test_ftruncate(0, 0000);
	err += test_open(0, O_RDONLY, 0);
	err += test_open(1, O_RDONLY, 0);
	err += test_open(1, O_RDWR, 0);
	err += test_open(1, O_WRONLY, 0);
	err += test_open(0, O_RDWR | O_CREAT, 0600);
	err += test_open(1, O_RDWR | O_CREAT, 0600);
	err += test_open(0, O_RDWR | O_CREAT | O_TRUNC, 0600);
	err += test_open(1, O_RDWR | O_CREAT | O_TRUNC, 0600);
	err += test_open(0, O_RDONLY | O_CREAT, 0600);
	err += test_open(0, O_RDONLY | O_CREAT, 0400);
	err += test_open(0, O_RDONLY | O_CREAT, 0200);
	err += test_open(0, O_RDONLY | O_CREAT, 0000);
	err += test_open(0, O_WRONLY | O_CREAT, 0600);
	err += test_open(0, O_WRONLY | O_CREAT, 0400);
	err += test_open(0, O_WRONLY | O_CREAT, 0200);
	err += test_open(0, O_WRONLY | O_CREAT, 0000);
	err += test_open(0, O_RDWR | O_CREAT, 0400);
	err += test_open(0, O_RDWR | O_CREAT, 0200);
	err += test_open(0, O_RDWR | O_CREAT, 0000);
	err += test_open(0, O_RDWR | O_CREAT | O_EXCL, 0600);
	err += test_open(1, O_RDWR | O_CREAT | O_EXCL, 0600);
	err += test_open(0, O_RDWR | O_CREAT | O_EXCL, 0000);
	err += test_open(1, O_RDWR | O_CREAT | O_EXCL, 0000);
	err += test_open_acc(O_RDONLY, 0600, 0);
	err += test_open_acc(O_WRONLY, 0600, 0);
	err += test_open_acc(O_RDWR,   0600, 0);
	err += test_open_acc(O_RDONLY, 0400, 0);
	err += test_open_acc(O_WRONLY, 0200, 0);
	if(!is_root) {
		err += test_open_acc(O_RDONLY | O_TRUNC, 0400, EACCES);
		err += test_open_acc(O_WRONLY, 0400, EACCES);
		err += test_open_acc(O_RDWR,   0400, EACCES);
		err += test_open_acc(O_RDONLY, 0200, EACCES);
		err += test_open_acc(O_RDWR,   0200, EACCES);
		err += test_open_acc(O_RDONLY, 0000, EACCES);
		err += test_open_acc(O_WRONLY, 0000, EACCES);
		err += test_open_acc(O_RDWR,   0000, EACCES);
	}
	err += test_create_ro_dir(O_CREAT);
	err += test_create_ro_dir(O_CREAT | O_EXCL);
	err += test_create_ro_dir(O_CREAT | O_WRONLY);
	err += test_create_ro_dir(O_CREAT | O_TRUNC);
	err += test_copy_file_range();

	unlink(testfile2);
	unlink(testsock);
	rmdir(testdir);
	rmdir(testdir2);

	if (err) {
		fprintf(stderr, "%i tests failed\n", -err);
		return 1;
	}

	return check_unlinked_testfiles();
}
