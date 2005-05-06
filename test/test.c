#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>


static char testfile[1024];
static char testfile2[1024];
static char testname[256];
static char zerodata[4096];

static void test_perror(const char *func, const char *msg)
{
    fprintf(stderr, "[%s] %s %s: %s\n", testname, func, msg, strerror(errno));
}

static void test_error(const char *func, const char *msg, ...)
     __attribute__ ((format (printf, 2, 3)));

static void start_test(const char *fmt, ...)
     __attribute__ ((format (printf, 1, 2)));
     
static void test_error(const char *func, const char *msg, ...)
{
    va_list ap;
    fprintf(stderr, "[%s] %s ", testname, func);
    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

static void success(void)
{
    fprintf(stderr, "[%s] OK\n", testname);
}

static void start_test(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsprintf(testname, fmt, ap);
    va_end(ap);
}

#define PERROR(msg) test_perror(__FUNCTION__, msg)
#define ERROR(msg, args...) test_error(__FUNCTION__, msg, ##args)

static int check_size(const char *path, int len)
{
    struct stat stbuf;
    int res = stat(path, &stbuf);
    if (res == -1) {
        PERROR("stat");
        return -1;
    }
    if (stbuf.st_size != len) {
        ERROR("length %u instead of %u", (int) stbuf.st_size, (int) len);
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
        if (memcmp(buf, data, rdlen) != 0) {
            ERROR("data mismatch");
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
    res = close(fd);
    if (res == -1) {
        PERROR("close");
        return -1;
    }
    res = check_size(path, len);
    if (res == -1)
        return -1;

    res = check_data(path, data, 0, len);
    if (res == -1)
        return -1;

    return 0;
}

int test_truncate(int len)
{
    const char *data = "abcdefghijklmnopqrstuvwxyz";
    int datalen = strlen(data); 
    int res;

    start_test("truncate(%u)", (int) len);
    res = create_file(testfile, data, datalen);
    if (res == -1)
        return -1;
    
    res = truncate(testfile, len);
    if (res == -1) {
        PERROR("truncate");
        return -1;
    }
    res = check_size(testfile, len);
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
            res = check_data(testfile, zerodata, datalen, len - datalen);
            if (res == -1)
                return -1;
        }
    }

    success();
    return 0;
}

static int test_symlink(void)
{
    char buf[1024];
    const char *data = "abcdefghijklmnopqrstuvwxyz";
    int datalen = strlen(data); 
    int linklen = strlen(testfile);
    int res;

    start_test("symlink");
    res = create_file(testfile, data, datalen);
    if (res == -1)
        return -1;
    
    unlink(testfile2);
    res = symlink(testfile, testfile2);
    if (res == -1) {
        PERROR("symlink");
        return -1;
    }
    res = readlink(testfile2, buf, sizeof(buf));
    if (res == -1) {
        PERROR("readlink");
        return -1;
    }
    if (res != linklen) {
        ERROR("short readlink: %u instead of %u", res, linklen);
        return -1;
    }
    if (memcmp(buf, testfile, linklen) != 0) {
        ERROR("link mismatch");
        return -1;
    }

    res = check_size(testfile2, datalen);
    if (res == -1)
        return -1;
    
    res = check_data(testfile2, data, 0, datalen);
    if (res == -1)
        return -1;

    success();
    return 0;
}

int main(void)
{
    sprintf(testfile, "/tmp/fusetest/testfile");
    sprintf(testfile2, "/tmp/fusetest/testfile2");
    test_symlink();
    test_truncate(0);
    test_truncate(10);
    test_truncate(26);
    test_truncate(100);
    return 0;
}
