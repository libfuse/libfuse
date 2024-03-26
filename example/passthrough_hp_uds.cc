/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2017       Nikolaus Rath <Nikolaus@rath.org>
  Copyright (C) 2018       Valve, Inc
  Copyright (C) 2024       Antmicro

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

/** @file
 *
 * This is a version of passthrough_hp.cc with IO over UNIX domain sockets.
 * Optional custom path of the socket can be provided as a second argument.
 */

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 12)

// C includes
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <ftw.h>
#include <fuse_lowlevel.h>
#include <fuse_kernel.h>
#include <inttypes.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <limits.h>

// C++ includes
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <list>
#include "cxxopts.hpp"
#include <mutex>
#include <fstream>
#include <thread>
#include <iomanip>
#include "passthrough_hp_common.hpp"


static void print_usage(char *prog_name) {
    cout << "Usage: " << prog_name << " --help\n"
         << "       " << prog_name << " [options] <source>\n";
}


static int create_socket(const char *socket_path) {
	struct sockaddr_un addr;

	if (strnlen(socket_path, sizeof(addr.sun_path)) >=
		sizeof(addr.sun_path)) {
		printf("Socket path may not be longer than %lu characters\n",
			 sizeof(addr.sun_path) - 1);
		return -1;
	}

	if (remove(socket_path) == -1 && errno != ENOENT) {
		printf("Could not delete previous socket file entry at %s. Error: "
			 "%s\n", socket_path, strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	strcpy(addr.sun_path, socket_path);

	int sfd = socket(AF_UNIX, SOCK_STREAM, 0); if (sfd == -1) {
		printf("Could not create socket. Error: %s\n", strerror(errno));
		return -1;
	}

	addr.sun_family = AF_UNIX;
	if (bind(sfd, (struct sockaddr *) &addr,
		   sizeof(struct sockaddr_un)) == -1) {
		printf("Could not bind socket. Error: %s\n", strerror(errno));
		return -1;
	}

	if (listen(sfd, 1) == -1)
		return -1;

	printf("Awaiting connection on socket at %s...\n", socket_path);
	int cfd = accept(sfd, NULL, NULL);
	if (cfd == -1) {
		printf("Could not accept connection. Error: %s\n",
			 strerror(errno));
		return -1;
	} else {
		printf("Accepted connection!\n");
	}
	return cfd;
}


static ssize_t stream_writev(int fd, struct iovec *iov, int count,
                             void *userdata) {
	(void)userdata;

	ssize_t written = 0;
	int cur = 0;
	for (;;) {
		written = writev(fd, iov+cur, count-cur);
		if (written < 0)
			return written;

		while (cur < count && written >= iov[cur].iov_len)
			written -= iov[cur++].iov_len;
		if (cur == count)
			break;

		iov[cur].iov_base = (char *)iov[cur].iov_base + written;
		iov[cur].iov_len -= written;
	}
	return written;
}


static ssize_t readall(int fd, void *buf, size_t len) {
	size_t count = 0;

	while (count < len) {
		int i = read(fd, (char *)buf + count, len - count);
		if (!i)
			break;

		if (i < 0)
			return i;

		count += i;
	}
	return count;
}


static ssize_t stream_read(int fd, void *buf, size_t buf_len, void *userdata) {
    (void)userdata;

	int res = readall(fd, buf, sizeof(struct fuse_in_header));
	if (res == -1)
    	return res;

    uint32_t packet_len = ((struct fuse_in_header *)buf)->len;
    if (packet_len > buf_len)
    	return -1;

    int prev_res = res;

    res = readall(fd, (char *)buf + sizeof(struct fuse_in_header),
                  packet_len - sizeof(struct fuse_in_header));

    return  (res == -1) ? res : (res + prev_res);
}


static ssize_t stream_splice_send(int fdin, off_t *offin, int fdout,
					    off_t *offout, size_t len,
                                  unsigned int flags, void *userdata) {
	(void)userdata;

	size_t count = 0;
	while (count < len) {
		int i = splice(fdin, offin, fdout, offout, len - count, flags);
		if (i < 1)
			return i;

		count += i;
	}
	return count;
}


int main(int argc, char *argv[]) {
    // Parse command line options
    auto options {parse_options(argc, argv, print_usage)};
    fs.timeout = options.count("nocache") ? 0 : 86400.0;
    // We need an fd for every dentry in our the filesystem that the
    // kernel knows about. This is way more than most processes need,
    // so try to get rid of any resource softlimit.
    maximize_fd_limit();

    struct fuse_loop_config *loop_config = NULL;
    const struct fuse_custom_io io = {
			.writev = stream_writev,
			.read = stream_read,
			.splice_receive = NULL,
			.splice_send = stream_splice_send,
		};
		int cfd = -1;
		int ret = -1;
    // Initialize fuse
    fuse_args args = FUSE_ARGS_INIT(0, nullptr);
    if (fuse_opt_add_arg(&args, argv[0]) ||
        fuse_opt_add_arg(&args, "-o") ||
        fuse_opt_add_arg(&args, fs.fuse_mount_options.c_str()) ||
        (fs.debug_fuse && fuse_opt_add_arg(&args, "-odebug")))
        errx(3, "ERROR: Out of memory");

    // Initialize filesystem root
		auto se = init_passthrough_fs(&args);
    if (se == nullptr)
        goto err_out1;
    if (fuse_set_signal_handlers(se) != 0)
        goto err_out2;

	    // Use UDS
    cfd = create_socket(fs.socket.c_str());
		if (cfd == -1)
			goto err_out3;

		if (fuse_session_custom_io(se, &io, cfd) != 0)
			goto err_out3;

	  if (fs.num_threads != -1)
	    fuse_loop_cfg_set_max_threads(loop_config, fs.num_threads);

    // Don't apply umask, use modes exactly as specified
    umask(0);
    if (options.count("single"))
        ret = fuse_session_loop(se);
    else
        ret = fuse_session_loop_mt(se, loop_config);


    fuse_session_unmount(se);

err_out3:
    fuse_remove_signal_handlers(se);
err_out2:
    fuse_session_destroy(se);
err_out1:
    fuse_loop_cfg_destroy(loop_config);
    fuse_opt_free_args(&args);

    return ret ? 1 : 0;
}

