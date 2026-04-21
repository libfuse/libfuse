/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2025-2026 Oracle.
 * Author: Darrick J. Wong <djwong@kernel.org>
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file LGPL2.txt.
 */
#ifndef FUSE_SERVICE_PRIV_H_
#define FUSE_SERVICE_PRIV_H_

/* All numeric fields are network order (big-endian) when going across the socket */

struct fuse_service_memfd_arg {
	uint32_t pos;
	uint32_t len;
};

struct fuse_service_memfd_argv {
	uint32_t magic;
	uint32_t argc;
};

#define FUSE_SERVICE_MAX_CMD_SIZE	(65536)

#define FUSE_SERVICE_ARGS_MAGIC		0x41524753	/* ARGS */

/* mount.service sends a hello to the server and it replies */
#define FUSE_SERVICE_HELLO_CMD		0x53414654	/* SAFT */
#define FUSE_SERVICE_HELLO_REPLY	0x4c415354	/* LAST */

/* fuse servers send commands to mount.service */
#define FUSE_SERVICE_OPEN_CMD		0x4f50454e	/* OPEN */
#define FUSE_SERVICE_OPEN_BDEV_CMD	0x42444556	/* BDEV */
#define FUSE_SERVICE_FSOPEN_CMD		0x54595045	/* TYPE */
#define FUSE_SERVICE_SOURCE_CMD		0x4e414d45	/* NAME */
#define FUSE_SERVICE_MNTOPTS_CMD	0x4f505453	/* OPTS */
#define FUSE_SERVICE_MNTPT_CMD		0x4d4e5450	/* MNTP */
#define FUSE_SERVICE_MOUNT_CMD		0x444f4954	/* DOIT */
#define FUSE_SERVICE_UNMOUNT_CMD	0x554d4e54	/* UMNT */
#define FUSE_SERVICE_BYE_CMD		0x42594545	/* BYEE */
#define FUSE_SERVICE_MTABOPTS_CMD	0x4d544142	/* MTAB */

/* mount.service sends replies to the fuse server */
#define FUSE_SERVICE_OPEN_REPLY		0x46494c45	/* FILE */
#define FUSE_SERVICE_SIMPLE_REPLY	0x5245504c	/* REPL */

struct fuse_service_packet {
	uint32_t magic;			/* FUSE_SERVICE_*_{CMD,REPLY} */
};

#define FUSE_SERVICE_PROTO	(1)
#define FUSE_SERVICE_MIN_PROTO	(1)
#define FUSE_SERVICE_MAX_PROTO	(1)

#define FUSE_SERVICE_FLAG_ALLOW_OTHER	(1U << 0)

#define FUSE_SERVICE_FLAGS		(FUSE_SERVICE_FLAG_ALLOW_OTHER)

struct fuse_service_hello {
	struct fuse_service_packet p;
	uint16_t min_version;
	uint16_t max_version;
	uint32_t flags;
};

static inline bool check_null_endbyte(const void *p, size_t psz)
{
	return *((const char *)p + psz - 1) == 0;
}

struct fuse_service_hello_reply {
	struct fuse_service_packet p;
	uint16_t version;
	uint16_t padding;
};

struct fuse_service_simple_reply {
	struct fuse_service_packet p;
	uint32_t error;			/* positive errno */
};

struct fuse_service_requested_file {
	struct fuse_service_packet p;
	uint32_t error;			/* positive errno */
	char path[];
};

static inline size_t sizeof_fuse_service_requested_file(size_t pathlen)
{
	return sizeof(struct fuse_service_requested_file) + pathlen + 1;
}

#define FUSE_SERVICE_FSOPEN_FUSEBLK	(1U << 0)
#define FUSE_SERVICE_FSOPEN_FLAGS	(FUSE_SERVICE_FSOPEN_FUSEBLK)

struct fuse_service_fsopen_command {
	struct fuse_service_packet p;
	uint32_t fsopen_flags;
};

#define FUSE_SERVICE_OPEN_QUIET		(1U << 0)
#define FUSE_SERVICE_OPEN_FLAGS		(FUSE_SERVICE_OPEN_QUIET)

struct fuse_service_open_command {
	struct fuse_service_packet p;
	uint32_t open_flags;
	uint32_t create_mode;
	uint32_t request_flags;
	uint32_t block_size;
	char path[];
};

static inline size_t sizeof_fuse_service_open_command(size_t pathlen)
{
	return sizeof(struct fuse_service_open_command) + pathlen + 1;
}

struct fuse_service_string_command {
	struct fuse_service_packet p;
	char value[];
};

static inline size_t sizeof_fuse_service_string_command(size_t len)
{
	return sizeof(struct fuse_service_string_command) + len + 1;
}

struct fuse_service_mountpoint_command {
	struct fuse_service_packet p;
	uint16_t expected_fmt;
	uint16_t padding;
	char value[];
};

static inline size_t sizeof_fuse_service_mountpoint_command(size_t len)
{
	return sizeof(struct fuse_service_mountpoint_command) + len + 1;
}

struct fuse_service_bye_command {
	struct fuse_service_packet p;
	uint32_t exitcode;
};

struct fuse_service_mount_command {
	struct fuse_service_packet p;
	uint32_t ms_flags;
};

struct fuse_service_unmount_command {
	struct fuse_service_packet p;
};

int fuse_parse_cmdline_service(struct fuse_args *args,
				 struct fuse_cmdline_opts *opts);

#define FUSE_SERVICE_ARGV	"argv"
#define FUSE_SERVICE_FUSEDEV	"fusedev"

#endif /* FUSE_SERVICE_PRIV_H_ */
