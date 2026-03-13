/*  FUSE: Filesystem in Userspace
  Copyright (C) 2025-2026 Oracle.
  Author: Darrick J. Wong <djwong@kernel.org>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file LGPL2.txt.
*/
#ifndef FUSE_SERVICE_PRIV_H_
#define FUSE_SERVICE_PRIV_H_

struct fuse_service_memfd_arg {
	__be32 pos;
	__be32 len;
};

struct fuse_service_memfd_argv {
	__be32 magic;
	__be32 argc;
};

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
#define FUSE_SERVICE_BYE_CMD		0x42594545	/* BYEE */

/* mount.service sends replies to the fuse server */
#define FUSE_SERVICE_OPEN_REPLY		0x46494c45	/* FILE */
#define FUSE_SERVICE_SIMPLE_REPLY	0x5245504c	/* REPL */

struct fuse_service_packet {
	__be32 magic;			/* FUSE_SERVICE_*_{CMD,REPLY} */
};

#define FUSE_SERVICE_PROTO	(1)
#define FUSE_SERVICE_MIN_PROTO	(1)
#define FUSE_SERVICE_MAX_PROTO	(1)

struct fuse_service_hello {
	struct fuse_service_packet p;
	__be16 min_version;
	__be16 max_version;
};

struct fuse_service_hello_reply {
	struct fuse_service_packet p;
	__be16 version;
};

struct fuse_service_simple_reply {
	struct fuse_service_packet p;
	__be32 error;
};

struct fuse_service_requested_file {
	struct fuse_service_packet p;
	__be32 error;			/* positive errno */
	char path[];
};

static inline size_t sizeof_fuse_service_requested_file(size_t pathlen)
{
	return sizeof(struct fuse_service_requested_file) + pathlen + 1;
}

#define FUSE_SERVICE_OPEN_FLAGS		(0)

struct fuse_service_open_command {
	struct fuse_service_packet p;
	__be32 open_flags;
	__be32 create_mode;
	__be32 request_flags;
	__be32 block_size;
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

struct fuse_service_bye_command {
	struct fuse_service_packet p;
	__be32 error;
};

struct fuse_service_mount_command {
	struct fuse_service_packet p;
	__be32 flags;
};

int fuse_parse_cmdline_service(struct fuse_args *args,
				 struct fuse_cmdline_opts *opts);

#define FUSE_SERVICE_ARGV	"argv"
#define FUSE_SERVICE_FUSEDEV	"fusedev"

#endif /* FUSE_SERVICE_PRIV_H_ */
