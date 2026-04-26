/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
 *
 * This program can be distributed under the terms of the GNU GPLv2.
 * See the file GPL2.txt.
 */
/* This program parses fuse.conf */
#define _GNU_SOURCE
#include "fuse_config.h"
#include "mount_util.h"
#include "util.h"
#include "fuser_conf.h"

#include <string.h>
#include <stddef.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <mntent.h>
#include <unistd.h>
#include <sys/fsuid.h>

#include "fuse_mount_compat.h"

#if defined HAVE_LISTMOUNT
#include <linux/mount.h>
#include <syscall.h>
#include <stdint.h>
#endif

int user_allow_other;
int mount_max = 1000;
static uid_t oldfsuid;
static gid_t oldfsgid;

// Older versions of musl libc don't unescape entries in /etc/mtab

// unescapes octal sequences like \040 in-place
// That's ok, because unescaping can not extend the length of the string.
void unescape(char *buf)
{
	char *src = buf;
	char *dest = buf;

	while (1) {
		char *next_src = strchrnul(src, '\\');
		int offset = next_src - src;

		memmove(dest, src, offset);
		src = next_src;
		dest += offset;

		if (*src == '\0') {
			*dest = *src;
			return;
		}
		src++;

		if ('0' <= src[0] && src[0] < '2' &&
		    '0' <= src[1] && src[1] < '8' &&
		    '0' <= src[2] && src[2] < '8') {
			*dest++ = (src[0] - '0') << 6
				| (src[1] - '0') << 3
				| (src[2] - '0') << 0;
			src += 3;
		} else if (src[0] == '\\') {
			*dest++ = '\\';
			src += 1;
		} else {
			*dest++ = '\\';
		}
	}
}

#ifndef IGNORE_MTAB
static int count_fuse_fs_mtab(const char *progname)
{
	const struct mntent *entp;
	int count = 0;
	const char *mtab = _PATH_MOUNTED;
	FILE *fp = setmntent(mtab, "r");

	if (fp == NULL) {
		fprintf(stderr, "%s: failed to open %s: %s\n", progname, mtab,
			strerror(errno));
		return -1;
	}
	while ((entp = GETMNTENT(fp)) != NULL) {
		if (strcmp(entp->mnt_type, "fuse") == 0 ||
		    strncmp(entp->mnt_type, "fuse.", 5) == 0)
			count++;
	}
	endmntent(fp);
	return count;
}

#ifdef HAVE_LISTMOUNT
static int count_fuse_fs_ls_mnt(const char *progname)
{
	#define SMBUF_SIZE 1024
	#define MNT_ID_LEN 128

	int fuse_count = 0;
	int n_mounts = 0;
	int ret = 0;
	uint64_t mnt_ids[MNT_ID_LEN];
	unsigned char smbuf[SMBUF_SIZE];
	struct mnt_id_req req = {
		.size = sizeof(struct mnt_id_req),
	};
	struct statmount *sm;

	for (;;) {
		req.mnt_id = LSMT_ROOT;

		n_mounts = syscall(SYS_listmount, &req, &mnt_ids, MNT_ID_LEN, 0);
		if (n_mounts == -1) {
			if (errno != ENOSYS) {
				fprintf(stderr, "%s: failed to list mounts: %s\n", progname,
					strerror(errno));
			}
			return -1;
		}

		for (int i = 0; i < n_mounts; i++) {
			req.mnt_id = mnt_ids[i];
			req.param = STATMOUNT_FS_TYPE;
			ret = syscall(SYS_statmount, &req, &smbuf, SMBUF_SIZE, 0);
			if (ret) {
				if (errno == ENOENT)
					continue;

				fprintf(stderr, "%s: failed to stat mount %lld: %s\n", progname,
					req.mnt_id, strerror(errno));
				return -1;
			}

			sm = (struct statmount *)smbuf;
			if (sm->mask & STATMOUNT_FS_TYPE &&
			    strcmp(&sm->str[sm->fs_type], "fuse") == 0)
				fuse_count++;
		}

		if (n_mounts < MNT_ID_LEN)
			break;
		req.param = mnt_ids[MNT_ID_LEN - 1];
	}
	return fuse_count;
}

int count_fuse_fs(const char *progname)
{
	int count = count_fuse_fs_ls_mnt(progname);

	return count >= 0 ? count : count_fuse_fs_mtab(progname);
}
#else
int count_fuse_fs(const char *progname)
{
	return count_fuse_fs_mtab(progname);
}
#endif /* HAVE_LISTMOUNT */
#else
int count_fuse_fs(const char *progname)
{
	return 0;
}
#endif /* !IGNORE_MTAB */

static void strip_line(char *line)
{
	char *s = strchr(line, '#');

	if (s != NULL)
		s[0] = '\0';
	for (s = line + strlen(line) - 1;
	     s >= line && isspace((unsigned char) *s); s--) {
	}
	s[1] = '\0';
	for (s = line; isspace((unsigned char) *s); s++)
		; /* empty */
	if (s != line)
		memmove(line, s, strlen(s)+1);
}

static void parse_line(const char *line, int linenum, const char *progname)
{
	int tmp;

	if (strcmp(line, "user_allow_other") == 0)
		user_allow_other = 1;
	else if (sscanf(line, "mount_max = %i", &tmp) == 1)
		mount_max = tmp;
	else if (line[0])
		fprintf(stderr,
			"%s: unknown parameter in %s at line %i: '%s'\n",
			progname, FUSE_CONF, linenum, line);
}

void read_conf(const char *progname)
{
	FILE *fp = fopen(FUSE_CONF, "r");

	if (fp != NULL) {
		int linenum = 1;
		char line[256];
		int isnewline = 1;

		while (fgets(line, sizeof(line), fp) != NULL) {
			if (isnewline) {
				if (line[strlen(line)-1] == '\n') {
					strip_line(line);
					parse_line(line, linenum, progname);
				} else {
					isnewline = 0;
				}
			} else if (line[strlen(line)-1] == '\n') {
				fprintf(stderr, "%s: reading %s: line %i too long\n",
					progname, FUSE_CONF, linenum);

				isnewline = 1;
			}
			if (isnewline)
				linenum++;
		}
		if (!isnewline) {
			fprintf(stderr, "%s: reading %s: missing newline at end of file\n",
				progname, FUSE_CONF);

		}
		if (ferror(fp)) {
			fprintf(stderr, "%s: reading %s: read failed\n", progname, FUSE_CONF);
			exit(1);
		}
		fclose(fp);
	} else if (errno != ENOENT) {
		bool fatal = (errno != EACCES && errno != ELOOP &&
			      errno != ENAMETOOLONG && errno != ENOTDIR &&
			      errno != EOVERFLOW);
		fprintf(stderr, "%s: failed to open %s: %s\n",
			progname, FUSE_CONF, strerror(errno));
		if (fatal)
			exit(1);
	}
}

void drop_privs(void)
{
	if (getuid() != 0) {
		oldfsuid = setfsuid(getuid());
		oldfsgid = setfsgid(getgid());
	}
}

void restore_privs(void)
{
	if (getuid() != 0) {
		setfsuid(oldfsuid);
		setfsgid(oldfsgid);
	}
}

int check_nonroot_mount_count(const char *progname)
{
	if (mount_max == -1)
		return 0;

	int mount_count = count_fuse_fs(progname);

	if (mount_count >= mount_max) {
		fprintf(stderr,
"%s: too many FUSE filesystems mounted; mount_max=N can be set in %s\n",
			progname, FUSE_CONF);
		return -1;
	}

	return 0;
}

int check_nonroot_dir_access(const char *progname, const char *origmnt,
			     const char *mnt, const struct stat *stbuf)
{
	int res;

	if ((stbuf->st_mode & S_ISVTX) && stbuf->st_uid != getuid()) {
		fprintf(stderr, "%s: mountpoint %s not owned by user\n",
			progname, origmnt);
		return -1;
	}

	res = access(mnt, W_OK);
	if (res == -1) {
		fprintf(stderr, "%s: user has no write access to mountpoint %s\n",
			progname, origmnt);
		return -1;
	}

	return 0;
}

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

int check_nonroot_fstype(const char *progname, const struct statfs *fs_buf)
{
	size_t i;

	/* Do not permit mounting over anything in procfs - it has a couple
	 * places to which we have "write access" without being supposed to be
	 * able to just put anything we want there.
	 * Luckily, without allow_other, we can't get other users to actually
	 * use any fake information we try to put there anyway.
	 * Use a whitelist to be safe.
	 */

	/* Define permitted filesystems for the mount target. This was
	 * originally the same list as used by the ecryptfs mount helper
	 * (https://bazaar.launchpad.net/~ecryptfs/ecryptfs/trunk/view/head:/src/utils/mount.ecryptfs_private.c#L225)
	 * but got expanded as we found more filesystems that needed to be
	 * overlaid.
	 */
	typeof(fs_buf->f_type) f_type_whitelist[] = {
		0x61756673 /* AUFS_SUPER_MAGIC */,
		0x00000187 /* AUTOFS_SUPER_MAGIC */,
		0xCA451A4E /* BCACHEFS_STATFS_MAGIC */,
		0x9123683E /* BTRFS_SUPER_MAGIC */,
		0x00C36400 /* CEPH_SUPER_MAGIC */,
		0xFF534D42 /* CIFS_MAGIC_NUMBER */,
		0x0000F15F /* ECRYPTFS_SUPER_MAGIC */,
		0X2011BAB0 /* EXFAT_SUPER_MAGIC */,
		0x0000EF53 /* EXT[234]_SUPER_MAGIC */,
		0xF2F52010 /* F2FS_SUPER_MAGIC */,
		0x65735546 /* FUSE_SUPER_MAGIC */,
		0x01161970 /* GFS2_MAGIC */,
		0x47504653 /* GPFS_SUPER_MAGIC */,
		0x0000482b /* HFSPLUS_SUPER_MAGIC */,
		0x000072B6 /* JFFS2_SUPER_MAGIC */,
		0x3153464A /* JFS_SUPER_MAGIC */,
		0x0BD00BD0 /* LL_SUPER_MAGIC */,
		0X00004D44 /* MSDOS_SUPER_MAGIC */,
		0x0000564C /* NCP_SUPER_MAGIC */,
		0x00006969 /* NFS_SUPER_MAGIC */,
		0x00003434 /* NILFS_SUPER_MAGIC */,
		0x5346544E /* NTFS_SB_MAGIC */,
		0x7366746E /* NTFS3_SUPER_MAGIC */,
		0x5346414f /* OPENAFS_SUPER_MAGIC */,
		0x794C7630 /* OVERLAYFS_SUPER_MAGIC */,
		0xAAD7AAEA /* PANFS_SUPER_MAGIC */,
		0x52654973 /* REISERFS_SUPER_MAGIC */,
		0xFE534D42 /* SMB2_SUPER_MAGIC */,
		0x73717368 /* SQUASHFS_MAGIC */,
		0x01021994 /* TMPFS_MAGIC */,
		0x24051905 /* UBIFS_SUPER_MAGIC */,
		0x18031977 /* WEKAFS_SUPER_MAGIC */,
#if __SIZEOF_LONG__ > 4
		0x736675005346544e /* UFSD */,
#endif
		0x58465342 /* XFS_SB_MAGIC */,
		0x2FC12FC1 /* ZFS_SUPER_MAGIC */,
		0x858458f6 /* RAMFS_MAGIC */,
	};
	for (i = 0; i < ARRAY_SIZE(f_type_whitelist); i++) {
		if (f_type_whitelist[i] == fs_buf->f_type)
			return 0;
	}

	fprintf(stderr, "%s: mounting over filesystem type %#010lx is forbidden\n",
		progname, (unsigned long)fs_buf->f_type);
	return -1;
}

const struct mount_flags mount_flags[] = {
	{"rw",	    MS_RDONLY,	    0, 1},
	{"ro",	    MS_RDONLY,	    1, 1},
	{"suid",    MS_NOSUID,	    0, 0},
	{"nosuid",  MS_NOSUID,	    1, 1},
	{"dev",	    MS_NODEV,	    0, 0},
	{"nodev",   MS_NODEV,	    1, 1},
	{"exec",    MS_NOEXEC,	    0, 1},
	{"noexec",  MS_NOEXEC,	    1, 1},
	{"async",   MS_SYNCHRONOUS, 0, 1},
	{"sync",    MS_SYNCHRONOUS, 1, 1},
	{"atime",   MS_NOATIME,	    0, 1},
	{"noatime", MS_NOATIME,	    1, 1},
	{"diratime",        MS_NODIRATIME,  0, 1},
	{"nodiratime",      MS_NODIRATIME,  1, 1},
	{"lazytime",        MS_LAZYTIME,    1, 1},
	{"nolazytime",      MS_LAZYTIME,    0, 1},
	{"relatime",        MS_RELATIME,    1, 1},
	{"norelatime",      MS_RELATIME,    0, 1},
	{"strictatime",     MS_STRICTATIME, 1, 1},
	{"nostrictatime",   MS_STRICTATIME, 0, 1},
	{"dirsync", MS_DIRSYNC,	    1, 1},
	{"symfollow",       MS_NOSYMFOLLOW, 0, 1},
	{"nosymfollow",     MS_NOSYMFOLLOW, 1, 1},
	{NULL,	    0,		    0, 0}
};
