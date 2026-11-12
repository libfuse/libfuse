/*
 * FUSE: Filesystem in Userspace
 *
 * Check that READDIRPLUS overflow leaves no extra lookup references.
 * Force "b" into a second reply, forget both returned entries, then check
 * that a new LOOKUP of "b" gets a different node ID.
 *
 * Exercise both readdir offset modes over a socket pair, without a mount.
 *
 * This program can be distributed under the terms of the GNU GPLv2.
 * See the file GPL2.txt.
 */

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 19)

#include <fuse.h>
#include <fuse_lowlevel.h>
#include <fuse_kernel.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static int use_offsets;
static uint64_t unique;
static int peer_fd;
static unsigned char reply[16384];

static int t_getattr(const char *path, struct stat *st,
		     struct fuse_file_info *fi)
{
	(void)fi;
	memset(st, 0, sizeof(*st));
	st->st_mode = strcmp(path, "/") == 0 ? S_IFDIR | 0755 : S_IFREG | 0644;
	st->st_nlink = 1;
	return 0;
}

static int t_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		     off_t off, struct fuse_file_info *fi,
		     enum fuse_readdir_flags flags)
{
	static const char *const names[] = { "a", "b" };
	struct stat st;
	int i;

	(void)path;
	(void)fi;
	(void)flags;
	if (use_offsets && (off < 0 || off >= 2))
		return 0;
	t_getattr("/a", &st, NULL);
	for (i = use_offsets ? off : 0; i < 2; i++) {
		if (filler(buf, names[i], &st, use_offsets ? i + 1 : 0,
			   FUSE_FILL_DIR_PLUS))
			break;
	}
	return 0;
}

static const struct fuse_operations t_ops = {
	.getattr = t_getattr,
	.readdir = t_readdir,
};

/* Return the reply payload; FORGET has no reply. */
static void *request(struct fuse_session *se, uint32_t opcode,
		     uint64_t nodeid, const void *body, size_t size,
		     size_t *len)
{
	unsigned char in[4096];
	struct fuse_in_header *h = (struct fuse_in_header *)in;
	struct fuse_out_header *out = (struct fuse_out_header *)reply;
	struct fuse_buf buf;
	ssize_t res;

	if (size > sizeof(in) - sizeof(*h)) {
		fprintf(stderr, "opcode %u: the body does not fit in the buffer\n",
			opcode);
		exit(1);
	}
	memset(in, 0, sizeof(*h));
	h->len = sizeof(*h) + size;
	h->opcode = opcode;
	h->unique = ++unique;
	h->nodeid = nodeid;
	h->uid = getuid();
	h->gid = getgid();
	h->pid = getpid();
	memcpy(in + sizeof(*h), body, size);
	buf = (struct fuse_buf){ .size = h->len, .mem = in };
	fuse_session_process_buf(se, &buf);
	if (opcode == FUSE_FORGET)
		return NULL;

	res = recv(peer_fd, reply, sizeof(reply), MSG_DONTWAIT);
	if (res < (ssize_t)sizeof(*out) || out->len != (uint32_t)res) {
		fprintf(stderr, "opcode %u: the reply is missing or incomplete\n",
			opcode);
		exit(1);
	}
	if (out->error) {
		fprintf(stderr, "opcode %u failed: %s\n", opcode,
			strerror(-out->error));
		exit(1);
	}
	if (len)
		*len = res - sizeof(*out);
	return reply + sizeof(*out);
}

/* Return nonzero if the rejected entry's lookup leaked. */
static int run(char *argv[], int offsets)
{
	struct fuse_args args = FUSE_ARGS_INIT(1, argv);
	struct fuse_init_in init = {
		.major = FUSE_KERNEL_VERSION,
		.minor = 31,
		.flags = FUSE_DO_READDIRPLUS,
	};
	struct fuse_open_in op = { .flags = O_RDONLY | O_DIRECTORY };
	struct fuse_forget_in forget = { .nlookup = 1 };
	struct fuse_entry_param e = { 0 };
	struct fuse_direntplus *dirent;
	struct fuse_open_out *opened;
	uint64_t fh;
	struct fuse_release_in rel;
	struct fuse_entry_out *entry;
	struct fuse_read_in rd;
	struct fuse_session *se;
	uint64_t a_id, b_id, new_id;
	char mountpoint[32];
	struct fuse *f;
	size_t len;
	int sv[2];

	use_offsets = offsets;
	unique = 0;
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == -1) {
		perror("socketpair");
		exit(1);
	}
	peer_fd = sv[1];
	f = fuse_new(&args, &t_ops, sizeof(t_ops), NULL);
	if (f == NULL) {
		fprintf(stderr, "fuse_new failed\n");
		exit(1);
	}
	snprintf(mountpoint, sizeof(mountpoint), "/dev/fd/%d", sv[0]);
	if (fuse_mount(f, mountpoint) != 0) {
		fprintf(stderr, "fuse_mount(%s) failed\n", mountpoint);
		exit(1);
	}
	se = fuse_get_session(f);

	request(se, FUSE_INIT, 0, &init, sizeof(init), NULL);
	opened = request(se, FUSE_OPENDIR, FUSE_ROOT_ID, &op, sizeof(op),
			 NULL);
	/* The next reply overwrites the buffer this points into */
	fh = opened->fh;
	memset(&rd, 0, sizeof(rd));
	rd.fh = fh;
	/* Room for exactly one entry */
	rd.size = fuse_add_direntry_plus(NULL, NULL, 0, "a", &e, 1);

	dirent = request(se, FUSE_READDIRPLUS, FUSE_ROOT_ID, &rd, sizeof(rd),
			 &len);
	if (len != rd.size || strncmp(dirent->dirent.name, "a", 1) != 0) {
		fprintf(stderr, "first READDIRPLUS did not return only \"a\"\n");
		exit(1);
	}
	a_id = dirent->entry_out.nodeid;
	rd.offset = dirent->dirent.off;

	dirent = request(se, FUSE_READDIRPLUS, FUSE_ROOT_ID, &rd, sizeof(rd),
			 &len);
	if (len != rd.size || strncmp(dirent->dirent.name, "b", 1) != 0) {
		fprintf(stderr, "second READDIRPLUS did not return \"b\"\n");
		exit(1);
	}
	b_id = dirent->entry_out.nodeid;

	/* Forget each entry that was sent */
	request(se, FUSE_FORGET, a_id, &forget, sizeof(forget), NULL);
	request(se, FUSE_FORGET, b_id, &forget, sizeof(forget), NULL);
	memset(&rel, 0, sizeof(rel));
	rel.fh = fh;
	request(se, FUSE_RELEASEDIR, FUSE_ROOT_ID, &rel, sizeof(rel), NULL);

	entry = request(se, FUSE_LOOKUP, FUSE_ROOT_ID, "b", sizeof("b"), NULL);
	new_id = entry->nodeid;
	request(se, FUSE_FORGET, new_id, &forget, sizeof(forget), NULL);

	printf("%s: \"b\" was node %llu, after the FORGETs a new lookup gives %llu: %s\n",
	       offsets ? "offsets (fill_dir_plus)" :
			 "offset 0 (readdir_fill_from_list)",
	       (unsigned long long)b_id, (unsigned long long)new_id,
	       new_id == b_id ? "the node leaked" : "ok");

	fuse_destroy(f);
	fuse_opt_free_args(&args);
	close(sv[1]);
	return new_id == b_id;
}

int main(int argc, char *argv[])
{
	int err = 0;

	(void)argc;
	err += run(argv, 0);
	err += run(argv, 1);
	return err ? 1 : 0;
}
