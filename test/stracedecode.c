#include <stdio.h>
#include <string.h>
#include "fuse_kernel.h"

static struct {
	const char *name;
} fuse_ll_ops[] = {
	[FUSE_LOOKUP]	   = { "LOOKUP"	     },
	[FUSE_FORGET]	   = { "FORGET"	     },
	[FUSE_GETATTR]	   = { "GETATTR"     },
	[FUSE_SETATTR]	   = { "SETATTR"     },
	[FUSE_READLINK]	   = { "READLINK"    },
	[FUSE_SYMLINK]	   = { "SYMLINK"     },
	[FUSE_MKNOD]	   = { "MKNOD"	     },
	[FUSE_MKDIR]	   = { "MKDIR"	     },
	[FUSE_UNLINK]	   = { "UNLINK"	     },
	[FUSE_RMDIR]	   = { "RMDIR"	     },
	[FUSE_RENAME]	   = { "RENAME"	     },
	[FUSE_LINK]	   = { "LINK"	     },
	[FUSE_OPEN]	   = { "OPEN"	     },
	[FUSE_READ]	   = { "READ"	     },
	[FUSE_WRITE]	   = { "WRITE"	     },
	[FUSE_STATFS]	   = { "STATFS"	     },
	[FUSE_RELEASE]	   = { "RELEASE"     },
	[FUSE_FSYNC]	   = { "FSYNC"	     },
	[FUSE_SETXATTR]	   = { "SETXATTR"    },
	[FUSE_GETXATTR]	   = { "GETXATTR"    },
	[FUSE_LISTXATTR]   = { "LISTXATTR"   },
	[FUSE_REMOVEXATTR] = { "REMOVEXATTR" },
	[FUSE_FLUSH]	   = { "FLUSH"	     },
	[FUSE_INIT]	   = { "INIT"	     },
	[FUSE_OPENDIR]	   = { "OPENDIR"     },
	[FUSE_READDIR]	   = { "READDIR"     },
	[FUSE_RELEASEDIR]  = { "RELEASEDIR"  },
	[FUSE_FSYNCDIR]	   = { "FSYNCDIR"    },
	[FUSE_GETLK]	   = { "GETLK"	     },
	[FUSE_SETLK]	   = { "SETLK"	     },
	[FUSE_SETLKW]	   = { "SETLKW"	     },
	[FUSE_ACCESS]	   = { "ACCESS"	     },
	[FUSE_CREATE]	   = { "CREATE"	     },
	[FUSE_INTERRUPT]   = { "INTERRUPT"   },
	[FUSE_BMAP]	   = { "BMAP"	     },
	[FUSE_DESTROY]	   = { "DESTROY"     },
	[FUSE_READDIRPLUS] = { "READDIRPLUS" },
};

#define FUSE_MAXOP (sizeof(fuse_ll_ops) / sizeof(fuse_ll_ops[0]))

static const char *opname(enum fuse_opcode opcode)
{
	if (opcode >= FUSE_MAXOP || !fuse_ll_ops[opcode].name)
		return "???";
	else
		return fuse_ll_ops[opcode].name;
}


static void process_buf(int dir, char *buf, int len)
{
	static unsigned long long prevuniq = -1;
	static int prevopcode;

	if (!dir) {
		struct fuse_in_header *in = (struct fuse_in_header *) buf;
		buf += sizeof(struct fuse_in_header);

		printf("unique: %llu, opcode: %s (%i), nodeid: %lu, len: %i, insize: %i\n",
		       (unsigned long long) in->unique,
		       opname((enum fuse_opcode) in->opcode), in->opcode,
		       (unsigned long) in->nodeid, in->len, len);

		switch (in->opcode) {
		case FUSE_READ: {
			struct fuse_read_in *arg = (struct fuse_read_in *) buf;
			printf("-READ fh:%llu off:%llu siz:%u rfl:%u own:%llu fl:%u\n",
			       arg->fh, arg->offset, arg->size, arg->read_flags,
			       arg->lock_owner, arg->flags);
			break;
		}
		case FUSE_WRITE: {
			struct fuse_write_in *arg = (struct fuse_write_in *) buf;
			printf("-WRITE fh:%llu off:%llu siz:%u wfl:%u own:%llu fl:%u\n",
			       arg->fh, arg->offset, arg->size, arg->write_flags,
			       arg->lock_owner, arg->flags);
			break;
		}
		}
		prevuniq = in->unique;
		prevopcode = in->opcode;
	} else {
		struct fuse_out_header *out = (struct fuse_out_header *) buf;
		buf += sizeof(struct fuse_out_header);

		printf("   unique: %llu, error: %i (%s), len: %i, outsize: %i\n",
		       (unsigned long long) out->unique, out->error,
		       strerror(-out->error), out->len, len);

		if (out->unique == prevuniq) {
			switch (prevopcode) {
			case FUSE_GETATTR: {
				struct fuse_attr_out *arg = (struct fuse_attr_out *) buf;
				printf("+ATTR v:%llu.%09u i:%llu s:%llu b:%llu\n",
				       arg->attr_valid, arg->attr_valid_nsec,
				       arg->attr.ino, arg->attr.size, arg->attr.blocks);
				break;
			}
			case FUSE_LOOKUP: {
				struct fuse_entry_out *arg = (struct fuse_entry_out *) buf;
				printf("+ENTRY nodeid:%llu v:%llu.%09u i:%llu s:%llu b:%llu\n",
				       arg->nodeid, arg->attr_valid, arg->attr_valid_nsec,
				       arg->attr.ino, arg->attr.size, arg->attr.blocks);
				break;
			}
			}
		}
	}

}

int main(void)
{
	FILE *in = stdin;
	while (1) {
		int dir;
		int res;
		char buf[1048576];
		unsigned len = 0;

		memset(buf, 0, sizeof(buf));
		while (1) {
			char str[32];

			res = fscanf(in, "%30s", str);
			if (res != 1 && feof(in))
				return 0;

			if (res == 0)
				continue;

			if (strncmp(str, "read(", 5) == 0) {
				dir = 0;
				break;
			} else if (strncmp(str, "writev(", 7) == 0) {
				dir = 1;
				break;
			}
		}

		while (1) {
			int c = getc(in);
			if (c == '"') {
				while (1) {
					int val;

					c = getc(in);
					if (c == EOF) {
						fprintf(stderr, "eof in string\n");
						break;
					}
					if (c == '\n') {
						fprintf(stderr, "eol in string\n");
						break;
					}
					if (c == '"')
						break;
					if (c != '\\') {
						val = c;
					} else {
						c = getc(in);
						switch (c) {
						case 'n': val = '\n'; break;
						case 'r': val = '\r'; break;
						case 't': val = '\t'; break;
						case '"': val = '"'; break;
						case '\\': val = '\\'; break;
						case 'x':
							res = scanf("%x", &val);
							if (res != 1) {
								fprintf(stderr, "parse error\n");
								continue;
							}
							break;
						default:
							fprintf(stderr, "unknown sequence: '\\%c'\n", c);
							continue;
						}
					}
					buf[len++] = val;
				}
			}
			if (c == '\n')
				break;
		}
		process_buf(dir, buf, len);
		memset(buf, 0, len);
		len = 0;
	}
}
