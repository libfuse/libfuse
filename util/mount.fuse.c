/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

static char *progname;

static char *xstrdup(const char *s)
{
	char *t = strdup(s);
	if (!t) {
		fprintf(stderr, "%s: failed to allocate memory\n", progname);
		exit(1);
	}
	return t;
}

static void *xrealloc(void *oldptr, size_t size)
{
	void *ptr = realloc(oldptr, size);
	if (!ptr) {
		fprintf(stderr, "%s: failed to allocate memory\n", progname);
		exit(1);
	}
	return ptr;
}

static void add_arg(char **cmdp, const char *opt)
{
	size_t optlen = strlen(opt);
	size_t cmdlen = *cmdp ? strlen(*cmdp) : 0;
	char *cmd = xrealloc(*cmdp, cmdlen + optlen * 4 + 4);
	char *s;
	s = cmd + cmdlen;
	if (*cmdp)
		*s++ = ' ';

	*s++ = '\'';
	for (; *opt; opt++) {
		if (*opt == '\'') {
			*s++ = '\'';
			*s++ = '\\';
			*s++ = '\'';
			*s++ = '\'';
		} else
			*s++ = *opt;
	}
	*s++ = '\'';
	*s = '\0';
	*cmdp = cmd;
}

static char *add_option(const char *opt, char *options)
{
	int oldlen = options ? strlen(options) : 0;

	options = xrealloc(options, oldlen + 1 + strlen(opt) + 1);
	if (!oldlen)
		strcpy(options, opt);
	else {
		strcat(options, ",");
		strcat(options, opt);
	}
	return options;
}

int main(int argc, char *argv[])
{
	char *type = NULL;
	char *source;
	const char *mountpoint;
	char *basename;
	char *options = NULL;
	char *command = NULL;
	char *setuid = NULL;
	int i;
	int dev = 1;
	int suid = 1;

	progname = argv[0];
	basename = strrchr(argv[0], '/');
	if (basename)
		basename++;
	else
		basename = argv[0];

	if (strncmp(basename, "mount.fuse.", 11) == 0)
		type = basename + 11;
	if (strncmp(basename, "mount.fuseblk.", 14) == 0)
		type = basename + 14;

	if (type && !type[0])
		type = NULL;

	if (argc < 3) {
		fprintf(stderr,
			"usage: %s %s destination [-t type] [-o opt[,opts...]]\n",
			progname, type ? "source" : "type#[source]");
		exit(1);
	}

	source = argv[1];
	if (!source[0])
		source = NULL;

	mountpoint = argv[2];

	for (i = 3; i < argc; i++) {
		if (strcmp(argv[i], "-v") == 0) {
			continue;
		} else if (strcmp(argv[i], "-t") == 0) {
			i++;

			if (i == argc) {
				fprintf(stderr,
					"%s: missing argument to option '-t'\n",
					progname);
				exit(1);
			}
			type = argv[i];
			if (strncmp(type, "fuse.", 5) == 0)
				type += 5;
			else if (strncmp(type, "fuseblk.", 8) == 0)
				type += 8;

			if (!type[0]) {
				fprintf(stderr,
					"%s: empty type given as argument to option '-t'\n",
					progname);
				exit(1);
			}
		} else	if (strcmp(argv[i], "-o") == 0) {
			char *opts;
			char *opt;
			i++;
			if (i == argc)
				break;

			opts = xstrdup(argv[i]);
			opt = strtok(opts, ",");
			while (opt) {
				int j;
				int ignore = 0;
				const char *ignore_opts[] = { "",
							      "user",
							      "nouser",
							      "users",
							      "auto",
							      "noauto",
							      "_netdev",
							      NULL};
				if (strncmp(opt, "setuid=", 7) == 0) {
					setuid = xstrdup(opt + 7);
					ignore = 1;
				}
				for (j = 0; ignore_opts[j]; j++)
					if (strcmp(opt, ignore_opts[j]) == 0)
						ignore = 1;

				if (!ignore) {
					if (strcmp(opt, "nodev") == 0)
						dev = 0;
					else if (strcmp(opt, "nosuid") == 0)
						suid = 0;

					options = add_option(opt, options);
				}
				opt = strtok(NULL, ",");
			}
		}
	}

	if (dev)
		options = add_option("dev", options);
	if (suid)
		options = add_option("suid", options);

	if (!type) {
		if (source) {
			type = xstrdup(source);
			source = strchr(type, '#');
			if (source)
				*source++ = '\0';
			if (!type[0]) {
				fprintf(stderr, "%s: empty filesystem type\n",
					progname);
				exit(1);
			}
		} else {
			fprintf(stderr, "%s: empty source\n", progname);
			exit(1);
		}
	}

	add_arg(&command, type);
	if (source)
		add_arg(&command, source);
	add_arg(&command, mountpoint);
	if (options) {
		add_arg(&command, "-o");
		add_arg(&command, options);
	}

	if (setuid && setuid[0]) {
		char *sucommand = command;
		command = NULL;
		add_arg(&command, "su");
		add_arg(&command, "-");
		add_arg(&command, setuid);
		add_arg(&command, "-c");
		add_arg(&command, sucommand);
	} else if (!getenv("HOME")) {
		/* Hack to make filesystems work in the boot environment */
		setenv("HOME", "/root", 0);
	}

	execl("/bin/sh", "/bin/sh", "-c", command, NULL);
	fprintf(stderr, "%s: failed to execute /bin/sh: %s\n", progname,
		strerror(errno));
	return 1;
}
