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

int main(int argc, char *argv[])
{
    char *type;
    char *source;
    const char *mountpoint;
    char *options = NULL;
    char *command = NULL;
    char *setuid = NULL;
    int i;

    progname = argv[0];
    if (argc < 3) {
        fprintf(stderr,
                "usage: %s type#[source] mountpoint [-o opt[,opts...]]\n",
                progname);
        exit(1);
    }

    type = xstrdup(argv[1]);
    source = strchr(type, '#');
    if (source)
        *source++ = '\0';

    if (!type[0]) {
        fprintf(stderr, "%s: empty filesystem type\n", progname);
        exit(1);
    }
    mountpoint = argv[2];

    for (i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0)
            continue;
        if (strcmp(argv[i], "-o") == 0) {
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
                const char *ignore_opts[] = { "", "user", "nouser", "users",
                                              "auto", "noauto", "_netdev",
                                              NULL};
                if (strncmp(opt, "setuid=", 7) == 0) {
                    setuid = xstrdup(opt + 7);
                    ignore = 1;
                }
                for (j = 0; ignore_opts[j]; j++)
                    if (strcmp(opt, ignore_opts[j]) == 0)
                        ignore = 1;

                if (!ignore) {
                    int oldlen = options ? strlen(options) : 0;
                    options = xrealloc(options, oldlen + 1 + strlen(opt) + 1);
                    if (!oldlen)
                        strcpy(options, opt);
                    else {
                        strcat(options, ",");
                        strcat(options, opt);
                    }
                }
                opt = strtok(NULL, ",");
            }
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
