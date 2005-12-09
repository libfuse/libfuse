/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB
*/

#include "fuse_opt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

struct fuse_opt_context {
    void *data;
    const struct fuse_opt *opt;
    fuse_opt_proc_t proc;
    int argctr;
    int argc;
    char **argv;
    int argcout;
    char **argvout;
    char *opts;
    int nonopt;
};

void fuse_opt_free_args(char *args[])
{
    int i;

    if (args) {
        for (i = 0; args[i]; i++)
            free(args[i]);
        free(args);
    }
}

static int alloc_failed(void)
{
    fprintf(stderr, "fuse: memory allocation failed\n");
    return -1;
}

int fuse_opt_add_arg(int *argcp, char **argvp[], const char *arg)
{
    char **newargv = realloc(*argvp, (*argcp + 2) * sizeof(char *));
    char *newarg = newargv ? strdup(arg) : NULL;
    if (!newargv || !newarg)
        return alloc_failed();

    newargv[(*argcp)++] = newarg;
    newargv[*argcp] = NULL;
    *argvp = newargv;
    return 0;
}

static int next_arg(struct fuse_opt_context *ctx, const char *opt)
{
    if (ctx->argctr + 1 >= ctx->argc) {
        fprintf(stderr, "fuse: missing argument after `%s'\n", opt);
        return -1;
    }
    ctx->argctr++;
    return 0;
}

static int add_arg(struct fuse_opt_context *ctx, const char *arg)
{
    return fuse_opt_add_arg(&ctx->argcout, &ctx->argvout, arg);
}

int fuse_opt_add_opt(char **opts, const char *opt)
{
    char *newopts;
    if (!*opts)
        newopts = strdup(opt);
    else {
        unsigned oldlen = strlen(*opts);
        newopts = realloc(*opts, oldlen + 1 + strlen(opt) + 1);
        if (newopts) {
            newopts[oldlen] = ',';
            strcpy(newopts + oldlen + 1, opt);
        }
    }
    if (!newopts)
        return alloc_failed();

    *opts = newopts;
    return 0;
}

static int add_opt(struct fuse_opt_context *ctx, const char *opt)
{
    return fuse_opt_add_opt(&ctx->opts, opt);
}

static int insert_arg(struct fuse_opt_context *ctx, int pos, const char *arg)
{
    assert(pos <= ctx->argcout);
    if (add_arg(ctx, arg) == -1)
        return -1;

    if (pos != ctx->argcout - 1) {
        char *newarg = ctx->argvout[ctx->argcout - 1];
        memmove(&ctx->argvout[pos+1], &ctx->argvout[pos], 
                sizeof(char *) * (ctx->argcout - pos - 1));
        ctx->argvout[pos] = newarg;
    }
    return 0;
}

static int call_proc(struct fuse_opt_context *ctx, const char *arg, int key,
                     int iso)
{
    int res;

    if (!ctx->proc) {
        fprintf(stderr, "fuse: unknown option `%s'\n", arg);
        return -1;
    }

    res = ctx->proc(ctx->data, arg, key);
    if (res == -1 || !res)
        return res;

    if (iso)
        return add_opt(ctx, arg);
    else
        return add_arg(ctx, arg);
}

static int match_template(const char *t, const char *arg, unsigned *sepp)
{
    int arglen = strlen(arg);
    const char *sep = strchr(t, '=');
    sep = sep ? sep : strchr(t, ' ');
    if (sep && (!sep[1] || sep[1] == '%')) {
        int tlen = sep - t;
        if (sep[0] == '=')
            tlen ++;
        if (arglen >= tlen && strncmp(arg, t, tlen) == 0) {
            *sepp = sep - t;
            return 1;
        }
    }
    if (strcmp(t, arg) == 0) {
        *sepp = 0;
        return 1;
    }
    return 0;
}

static const struct fuse_opt *find_opt(const struct fuse_opt *opt,
                                       const char *arg, unsigned *sepp)
{
    for (; opt && opt->template; opt++)
        if (match_template(opt->template, arg, sepp))
            return opt;
    return NULL;
}

int fuse_opt_match(const struct fuse_opt *opts, const char *opt)
{
    unsigned dummy;
    return find_opt(opts, opt, &dummy) ? 1 : 0;
}

static int process_opt_param(void *var, const char *format, const char *param,
                             const char *arg)
{
    assert(format[0] == '%');
    if (format[1] == 's') {
        char *copy = strdup(param);
        if (!copy)
            return alloc_failed();

        *(char **) var = copy;
    } else {
        if (sscanf(param, format, var) != 1) {
            fprintf(stderr, "fuse: invalid parameter in option `%s'\n", arg);
            return -1;
        }
    }
    return 0;
}

static int process_opt(struct fuse_opt_context *ctx,
                       const struct fuse_opt *opt, unsigned sep,
                       const char *arg, int iso)
{
    if (opt->offset == FUSE_OPT_OFFSET_KEY) {
        if (call_proc(ctx, arg, opt->value, iso) == -1)
            return -1;
    } else {
        void *var = ctx->data + opt->offset;
        if (sep && opt->template[sep + 1]) {
            const char *param = arg + sep;
            if (opt->template[sep] == '=')
                param ++;
            if (process_opt_param(var, opt->template + sep + 1,
                                  param, arg) == -1)
                return -1;
        } else
            *(int *)var = opt->value;
    }
    return 0;
}

static int process_opt_sep_arg(struct fuse_opt_context *ctx,
                               const struct fuse_opt *opt, unsigned sep,
                               const char *arg, int iso)
{
    int res;
    char *newarg;
    char *param;

    if (next_arg(ctx, arg) == -1)
        return -1;

    param = ctx->argv[ctx->argctr];
    newarg = malloc(sep + strlen(param) + 1);
    if (!newarg)
        return alloc_failed();

    memcpy(newarg, arg, sep);
    strcpy(newarg + sep, param);
    res = process_opt(ctx, opt, sep, newarg, iso);
    free(newarg);

    return res;
}

static int process_gopt(struct fuse_opt_context *ctx, const char *arg, int iso)
{
    unsigned sep;
    const struct fuse_opt *opt = find_opt(ctx->opt, arg, &sep);
    if (opt) {
        for (; opt; opt = find_opt(opt + 1, arg, &sep)) {
            int res;
            if (sep && opt->template[sep] == ' ' && !arg[sep])
                res = process_opt_sep_arg(ctx, opt, sep, arg, iso);
            else
                res = process_opt(ctx, opt, sep, arg, iso);
            if (res == -1)
                return -1;
        }
        return 0;
    } else
        return call_proc(ctx, arg, FUSE_OPT_KEY_OPT, iso);
}

static int process_real_option_group(struct fuse_opt_context *ctx, char *opts)
{
    char *sep;

    do {
        int res;
        sep = strchr(opts, ',');
        if (sep)
            *sep = '\0';
        res = process_gopt(ctx, opts, 1);
        if (res == -1)
            return -1;
        opts = sep + 1;
    } while (sep);

    return 0;
}

static int process_option_group(struct fuse_opt_context *ctx, const char *opts)
{
    int res;
    char *copy;
    const char *sep = strchr(opts, ',');
    if (!sep)
        return process_gopt(ctx, opts, 1);

    copy = strdup(opts);
    if (!copy) {
        fprintf(stderr, "fuse: memory allocation failed\n");
        return -1;
    }
    res = process_real_option_group(ctx, copy);
    free(copy);
    return res;
}

static int process_one(struct fuse_opt_context *ctx, const char *arg)
{
    if (ctx->nonopt || arg[0] != '-')
        return call_proc(ctx, arg, FUSE_OPT_KEY_NONOPT, 0);
    else if (arg[1] == 'o') {
        if (arg[2])
            return process_option_group(ctx, arg + 2);
        else {
            if (next_arg(ctx, arg) == -1)
                return -1;

            return process_option_group(ctx, ctx->argv[ctx->argctr]);
        }
    } else if (arg[1] == '-' && !arg[2]) {
        if (add_arg(ctx, arg) == -1)
            return -1;
        ctx->nonopt = 1;
        return 0;
    } else
        return process_gopt(ctx, arg, 0);
}

static int opt_parse(struct fuse_opt_context *ctx)
{
    if (ctx->argc) {
        if (add_arg(ctx, ctx->argv[0]) == -1)
            return -1;
    }

    for (ctx->argctr = 1; ctx->argctr < ctx->argc; ctx->argctr++)
        if (process_one(ctx, ctx->argv[ctx->argctr]) == -1)
            return -1;

    if (ctx->opts) {
        if (insert_arg(ctx, 1, "-o") == -1 ||
            insert_arg(ctx, 2, ctx->opts) == -1)
            return -1;
    }
    return 0;
}

int fuse_opt_parse(int argc, char *argv[], void *data,
                   const struct fuse_opt opts[], fuse_opt_proc_t proc,
                   int *argcout, char **argvout[])
{
    int res;
    struct fuse_opt_context ctx = {
        .argc = argv ? argc : *argcout,
        .argv = argv ? argv : *argvout,
        .data = data,
        .opt = opts,
        .proc = proc,
        .argcout = 0,
        .argvout = NULL,
        .opts = NULL,
        .nonopt = 0,
    };

    res = opt_parse(&ctx);
    if (!argv)
        fuse_opt_free_args(ctx.argv);
    free(ctx.opts);
    if (res == -1)
        fuse_opt_free_args(ctx.argvout);
    else {
        if (argcout)
            *argcout = ctx.argcout;
        if (argvout)
            *argvout = ctx.argvout;
        else
            fuse_opt_free_args(ctx.argvout);
    }
    return res;
}
