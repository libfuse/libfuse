/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#ifndef _FUSE_OPT_H_
#define _FUSE_OPT_H_

/* This file defines the option parsing interface of FUSE */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Special 'offset' value.  In case of a match, the processing
 * function will be called with 'value' as the key
 */
#define FUSE_OPT_OFFSET_KEY -1U

/**
 * Option description
 *
 * This structure describes a single option, and and action associated
 * with it, in case it matches.
 *
 * More than one such match may occur, in which case the action for
 * each match is executed.
 *
 * There are three possible actions in case of a match:
 *
 * i) An integer (int or unsigned) variable determined by 'offset' is
 *    set to 'value'
 *
 * ii) The processing function is called, with 'value' as the key
 *
 * iii) An integer (any) or string (char *) variable determined by
 *    'offset' is set to the value of an option parameter
 *
 * 'offset' should normally be either set to
 *
 *  - 'offsetof(struct foo, member)'  actions i) and iii)
 *
 *  - FUSE_OPT_OFFSET_KEY             action ii)
 *
 * The 'offsetof()' macro is defined in the <stddef.h> header.
 *
 * The template determines which options match, and also have an
 * effect on the action.  Normally the action is either i) or ii), but
 * if a format is present in the template, then action iii) is
 * performed.
 *
 * The types of templates are:
 *
 * 1) "-x", "-foo", "--foo", "--foo-bar", etc.  These match only
 *   themselves.  Invalid values are "--" and anything beginning
 *   with "-o"
 *
 * 2) "foo", "foo-bar", etc.  These match "-ofoo", "-ofoo-bar" or
 *    the relevant option in a comma separated option list
 *
 * 3) "bar=", "--foo=", etc.  These are variations of 1) and 2)
 *    which have a parameter
 *
 * 4) "bar=%s", "--foo=%lu", etc.  Same matching as above but perform
 *    action iii).
 *
 * 5) "-x ", etc.  Matches either "-xparam" or "-x param" as
 *    two separate arguments
 *
 * 6) "-x %s", etc.  Combination of 4) and 5)
 *
 * If the format is "%s", memory is allocated for the string unlike
 * with scanf().
 */
struct fuse_opt {
    /** Matching template and optional parameter formatting */
    const char *template;

    /**
     * Offset of variable within 'data' parameter of fuse_opt_parse()
     * or FUSE_OPT_OFFSET_KEY
     */
    unsigned long offset;

    /**
     * Value to set the variable to, or to be passed as 'key' to the
     * processing function.  Ignored if template a format
     */
    int value;
};

/**
 * Last option.  An array of 'struct fuse_opt' must end with a NULL
 * template value
 */
#define FUSE_OPT_END { .template = NULL }


/**
 * Key value passed to the processing function if an option did not
 * match any templated
 */
#define FUSE_OPT_KEY_OPT     -1

/**
 * Key value passed to the processing function for all non-options
 *
 * Non-options are the arguments beginning with a charater other than
 * '-' or all arguments after the special '--' option
 */
#define FUSE_OPT_KEY_NONOPT  -2

/**
 * Processing function
 *
 * This function is called if
 *    - option did not match any 'struct fuse_opt'
 *    - argument is a non-option
 *    - option did match and offset was set to FUSE_OPT_OFFSET_KEY
 *
 * The 'arg' parameter will always contain the whole argument or
 * option including the parameter if exists.  A two-argument option
 * ("-x foo") is always converted to single arguemnt option of the
 * form "-xfoo" before this function is called.
 *
 * Options of the form '-ofoo' are passed to this function without the
 * '-o' prefix.
 *
 * The return value of this function determines whether this argument
 * is to be inserted into the output argument vector, or discarded.
 *
 * @param data is the user data passed to the fuse_opt_parse() function
 * @param arg is the whole argument or option
 * @param key determines why the processing function was called
 * @return -1 on error, 0 if arg is to be discarded, 1 if arg should be kept
 */
typedef int (*fuse_opt_proc_t)(void *data, const char *arg, int key);

/**
 * Option parsing function
 *
 * If 'argv' is NULL, the values pointed by argcout and argvout will
 * be used as input
 *
 * A NULL 'opts' is the same as an 'opts' array containing a single
 * end marker
 *
 * If 'proc' is NULL, then any non-matching options will cause an
 * error to be returned
 *
 * If argvout is NULL, then any output arguments are discarded
 *
 * If argcout is NULL, then the output argument count is not stored
 *
 * @param argc is the input argument count
 * @param argv is the input argument vector, may be NULL
 * @param data is the user data
 * @param opts is the option description array, may be NULL
 * @param proc is the processing function, may be NULL
 * @param argcout is pointer to output argument count, may be NULL
 * @param argvout is pointer to output argument vector, may be NULL
 * @return -1 on error, 0 on success
 */
int fuse_opt_parse(int argc, char *argv[], void *data,
                   const struct fuse_opt opts[], fuse_opt_proc_t proc,
                   int *argcout, char **argvout[]);

/**
 * Add an option to a comma separated option list
 *
 * @param opts is a pointer to an option list, may point to a NULL value
 * @param opt is the option to add
 * @return -1 on allocation error, 0 on success
 */
int fuse_opt_add_opt(char **opts, const char *opt);

/**
 * Add an argument to a NULL terminated argument vector
 *
 * @param argcp is a pointer to argument count
 * @param argvp is a pointer to argument vector
 * @param arg is the new argument to add
 * @return -1 on allocation error, 0 on success
 */
int fuse_opt_add_arg(int *argcp, char **argvp[], const char *arg);

/**
 * Free argument vector
 *
 * @param args is the argument vector
 */
void fuse_opt_free_args(char *args[]);


/**
 * Check if an option matches
 *
 * @param opts is the option description array
 * @param opt is the option to match
 * @return 1 if a match is found, 0 if not
 */
int fuse_opt_match(const struct fuse_opt opts[], const char *opt);

#ifdef __cplusplus
}
#endif

#endif /* _FUSE_OPT_H_ */
