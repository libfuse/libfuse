#ifndef __FUSESTAT_H_
#define __FUSESTAT_H_
/* this is seperated out into its own file because both
 * kernel and lib use it, but neither can #include the
 * other's headerfile */
typedef struct fuse_statfs {
    long block_size;
    long blocks;
    long blocks_free;
    long files;
    long files_free;
    long namelen;
} fuse_statfs_t;
#endif
