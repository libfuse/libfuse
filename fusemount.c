/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998-2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "fuse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <mntent.h>
#include <glib.h>

static char *mount_dir;

const char *basedir = "/tmp/pro";

struct node {
    char *name;
    unsigned long ino;
};

static GNode *root;
static GHashTable *nodetab;
static unsigned long inoctr = FUSE_ROOT_INO;

static GNode *new_node(const char *name, unsigned long ino)
{
    struct node *node = g_new0(struct node, 1);
    GNode *gn = g_node_new(node);
    
    node->name = g_strdup(name);
    node->ino = ino;

    return gn;
}

static unsigned long find_node(unsigned long ino, const char *name)
{
    GNode *cn;
    GNode *pn = g_hash_table_lookup(nodetab, (gpointer) ino);
    if(pn == NULL) {
        fprintf(stderr, "Can't find parent node %li\n", ino);
        return 0;
    }
    
    for(cn = pn->children; cn != NULL; cn = cn->next) {
        struct node *node = (struct node *) cn->data;
        if(strcmp(node->name, name) == 0)
            return node->ino;
    }

    do inoctr++;
    while(!inoctr && g_hash_table_lookup(nodetab, (gpointer) ino) != NULL);
    
    cn = new_node(name, inoctr);
    g_node_insert(pn, -1, cn);
    g_hash_table_insert(nodetab, (gpointer) inoctr, cn);
    
    return inoctr;
}

static char *real_path(unsigned long ino)
{
    GString *s;
    char *ss;
    GNode *gn = g_hash_table_lookup(nodetab, (gpointer) ino);

    if(gn == NULL) {
        fprintf(stderr, "Can't find node %li\n", ino);
        return NULL;
    }
    
    s = g_string_new("");
    for(; gn != NULL; gn = gn->parent) {
        g_string_prepend(s, ((struct node *) gn->data)->name);
        g_string_prepend_c(s, '/');
    }
    g_string_prepend(s, basedir);
    ss = s->str;
    g_string_free(s, FALSE);
    
    return ss;
}

static int get_dir(unsigned long dir)
{
    int dirfd;
    struct fuse_dirent dirent;
    DIR *dp;
    struct dirent *de;
    size_t reclen;
    char *path;
    
    path = real_path(dir);
    if(path == NULL)
        return -ENOENT;

    dp = opendir(path);
    g_free(path);
    if(dp == NULL) {
        perror(path);
        return -errno;
    }
    dirfd = open("/tmp/dirtmp", O_RDWR | O_TRUNC | O_CREAT, 0600);
    if(dirfd == -1) {
        perror("/tmp/dirtmp");
        exit(1);
    }
    while((de = readdir(dp)) != NULL) {
        unsigned long ino = find_node(dir, de->d_name);
        assert(ino != 0);

        dirent.ino = ino;
        dirent.namelen = strlen(de->d_name);
        assert(dirent.namelen <= NAME_MAX);
        strcpy(dirent.name, de->d_name);
        dirent.type = de->d_type;

        reclen = FUSE_DIRENT_SIZE(&dirent);
        write(dirfd, &dirent, reclen);
    }
    closedir(dp);

    return dirfd;
}

static int get_attributes(unsigned long ino, struct fuse_attr *attr)
{
    char *path;
    struct stat buf;
    int res;
    
    path = real_path(ino);
    if(path == NULL)
        return -ENOENT;

    res = stat(path, &buf);
    g_free(path);
    if(res == -1)
        return -errno;

    attr->mode    = buf.st_mode;
    attr->nlink   = buf.st_nlink;
    attr->uid     = buf.st_uid;
    attr->gid     = buf.st_gid;
    attr->rdev    = buf.st_rdev;
    attr->size    = buf.st_size;
    attr->blksize = buf.st_blksize;
    attr->blocks  = buf.st_blocks;
    attr->atime   = buf.st_atime;
    attr->mtime   = buf.st_mtime;
    attr->ctime   = buf.st_ctime;
    
    return 0;
}

static void loop(int devfd)
{
    int res;
    struct fuse_param param;
    struct fuse_outparam out;
    struct fuse_inparam in;
    int dirfd;
    
    while(1) {
        res = read(devfd, &param, sizeof(param));
        if(res == -1) {
            perror("read");
            exit(1);
        }

        printf("unique: %i, opcode: %i\n", param.unique, param.u.i.opcode);

        dirfd = -1;
        in = param.u.i;
        switch(in.opcode) {
        case FUSE_LOOKUP:
            out.u.lookup.ino = find_node(in.ino, in.u.lookup.name);
            if(out.u.lookup.ino == 0)
                out.result = -ENOENT;
            else
                out.result = get_attributes(out.u.lookup.ino,
                                            &out.u.lookup.attr);
            break;

        case FUSE_GETATTR:
            out.result = get_attributes(in.ino, &out.u.getattr.attr);
            break;

        case FUSE_OPEN:
            dirfd = get_dir(in.ino);
            if(dirfd >= 0) {
                out.u.open.fd = dirfd;
                out.result = 0;
            }
            else
                out.result = dirfd;
            break;

        case FUSE_RELEASE:
            out.result = 0;
            break;

        default:
            out.result = -EOPNOTSUPP;
        }
        param.u.o = out;
                
        res = write(devfd, &param, sizeof(param));
        if(res == -1) {
            perror("write");
            exit(1);
        }
        if(dirfd != -1) {
            close(dirfd);
            unlink("/tmp/dirtmp");
        }
    }
}

static int mount_fuse(const char *dev, const char *dir, int devfd)
{
    int res;
    const char *type;
    FILE *fd;
    struct mntent ent;
    struct fuse_mount_data data;
    
    data.version = FUSE_MOUNT_VERSION;
    data.fd = devfd;

    type = "fuse";
    res = mount(dev, dir, type, MS_MGC_VAL | MS_NOSUID | MS_NODEV, &data);
    
    if(res == -1) {
        fprintf(stderr, "mount failed: %s\n", strerror(errno));
	return -1;
    }
    
    fd = setmntent("/etc/mtab", "a");
    if(fd == NULL) {
	fprintf(stderr, "setmntent(\"/etc/mtab\") failed: %s\n",
		strerror(errno));
	return -1;
    }
    
    ent.mnt_fsname = (char *) dev;
    ent.mnt_dir = (char *) dir;
    ent.mnt_type = (char *) type;
    ent.mnt_opts = "rw,nosuid,nodev";
    ent.mnt_freq = 0;
    ent.mnt_passno = 0;
    res = addmntent(fd, & ent);
    if(res != 0)
	fprintf(stderr, "addmntent() failed: %s\n", strerror(errno));
    
    endmntent(fd);
    
    return 0;
}

int unmount_fuse(const char *dir)
{
    int res;
    FILE *fdold, *fdnew;
    struct mntent *entp;
    
    res = umount(dir);
    
    if(res == -1) {
        fprintf(stderr, "umount failed: %s\n", strerror(errno));
	return -1;
    }
    
    fdold = setmntent("/etc/mtab", "r");
    if(fdold == NULL) {
	fprintf(stderr, "setmntent(\"/etc/mtab\") failed: %s\n",
		strerror(errno));
	return -1;
    }

    fdnew = setmntent("/etc/mtab~", "w");
    if(fdnew == NULL) {
	fprintf(stderr, "setmntent(\"/etc/mtab~\") failed: %s\n",
		strerror(errno));
	return -1;
    }

    do {
	entp = getmntent(fdold);
	if(entp != NULL) {
	    if(strcmp(entp->mnt_dir, dir) != 0) {
		res = addmntent(fdnew, entp);
		if(res != 0) {
		    fprintf(stderr, "addmntent() failed: %s\n",
			    strerror(errno));
		}
	    }
	}
    } while(entp != NULL);

    endmntent(fdold);
    endmntent(fdnew);

    res = rename("/etc/mtab~", "/etc/mtab");
    if(res == -1) {
	fprintf(stderr, "rename(\"/etc/mtab~\", \"/etc/mtab\") failed: %s\n", 
		strerror(errno));
	return -1;
    }
    
    return 0;
}

void cleanup()
{
    unmount_fuse(mount_dir);
}


void exit_handler()
{
    exit(0);
}

void set_signal_handlers()
{
    struct sigaction sa;

    sa.sa_handler = exit_handler;
    sigemptyset(&(sa.sa_mask));
    sa.sa_flags = 0;

    if (sigaction(SIGHUP, &sa, NULL) == -1 || 
	sigaction(SIGINT, &sa, NULL) == -1 || 
	sigaction(SIGTERM, &sa, NULL) == -1) {
	
	perror("Cannot set exit signal handlers");
        exit(1);
    }

    sa.sa_handler = SIG_IGN;
    
    if(sigaction(SIGPIPE, &sa, NULL) == -1) {
	perror("Cannot set ignored signals");
        exit(1);
    }
}


int main(int argc, char *argv[])
{
    const char *dev;
    int devfd;

    if(argc < 3) {
        fprintf(stderr, "usage: %s dev dir\n", argv[0]);
        exit(1);
    }

    dev = argv[1];
    mount_dir = argv[2];

    devfd = open(dev, O_RDWR);
    if(devfd == -1) {
        fprintf(stderr, "failed to open %s: %s\n", dev, strerror(errno));
        exit(1);
    }

    mount_fuse(dev, mount_dir, devfd);

    set_signal_handlers();
    atexit(cleanup);

    root = new_node("/", FUSE_ROOT_INO);
    nodetab = g_hash_table_new(NULL, NULL);
    g_hash_table_insert(nodetab, (gpointer) FUSE_ROOT_INO, root);

    loop(devfd);
    
    return 0;
}



