#define _GNU_SOURCE

#include <lufs/fs.h>
#include <lufs/proto.h>
#include <fuse.h>
#include "list.h"
#include "dircache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

struct fs_operations {
    void	*(*init)(struct list_head*, struct dir_cache*, struct credentials*, void**);
    void	(*free)(void*);
    int 	(*mount)(void*);
    void 	(*umount)(void*);
    int 	(*readdir)(void*, char*, struct directory*);
    int 	(*stat)(void*, char*, struct lufs_fattr*);
    int 	(*mkdir)(void*, char*, int);
    int 	(*rmdir)(void*, char*);
    int 	(*create)(void*, char*, int);
    int 	(*unlink)(void*, char*);
    int 	(*rename)(void*, char*, char*);
    int 	(*open)(void*, char*, unsigned);
    int 	(*release)(void*, char*);
    int 	(*read)(void*, char*, long long, unsigned long, char*);
    int		(*write)(void*, char*, long long, unsigned long, char*);
    int 	(*readlink)(void*, char*, char*, int);
    int 	(*link)(void*, char*, char*);
    int 	(*symlink)(void*, char*, char*);
    int 	(*setattr)(void*, char*, struct lufs_fattr*);
};

static struct fs_operations lu_fops;
static void *lu_dlhandle;
static struct list_head lu_cfg;
static void *lu_global_ctx;
static struct credentials lu_cred;
static void *lu_context;
static struct dir_cache *lu_cache;

#define BUF_SIZE	1024
#define PASSWD		"/etc/passwd"
#define GROUP		"/etc/group"

int lu_check_to(int rd_fd, int wr_fd, int time_out){
    fd_set rd, wr;
    int res, maxfd = 0;
    struct timeval tv;

    FD_ZERO(&rd);
    FD_ZERO(&wr);

    if(rd_fd){
	FD_SET(rd_fd, &rd);
	maxfd = rd_fd > maxfd ? rd_fd : maxfd;
    }

    if(wr_fd){
	FD_SET(wr_fd, &wr);
	maxfd = wr_fd > maxfd ? wr_fd : maxfd;
    }

    tv.tv_sec = time_out;
    tv.tv_usec = 0;

    do{
	res = select(maxfd + 1, &rd, &wr, NULL, &tv);

    }while((res < 0) && (errno == EINTR));    

    if(res > 0)
	return 0;

    if(res < 0){
	    WARN("select call failed: %s", strerror(errno));
	    return -errno;
    }
       
    WARN("operation timed out!");

    return -ETIMEDOUT;
}

int lu_atomic_read(int fd, char *buf, int len, int time_out){
    int res, offset = 0;

    do{
	if((time_out) && ((res = lu_check_to(fd, 0, time_out)) < 0))
	    return res;

	do{
	    res = read(fd, buf + offset, len - offset);
	}while((res < 0) && (errno == EINTR));

	if(res <= 0){
	    WARN("read call failed: %s", strerror(errno));
	    return (res < 0) ? -errno : (offset > 0 ? offset : -EPIPE);
	}

	offset += res;

    }while(offset < len);

    return offset;
}

int lu_atomic_write(int fd, char *buf, int len, int time_out){
    int res, offset = 0;

    do{
	if((time_out) && ((res = lu_check_to(0, fd, time_out)) < 0))
	    return res;

	do{
	    res = write(fd, buf + offset, len - offset);
	}while((res < 0) && (errno == EINTR));

	if(res <= 0){
	    WARN("write call failed: %s", strerror(errno));
	    return (res < 0) ? -errno : (offset > 0 ? offset : -EPIPE);
	}

	offset += res;

    }while(offset < len);

    return offset;
}

static int get_filesystem(const char *fs)
{
    char *buf;
    void *dlhandle;

    if(!(buf = (char*)malloc(strlen(fs) + 32)))
	return -1;

    sprintf(buf, "liblufs-%s.so", fs);
    if(!(dlhandle = dlopen(buf, RTLD_LAZY))){
	ERROR(dlerror());
	goto fail;
    }

    sprintf(buf, "%s_init", fs);
    if(!(lu_fops.init = (void*(*)(struct list_head*, struct dir_cache*, struct credentials*, void**))dlsym(dlhandle, buf))){
	ERROR(dlerror());
	goto fail_fops;
    }

    sprintf(buf, "%s_free", fs);
    if(!(lu_fops.free = (void(*)(void*))dlsym(dlhandle, buf))){
	ERROR(dlerror());
	goto fail_fops;
    }

    sprintf(buf, "%s_mount", fs);
    if(!(lu_fops.mount = (int(*)(void*))dlsym(dlhandle, buf))){
	ERROR(dlerror());
	goto fail_fops;
    }

    sprintf(buf, "%s_umount", fs);
    if(!(lu_fops.umount = (void(*)(void*))dlsym(dlhandle, buf)))
	ERROR(dlerror());

    sprintf(buf, "%s_readdir", fs);
    if(!(lu_fops.readdir = (int(*)(void*, char*, struct directory*))dlsym(dlhandle, buf)))
	ERROR(dlerror());

    sprintf(buf, "%s_stat", fs);
    if(!(lu_fops.stat = (int(*)(void*, char*, struct lufs_fattr*))dlsym(dlhandle, buf)))
	ERROR(dlerror());

    sprintf(buf, "%s_mkdir", fs);
    if(!(lu_fops.mkdir = (int(*)(void*, char*, int))dlsym(dlhandle, buf)))
	ERROR(dlerror());

    sprintf(buf, "%s_rmdir", fs);
    if(!(lu_fops.rmdir = (int(*)(void*, char*))dlsym(dlhandle, buf)))
	ERROR(dlerror());

    sprintf(buf, "%s_create", fs);
    if(!(lu_fops.create = (int(*)(void*, char*, int))dlsym(dlhandle, buf)))
	ERROR(dlerror());

    sprintf(buf, "%s_unlink", fs);
    if(!(lu_fops.unlink = (int(*)(void*, char*))dlsym(dlhandle, buf)))
	ERROR(dlerror());

    sprintf(buf, "%s_rename", fs);
    if(!(lu_fops.rename = (int(*)(void*, char*, char*))dlsym(dlhandle, buf)))
	ERROR(dlerror());

    sprintf(buf, "%s_open", fs);
    if(!(lu_fops.open = (int(*)(void*, char*, unsigned))dlsym(dlhandle, buf)))
	ERROR(dlerror());

    sprintf(buf, "%s_release", fs);
    if(!(lu_fops.release = (int(*)(void*, char*))dlsym(dlhandle, buf)))
	ERROR(dlerror());

    sprintf(buf, "%s_read", fs);
    if(!(lu_fops.read = (int(*)(void*, char*, long long, unsigned long, char*))dlsym(dlhandle, buf)))
	ERROR(dlerror());

    sprintf(buf, "%s_write", fs);
    if(!(lu_fops.write = (int(*)(void*, char*, long long, unsigned long, char*))dlsym(dlhandle, buf)))
	ERROR(dlerror());

    sprintf(buf, "%s_readlink", fs);
    if(!(lu_fops.readlink = (int(*)(void*, char*, char*, int))dlsym(dlhandle, buf)))
	ERROR(dlerror());

    sprintf(buf, "%s_link", fs);
    if(!(lu_fops.link = (int(*)(void*, char*, char*))dlsym(dlhandle, buf)))
	ERROR(dlerror());

    sprintf(buf, "%s_symlink", fs);
    if(!(lu_fops.symlink = (int(*)(void*, char*, char*))dlsym(dlhandle, buf)))
	ERROR(dlerror());

    sprintf(buf, "%s_setattr", fs);
    if(!(lu_fops.setattr = (int(*)(void*, char*, struct lufs_fattr*))dlsym(dlhandle, buf)))
	ERROR(dlerror());
    
    lu_dlhandle = dlhandle;
    free(buf);
    return 0;

  fail_fops:
    dlclose(dlhandle);
  fail:  
    free(buf);
    return -1;
}

static int lu_getattr_native(const char *path, struct lufs_fattr *fattr)
{
    if(!lu_fops.stat)
        return -ENOSYS;

    memset(fattr, 0, sizeof(struct lufs_fattr));
    if(lu_cache_lookup_file(lu_cache, (char *) path, fattr, NULL, 0) < 0) {
        if(lu_fops.stat(lu_context, (char *) path, fattr) < 0)
            return -ENOENT;
    }
    return 0;
}

static int lu_getattr(const char *path, struct stat *stbuf)
{
    struct lufs_fattr fattr;
    int res;
    
    res = lu_getattr_native(path, &fattr);
    if(res < 0)
        return res;

    stbuf->st_mode    = fattr.f_mode;
    stbuf->st_nlink   = fattr.f_nlink;
    stbuf->st_uid     = fattr.f_uid;
    stbuf->st_gid     = fattr.f_gid;
    stbuf->st_size    = fattr.f_size;
    stbuf->st_atime   = fattr.f_atime;
    stbuf->st_mtime   = fattr.f_mtime;
    stbuf->st_ctime   = fattr.f_ctime;
    stbuf->st_blksize = fattr.f_blksize;
    stbuf->st_blocks  = fattr.f_blocks;

    return 0;
}

static int lu_readlink(const char *path, char *buf, size_t size)
{
    int len;
    struct lufs_fattr fattr;

    if(!lu_fops.readlink)
        return -ENOSYS;

    if(lu_cache_lookup_file(lu_cache, (char *) path, &fattr, buf, size) < 0 ||
       strcmp(buf, "") == 0) {
        if((len = lu_fops.readlink(lu_context, (char *) path, buf, size)) < 0)
            return -EPERM;
        
        /* FUSE leaves one extra char free at the end */
        buf[len] = '\0';
    }
    
    return 0;
}

static int lu_getdir(const char *path, fuse_dirh_t h, fuse_dirfil_t filler)
{
    struct directory *dir;

    if(!lu_fops.readdir)
        return -ENOSYS;

    if(lu_cache_readdir(lu_cache, (char *) path, h, filler) < 0){
	if(!(dir = lu_cache_mkdir((char *) path)))
	    return -1;

	if(lu_fops.readdir(lu_context, (char *) path, dir) < 0){
	    lu_cache_killdir(dir);
	    return -1;
	}
	lu_cache_add_dir(lu_cache, dir);
	
	if(lu_cache_readdir(lu_cache, (char *) path, h, filler) < 0) {
	    return -EPERM;
	}
    }
    return 0;
}

static int lu_mknod(const char *path, mode_t mode, dev_t rdev)
{
    (void) rdev;
    if(!S_ISREG(mode) || !lu_fops.create)
        return -ENOSYS;
    
    if(lu_fops.create(lu_context, (char *) path, mode) < 0)
        return -EPERM;

    lu_cache_invalidate(lu_cache, (char *) path);
    return 0;
}

static int lu_mkdir(const char *path, mode_t mode)
{
    if(!lu_fops.mkdir)
        return -ENOSYS;
    
    if(lu_fops.mkdir(lu_context, (char *) path, mode) < 0)
        return -EPERM;

    lu_cache_invalidate(lu_cache, (char *) path);
    return 0;
}

static int lu_unlink(const char *path)
{
    if(!lu_fops.unlink)
        return -ENOSYS;
    
    if(lu_fops.unlink(lu_context, (char *) path) < 0)
        return -EPERM;

    lu_cache_invalidate(lu_cache, (char *) path);
    return 0;
}

static int lu_rmdir(const char *path)
{
    if(!lu_fops.rmdir)
        return -ENOSYS;
    
    if(lu_fops.rmdir(lu_context, (char *) path) < 0)
        return -EPERM;

    lu_cache_invalidate(lu_cache, (char *) path);
    return 0;
}

static int lu_symlink(const char *from, const char *to)
{
    if(!lu_fops.symlink)
        return -ENOSYS;
    
    if(lu_fops.symlink(lu_context, (char *) from, (char *) to) < 0)
        return -EPERM;

    lu_cache_invalidate(lu_cache, (char *) to);
    return 0;
}

static int lu_rename(const char *from, const char *to)
{
    if(!lu_fops.rename)
        return -ENOSYS;
    
    if(lu_fops.rename(lu_context, (char *) from, (char *) to) < 0)
        return -EPERM;

    lu_cache_invalidate(lu_cache, (char *) from);
    lu_cache_invalidate(lu_cache, (char *) to);
    return 0;
}

static int lu_link(const char *from, const char *to)
{
    if(!lu_fops.link)
        return -ENOSYS;
    
    if(lu_fops.link(lu_context, (char *) from, (char *) to) < 0)
        return -EPERM;

    lu_cache_invalidate(lu_cache, (char *) from);
    lu_cache_invalidate(lu_cache, (char *) to);
    return 0;
}

static int lu_chmod(const char *path, mode_t mode)
{
    int res;
    struct lufs_fattr fattr;

    if(!lu_fops.setattr)
        return -ENOSYS;
    
    res = lu_getattr_native(path, &fattr);
    if(res < 0)
        return res;

    fattr.f_mode = mode;
    if(lu_fops.setattr(lu_context, (char *) path, &fattr) < 0)
        return -EPERM;

    lu_cache_invalidate(lu_cache, (char *) path);
    return 0;
}

static int lu_chown(const char *path, uid_t uid, gid_t gid)
{
    int res;
    struct lufs_fattr fattr;

    if(!lu_fops.setattr)
        return -ENOSYS;
    
    res = lu_getattr_native(path, &fattr);
    if(res < 0)
        return res;

    if(uid != (uid_t) -1)
        fattr.f_uid = uid;
    if(gid != (gid_t) -1)
        fattr.f_gid = gid;
    if(lu_fops.setattr(lu_context, (char *) path, &fattr) < 0)
        return -EPERM;

    lu_cache_invalidate(lu_cache, (char *) path);
    return 0;

}

static int lu_truncate(const char *path, off_t size)
{
    int res;
    struct lufs_fattr fattr;

    if(!lu_fops.setattr)
        return -ENOSYS;
    
    res = lu_getattr_native(path, &fattr);
    if(res < 0)
        return res;

    fattr.f_size = size;
    if(lu_fops.setattr(lu_context, (char *) path, &fattr) < 0)
        return -EPERM;

    lu_cache_invalidate(lu_cache, (char *) path);
    return 0;
}

static int lu_utime(const char *path, struct utimbuf *buf)
{
    int res;
    struct lufs_fattr fattr;

    if(!lu_fops.setattr)
        return -ENOSYS;
    
    res = lu_getattr_native(path, &fattr);
    if(res < 0)
        return res;

    fattr.f_atime = buf->actime;
    fattr.f_mtime = buf->modtime;
    if(lu_fops.setattr(lu_context, (char *) path, &fattr) < 0)
        return -EPERM;

    lu_cache_invalidate(lu_cache, (char *) path);
    return 0;
}


static int lu_open(const char *path, int flags)
{
    if(!lu_fops.open)
        return -ENOSYS;

    if(lu_fops.open(lu_context, (char *) path, flags) < 0)
        return -EPERM;

    return 0;
}

static int lu_read(const char *path, char *buf, size_t size, off_t offset)
{
    int res;
    if(!lu_fops.read)
        return -ENOSYS;

    if((res = lu_fops.read(lu_context, (char *) path, offset, size, buf)) < 0)
        return -EPERM;

    return res;
}

static int lu_write(const char *path, const char *buf, size_t size,
                     off_t offset)
{
    if(!lu_fops.write)
        return -ENOSYS;

    if(lu_fops.write(lu_context, (char *) path, offset, size, (char *) buf) < 0)
        return -EPERM;

    return size;
}

static int lu_release(const char *path, int flags)
{
    (void) flags;
    if(!lu_fops.release)
        return -ENOSYS;

    if(lu_fops.release(lu_context, (char *) path) < 0)
        return -EPERM;

    return 0;
}

static int load_credentials(void)
{
    static char buf[BUF_SIZE];
    char srch_str[MAX_LEN + 4];
    long int uid, gid;
    int res, offset, chunk, readlen;
    char *c;

    TRACE("loading remote credentials for %s", lu_cred.user);

    if((!lu_fops.open) || (!lu_fops.read) || (!lu_fops.release)){
	WARN("unsupported operation");
	return -1;;
    }

    lu_cred.uid = lu_cred.gid = -1;

    if(lu_fops.open(lu_context, PASSWD, O_RDONLY) < 0){
	TRACE("could not open %s", PASSWD);
	return -1;
    }

    sprintf(srch_str, "\n%s:", lu_cred.user);
    chunk = strlen(srch_str) + 64;
    readlen = BUF_SIZE - chunk - 1;

    memset(buf, 32, chunk);
    offset = 0;

    do{
	res = lu_fops.read(lu_context, PASSWD, offset, readlen, (buf + chunk));
	if(res > 0){
	    *(buf + chunk + res) = 0;

	    if((c = strstr(buf, srch_str))){
		TRACE("username found!");
		if(!(c = strchr(c + strlen(srch_str), ':'))){
		    TRACE("separator not found!");
		}else{ 
		    if(sscanf(c , ":%li:%li:", &uid, &gid) != 2){
			TRACE("uid/gid not found!");
		    }else{
			TRACE("uid: %li, gid: %li", uid, gid);

			lu_cred.uid = uid;
			lu_cred.gid = gid;

			break;
		    }
		}
	    }

	    memcpy(buf, buf + BUF_SIZE - chunk - 1, chunk);
	    offset += res;
	}
    }while(res == readlen);

    lu_fops.release(lu_context, PASSWD);

    if(res <= 0){
	TRACE("read failed");
	return -1;
    }

    
    if(lu_fops.open(lu_context, GROUP, O_RDONLY) < 0){
	TRACE("could not open %s", GROUP);
	return -1;
    }

    sprintf(srch_str, ":%li:", (long)lu_cred.gid);
    chunk = strlen(srch_str) + 64;
    readlen = BUF_SIZE - chunk - 1;

    memset(buf, 32, chunk);
    offset = 0;

    do{
	res = lu_fops.read(lu_context, GROUP, offset, readlen, (buf + chunk));
	if(res > 0){
	    *(buf + chunk + res) = 0;

	    if((c = strstr(buf, srch_str))){
		TRACE("group found!");
		if(!(c = (char*)memrchr(buf, '\n', (c - buf)))){
		    TRACE("separator not found!");
		}else{ 
		    *(strchr(c, ':')) = 0;
		    if(strlen(c + 1) >= MAX_LEN){
			TRACE("groupname too long");
		    }else{
			strcpy(lu_cred.group, c + 1);
			TRACE("group: %s", lu_cred.group);
			break;
		    }
		}
	    }

	    memcpy(buf, buf + BUF_SIZE - chunk - 1, chunk);
	    offset += res;
	}
    }while(res == readlen);

    lu_fops.release(lu_context, GROUP);

    if(res <= 0){
	TRACE("read failed");
	return -1;
    }

    return 0;
}

static int lufis_init(int *argcp, char **argvp[])
{
    int argc = *argcp;
    char **argv = *argvp;
    int res;
    char *opts;
    const char *fs_name;

    if(argc < 2) {
        fprintf(stderr, "usage: %s opts\n", argv[0]);
        return -1;
    }

    INIT_LIST_HEAD(&lu_cfg);
    opts = argv[1];
    if(lu_opt_parse(&lu_cfg, "MOUNT", opts) < 0){
	ERROR("could not parse options!");
        return -1;
    }

    (*argcp)--;
    (*argvp)++;
    argv[1] = argv[0];


    lu_cache = lu_cache_create(&lu_cfg);
    if(!lu_cache)
        return -1;

    if(!(fs_name = lu_opt_getchar(&lu_cfg, "MOUNT", "fs"))){
	ERROR("you need to specify a file system!");
        return -1;
    }

    res = get_filesystem(fs_name);
    if(res == -1)
        return -1;

    if(!(lu_context = lu_fops.init(&lu_cfg, lu_cache, &lu_cred, &lu_global_ctx))) {
	ERROR("could not initialize file system!");
        return -1;
    }
    
    res = lu_fops.mount(lu_context);
    if(res) {
	if(load_credentials() < 0)
	    TRACE("could not load credentials.");
	else
	    TRACE("credentials loaded.");
    } else {
	WARN("fs mount failed...");
    }
    
    return 0;
}

static struct fuse_operations lu_oper = {
    .getattr	= lu_getattr,
    .readlink	= lu_readlink,
    .getdir	= lu_getdir,
    .mknod	= lu_mknod,
    .mkdir	= lu_mkdir,
    .symlink	= lu_symlink,
    .unlink	= lu_unlink,
    .rmdir	= lu_rmdir,
    .rename	= lu_rename,
    .link	= lu_link,
    .chmod	= lu_chmod,
    .chown	= lu_chown,
    .truncate	= lu_truncate,
    .utime	= lu_utime,
    .open	= lu_open,
    .read	= lu_read,
    .write	= lu_write,
    .release	= lu_release,
};

int main(int argc, char *argv[])
{
    int res;

    res = lufis_init(&argc, &argv);
    if(res == -1)
        exit(1);

    fuse_main(argc, argv, &lu_oper);
    return 0;
}
