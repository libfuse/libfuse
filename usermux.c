#include <fuse.h>

#include <pthread.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <wait.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#define MOUNTDIR "/mnt/avfs"

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static struct fuse *um_fuse;
static const char *um_dir;

#define MAX_USERS 100
static uid_t users[MAX_USERS];
static size_t numusers = 0;

void avfs_main(struct fuse *fuse);

static void reset_signal_handlers()
{
    struct sigaction sa;
	
    sa.sa_handler = SIG_DFL;
    sigemptyset(&(sa.sa_mask));
    sa.sa_flags = 0;
	
    sigaction(SIGCHLD, &sa, NULL);
}


static void start_avfs(uid_t uid)
{
    int res;
    char *userdir;
    struct fuse *user_fuse;
    struct passwd pw_buf;
    struct passwd *pw;
    char buf[1024];

    res = getpwuid_r(uid, &pw_buf, buf, sizeof(buf), &pw);
    if(pw == NULL)
        return;

    user_fuse = fuse_new(FUSE_MULTITHREAD, 0);
    
    userdir = g_strdup_printf("%s/%010u", MOUNTDIR, uid);
    mkdir(userdir, 0755);
    chown(userdir, pw->pw_uid, pw->pw_gid);
    res = fuse_mount(user_fuse, userdir);
    g_free(userdir);

    if(res == -1)
        return;

    res = fork();
    if(res == 0) {
        reset_signal_handlers();

        initgroups(pw->pw_name, pw->pw_gid);
        setgid(pw->pw_gid);
        setuid(pw->pw_uid);
        
        avfs_main(user_fuse);
        exit(0);
    }

    fuse_destroy(user_fuse);
}


static int find_user(const char *userstr, uid_t *uid)
{
    size_t i;
    char *end;
    
    *uid = strtol(userstr, &end, 10);
    if(*end != '\0')
        return 0;

    pthread_mutex_lock(&lock);
    for(i = 0; i < numusers; i++) {
        if(users[i] == *uid) {
            pthread_mutex_unlock(&lock);
            return 1;
        }
    }
    if(numusers == MAX_USERS) {
        memmove(users, users + sizeof(users[0]),
                (MAX_USERS - 1) * sizeof(users[0]));
        numusers --;
    }

    users[numusers++] = *uid;
    pthread_mutex_unlock(&lock);

    start_avfs(*uid);

    return 1;
}

static void root_attr(struct stat *stbuf)
{
    stbuf->st_mode = S_IFDIR | 0555;
    stbuf->st_nlink = 2 + numusers;
    stbuf->st_size = MAX_USERS;
    stbuf->st_blksize = 1024;
}

static int um_getattr(struct fuse_cred *cred, const char *path,
                      struct stat *stbuf)
{
    uid_t uid;
    memset(stbuf, 0, sizeof(*stbuf));

    if(strcmp(path, "/") == 0) {
        root_attr(stbuf);
        return 0;
    }

    if(!find_user(path+1, &uid))
        return -ENOENT;

    stbuf->st_mode = S_IFLNK | 0777;
    stbuf->st_nlink = 1;
    stbuf->st_size = strlen(MOUNTDIR) + 1 + 10;
    stbuf->st_blksize = 1024;
    stbuf->st_uid = uid;

    return 0;
}

static int um_readlink(struct fuse_cred *cred, const char *path, char *buf,
                       size_t size)
{
    uid_t uid;

    if(!find_user(path+1, &uid))
        return -ENOENT;

    snprintf(buf, size, "%s/%010u", MOUNTDIR, uid);
    return 0;
}

static int um_getdir(struct fuse_cred *cred, const char *path, fuse_dirh_t h,
                     fuse_dirfil_t filler)
{
    size_t i;

    if(strcmp(path, "/") != 0)
        return 0;
    
    filler(h, ".", 0);
    filler(h, "..", 0);

    pthread_mutex_lock(&lock);
    for(i = 0; i < numusers; i++) {
        char buf[32];

        sprintf(buf, "%u", users[i]);
        filler(h, buf, 0);
    }
    pthread_mutex_unlock(&lock);

    return 0;
}


static void exit_handler()
{
    exit(0);
}

static void child_handler()
{
    int status;
    wait(&status);
}

static void set_signal_handlers()
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

    sa.sa_handler = child_handler;
    if(sigaction(SIGCHLD, &sa, NULL) == -1) {
	perror("Cannot set child signal handler");
        exit(1);
    }
}

static void cleanup()
{
    fuse_unmount(um_fuse);
    fuse_destroy(um_fuse);
}

static struct fuse_operations um_oper = {
    getattr:	um_getattr,
    getdir:     um_getdir,
    readlink:	um_readlink,
};

int main(int argc, char *argv[])
{
    int res;
    if(argc != 2) {
        fprintf(stderr, "usage: %s mount_dir\n", argv[0]);
        exit(1);
    }
    
    um_dir = argv[1];

    set_signal_handlers();
    atexit(cleanup);

    um_fuse = fuse_new(FUSE_MULTITHREAD, 0);
    res = fuse_mount(um_fuse, um_dir);
    if(res == -1)
        exit(1);
        
    fuse_set_operations(um_fuse, &um_oper);
    fuse_loop(um_fuse);

    return 0;
}
