#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/smp_lock.h>
#include <asm/uaccess.h>
#include <linux/coda_psdev.h>
#include <linux/version.h>

#if 0
#define DEB(X) printk X
#else
#define DEB(X)
#endif

#define REDIR_VERSION "0.3"

extern void *sys_call_table[];

typedef asmlinkage int (*chdir_func)    (const char *);
typedef asmlinkage int (*stat_func)     (const char *, struct stat *);
typedef asmlinkage int (*access_func)   (const char *, int);
typedef asmlinkage int (*open_func)     (const char *, int, int);
typedef asmlinkage int (*readlink_func) (const char *, char *, int);
typedef asmlinkage int (*getcwd_func)   (char *, unsigned long);

static chdir_func    orig_chdir;
static stat_func     orig_stat;
static stat_func     orig_lstat;
static access_func   orig_access;
static open_func     orig_open;
static readlink_func orig_readlink;
static getcwd_func   orig_getcwd;

typedef asmlinkage long (*stat64_func)   (const char *, struct stat64 *, long);

static stat64_func   orig_stat64;
static stat64_func   orig_lstat64;

#ifdef __i386__
typedef asmlinkage int (*execve_func) (struct pt_regs);

static execve_func orig_execve;
#endif

#define AVFS_MAGIC_CHAR '#'

#define PF_AVFS 0x00008000

#define OVERLAY_BASE "/mnt/tmp"

#define path_ok(pwd) (pwd->d_parent == pwd || !list_empty(&pwd->d_hash))

static char *path_pwd(char *page)
{
        return d_path(current->fs->pwd, current->fs->pwdmnt, page, PAGE_SIZE);
}

static int a_path_walk(const char *pathname, int flags, struct nameidata *nd)
{
        int error;

        error = 0;
        if (path_init(pathname, flags, nd))
                error = path_walk(pathname, nd);

        return error;
}

static void a_path_release(struct nameidata *nd)
{
        dput(nd->dentry);
        mntput(nd->mnt);
}

static char *resolv_virt(const char *pathname, int must_exist, int flags)
{
        struct nameidata root;
	struct nameidata nd;
        struct dentry *origroot;
        struct vfsmount *origrootmnt;
	char *newpathname = NULL;
	char *page = NULL;
	char *path = NULL;
	int pathlen = 0;
        int error;
        int newflags;
        char overlay_dir[128];
        unsigned overlay_dir_len;
        
        sprintf(overlay_dir, "%s/%u", OVERLAY_BASE, current->fsuid);
        overlay_dir_len = strlen(overlay_dir);
        
	lock_kernel();

	DEB((KERN_INFO "resolve_virt pathname: '%s'\n", 
	       pathname ? pathname : "(null)"));

        error = a_path_walk(overlay_dir, LOOKUP_POSITIVE|LOOKUP_FOLLOW, &root);
        if(error)
            goto out;

	origroot = current->fs->root;
        origrootmnt = current->fs->rootmnt;

	current->fs->root = root.dentry;
        current->fs->rootmnt = root.mnt;
	
        newflags = flags;
        if(must_exist)
                newflags |= LOOKUP_POSITIVE;

        error  = a_path_walk(pathname, newflags, &nd);
	if(!error) {
		if(path_ok(nd.dentry)) {
			page = (char *) __get_free_page(GFP_USER);
			if(page) {
				path = d_path(nd.dentry, nd.mnt, page,
                                              PAGE_SIZE);
				DEB((KERN_INFO "resolve_virt path = '%s'\n",
				     path));
				pathlen = (unsigned int) page + PAGE_SIZE - 
					(unsigned int) path;
			}
		}
                a_path_release(&nd);
	}

	current->fs->root = origroot;
        current->fs->rootmnt = origrootmnt;

        a_path_release(&root);

	if(path) {
		int isvirtual;

                error  = a_path_walk(path, flags, &nd);
		if(!error) {
			if(nd.dentry->d_inode)
				isvirtual = 0;
			else if(must_exist)
				isvirtual = 1;
			else if(strchr(path, AVFS_MAGIC_CHAR))
				isvirtual = 1;
			else 
				isvirtual = 0;

                        a_path_release(&nd);
		}
		else {
			isvirtual = 1;
		}

		if(!isvirtual) {
			newpathname = kmalloc(pathlen + 1, GFP_USER);
			if(newpathname)
				strncpy(newpathname, path, pathlen);
		}
		else {
			newpathname = kmalloc(overlay_dir_len + pathlen + 1,
					      GFP_USER);

			if(newpathname) {
				strcpy(newpathname, overlay_dir);
				strncat(newpathname, path, pathlen);
			}
		}
	}

	if(page)
		free_page((unsigned long) page);


	DEB((KERN_INFO "resolve_virt newpathname: '%s'\n", 
	     newpathname ? newpathname : "(null)"));

  out:
	unlock_kernel();
	return newpathname;
}


#define FUSE_SUPER_MAGIC 0x65735546

#define cwd_virtual() \
	(current->fs->pwd->d_sb->s_magic == FUSE_SUPER_MAGIC)

static char *get_abs_path(const char *filename)
{
	char *cwd;
	int cwdlen, fnamelen;
	char *abspath, *s;
	char *page;
        char overlay_dir[128];
        unsigned overlay_dir_len;
        
        sprintf(overlay_dir, "/mnt/avfs/%010u", current->fsuid);
        overlay_dir_len = strlen(overlay_dir);

        if(!path_ok(current->fs->pwd))
                return NULL;

        page = (char *) __get_free_page(GFP_USER);
	if(!page)
		return NULL;

        cwd = path_pwd(page);
	cwdlen = (unsigned int) page + PAGE_SIZE - (unsigned int) cwd - 1;
	if(cwd_virtual() && cwdlen > overlay_dir_len) {
		cwd += overlay_dir_len;
		cwdlen -= overlay_dir_len;
	}
		

	fnamelen = strlen(filename);

	abspath = kmalloc(cwdlen + 1 + fnamelen + 1, GFP_USER);
	if(abspath) {
		s = abspath;
		strncpy(s, cwd, cwdlen);
		s += cwdlen;
		*s++ = '/';
		strncpy(s, filename, fnamelen + 1);
	}
	free_page((unsigned long) page);
	
	return abspath;
}

static char *resolve_name(const char *kfilename, int must_exist, int flags)
{
	char *tmp;
	char *newfilename;		

	tmp = getname(kfilename);
	if(IS_ERR(tmp))
		return tmp;


	if((tmp[0] != '/' && cwd_virtual()) || strchr(tmp, AVFS_MAGIC_CHAR)) {
		DEB((KERN_INFO "resolve_name: %s (%i/%s)\n", tmp, 
		     current->pid,
		     (current->flags & PF_AVFS) ? "on" : "off"));

		if(strcmp(tmp, "/#avfs-on") == 0) {
			printk(KERN_INFO "AVFS ON  (pid: %i)\n",
			       current->pid);
			current->flags |= PF_AVFS;
			newfilename = ERR_PTR(-EEXIST);
		}
		else if(!(current->flags & PF_AVFS))
			newfilename = NULL;
		else if(strcmp(tmp, "/#avfs-off") == 0) {
			printk(KERN_INFO "AVFS OFF (pid: %i)\n",
			       current->pid);
			current->flags &= ~PF_AVFS;
			newfilename = ERR_PTR(-EEXIST);
		}
		else {
			if(tmp[0] == '/') {
				newfilename = resolv_virt(tmp, must_exist, flags);
			}
			else {
				char *abspath;

				abspath = get_abs_path(tmp);
				if(abspath) {
					newfilename = resolv_virt(abspath, must_exist, flags);
					kfree(abspath);
				}
				else
					newfilename = NULL;
			}
		}
	}
	else 
		newfilename = NULL;
	
	putname(tmp);
	
	return newfilename;
}

asmlinkage int virt_chdir(const char *filename)
{
	int ret;
	mm_segment_t old_fs;
	char *newfilename;
	
	if(!cwd_virtual()) {
		ret = (*orig_chdir)(filename);
		if(ret != -ENOENT) 
			return ret;
	}
	else 
		ret = 0;

	newfilename = resolve_name(filename, 1, 1);
	if(!newfilename) {
		if(ret)
			return ret;
		else
			return (*orig_chdir)(filename);
	}
	if(IS_ERR(newfilename))
			return PTR_ERR(newfilename);


	DEB((KERN_INFO "CHDIR: trying '%s'\n", newfilename));
		
	old_fs = get_fs();
	set_fs(get_ds());
	ret =  (*orig_chdir)(newfilename);
	set_fs(old_fs);
	kfree(newfilename);

	DEB((KERN_INFO "CHDIR: result %i\n", ret));
	
	return ret;
}

static int do_orig_stat(stat_func sfunc, const char *filename,
			struct stat *statbuf)
{
	int ret;
	mm_segment_t old_fs;
	struct stat locbuf;

	old_fs = get_fs();
	set_fs(get_ds());
	ret =  (*sfunc)(filename, &locbuf);
	set_fs(old_fs);

	if(ret == 0)
		ret = (copy_to_user(statbuf, &locbuf, sizeof(locbuf)) ? 
		       -EFAULT : 0);

	return ret;
}

asmlinkage int virt_stat(const char *filename, struct stat *statbuf)
{
	int ret;
	char *newfilename;

	if(!cwd_virtual()) {
		ret = (*orig_stat)(filename, statbuf);
		if(ret != -ENOENT) 
			return ret;
	}
	else 
		ret = 0;

	newfilename = resolve_name(filename, 1, 1);
	if(!newfilename) {
		if(ret)
			return ret;
		else
			return (*orig_stat)(filename, statbuf);
	}
	if(IS_ERR(newfilename))
			return PTR_ERR(newfilename);

	DEB((KERN_INFO "STAT: trying '%s'\n", newfilename));

	ret = do_orig_stat(orig_stat, newfilename, statbuf);
	kfree(newfilename);

	DEB((KERN_INFO "STAT: result %i\n", ret));

	return ret;
}

asmlinkage int virt_lstat(const char *filename, struct stat *statbuf)
{
	int ret;
	char *newfilename;

	if(!cwd_virtual()) {
		ret = (*orig_lstat)(filename, statbuf);
		if(ret != -ENOENT) 
			return ret;
	}
	else 
		ret = 0;

	newfilename = resolve_name(filename, 1, 0);
	if(!newfilename) {
		if(ret)
			return ret;
		else
			return (*orig_lstat)(filename, statbuf);
	}
	if(IS_ERR(newfilename))
			return PTR_ERR(newfilename);

	DEB((KERN_INFO "LSTAT: trying '%s'\n", newfilename));

	ret = do_orig_stat(orig_lstat, newfilename, statbuf);
	kfree(newfilename);

	DEB((KERN_INFO "LSTAT: result %i\n", ret));

	return ret;
}


asmlinkage int virt_access(const char *filename, int mode)
{
	int ret;
	mm_segment_t old_fs;
	char *newfilename;
	
	if(!cwd_virtual()) {
		ret = (*orig_access)(filename, mode);
		if(ret != -ENOENT) 
			return ret;
	}
	else 
		ret = 0;

	newfilename = resolve_name(filename, 1, 1);
	if(!newfilename) {
		if(ret)
			return ret;
		else
			return (*orig_access)(filename, mode);
	}
	if(IS_ERR(newfilename))
			return PTR_ERR(newfilename);

	DEB((KERN_INFO "ACCESS: trying '%s'\n", newfilename));
		
	old_fs = get_fs();
	set_fs(get_ds());
	ret = (*orig_access)(newfilename, mode);
	set_fs(old_fs);
	kfree(newfilename);

	DEB((KERN_INFO "ACCESS: result %i\n", ret));
	
	return ret;
}

asmlinkage int virt_open(const char *filename, int flags, int mode)
{
	int ret;
	mm_segment_t old_fs;
	char *newfilename;
	
	if(!cwd_virtual()) {
		ret = (*orig_open)(filename, flags, mode);
		if(ret != -ENOENT) 
			return ret;
	}
	else 
		ret = 0;

	newfilename = resolve_name(filename, 1, 1);
	if(!newfilename) {
		if(ret)
			return ret;
		else
			return (*orig_open)(filename, flags, mode);
	}
	if(IS_ERR(newfilename))
			return PTR_ERR(newfilename);

	DEB((KERN_INFO "OPEN: trying '%s'\n", newfilename));
		
	old_fs = get_fs();
	set_fs(get_ds());
	ret = (*orig_open)(newfilename, flags, mode);
	set_fs(old_fs);
	kfree(newfilename);

	DEB((KERN_INFO "OPEN: result %i\n", ret));
	
	return ret;
}

asmlinkage int virt_readlink(const char *filename, char *buf, int bufsiz)
{
	int ret;
	mm_segment_t old_fs;
	char *newfilename;
	char *locbuf;
	int len;
	
	if(!cwd_virtual()) {
		ret = (*orig_readlink)(filename, buf, bufsiz);
		if(ret != -ENOENT) 
			return ret;
	}
	else 
		ret = 0;

	newfilename = resolve_name(filename, 1, 0);
	if(!newfilename) {
		if(ret)
			return ret;
		else
			return (*orig_readlink)(filename, buf, bufsiz);
	}
	if(IS_ERR(newfilename))
			return PTR_ERR(newfilename);

	DEB((KERN_INFO "READLINK: trying '%s'\n", newfilename));

	/* bufsiz is legal (already checked by sys_readlink) */
	len = bufsiz;
	if(bufsiz > PAGE_SIZE)
		len = PAGE_SIZE;
			
	locbuf = (char *) __get_free_page(GFP_USER);
			
	ret = -ENOMEM;
	if(locbuf) {
		old_fs = get_fs();
		set_fs(get_ds());
		ret =  (*orig_readlink)(newfilename, locbuf, len);
		set_fs(old_fs);

		if(ret >= 0)
			if(copy_to_user(buf, locbuf, len))
				ret = -EFAULT;
		free_page((unsigned long) locbuf);
	}
	kfree(newfilename);

	DEB((KERN_INFO "READLINK: result %i\n", ret));
	
	return ret;
}

asmlinkage int virt_getcwd(char *buf, unsigned long size)
{
	int ret;
	char *cwd;
	unsigned long cwdlen;
	char *page;
	char *newcwd;
	unsigned long newlen;
        char overlay_dir[128];
        unsigned overlay_dir_len;
        	
	ret = (*orig_getcwd)(buf, size);

	if(!cwd_virtual() || ret < 0)
		return ret;
		
	if(!path_ok(current->fs->pwd))
		return -ENOENT;
	
	page = (char *) __get_free_page(GFP_USER);
	if(!page)
		return -ENOMEM;
	
        cwd = path_pwd(page);
	cwdlen = PAGE_SIZE + (page - cwd) - 1;
	
        sprintf(overlay_dir, "/mnt/avfs/%010u", current->fsuid);
        overlay_dir_len = strlen(overlay_dir);

	if(cwdlen >= overlay_dir_len && 
	   strncmp(cwd, overlay_dir, overlay_dir_len) == 0) {
		if(cwdlen == overlay_dir_len) {
			newcwd = "/";
			newlen = 1;
		}
		else {
			newcwd = cwd + overlay_dir_len;
			newlen = cwdlen - overlay_dir_len;
		}

		ret = -ERANGE;
		if(newlen + 1 <= size) {
			ret = newlen + 1;
			if(copy_to_user(buf, newcwd, newlen + 1))
				ret = -EFAULT;
		}
	}
	free_page((unsigned long) page);

	return ret;
}


static long do_orig_stat64(stat64_func sfunc, const char *filename,
			  struct stat64 * statbuf, long flags)
{
	long ret;
	mm_segment_t old_fs;
	struct stat64 locbuf;

	old_fs = get_fs();
	set_fs(get_ds());
	ret =  (*sfunc)(filename, &locbuf, flags);
	set_fs(old_fs);

	if(ret == 0)
		ret = (copy_to_user(statbuf, &locbuf, sizeof(locbuf)) ? 
		       -EFAULT : 0);

	return ret;
}

asmlinkage long virt_stat64(char * filename, struct stat64 * statbuf, long flags)
{
	long ret;
	char *newfilename;

	if(!cwd_virtual()) {
		ret = (*orig_stat64)(filename, statbuf, flags);
		if(ret != -ENOENT) 
			return ret;
	}
	else 
		ret = 0;

	newfilename = resolve_name(filename, 1, 1);
	if(!newfilename) {
		if(ret)
			return ret;
		else
			return (*orig_stat64)(filename, statbuf, flags);
	}
	if(IS_ERR(newfilename))
			return PTR_ERR(newfilename);

	DEB((KERN_INFO "STAT64: trying '%s'\n", newfilename));

	ret = do_orig_stat64(orig_stat64, newfilename, statbuf, flags);
	kfree(newfilename);

	DEB((KERN_INFO "STAT64: result %li\n", ret));

	return ret;
}

asmlinkage long virt_lstat64(char * filename, struct stat64 * statbuf, long flags)
{
	long ret;
	char *newfilename;

	if(!cwd_virtual()) {
		ret = (*orig_lstat64)(filename, statbuf, flags);
		if(ret != -ENOENT) 
			return ret;
	}
	else 
		ret = 0;

	newfilename = resolve_name(filename, 1, 0);
	if(!newfilename) {
		if(ret)
			return ret;
		else
			return (*orig_lstat64)(filename, statbuf, flags);
	}
	if(IS_ERR(newfilename))
			return PTR_ERR(newfilename);

	DEB((KERN_INFO "LSTAT64: trying '%s'\n", newfilename));

	ret = do_orig_stat64(orig_lstat64, newfilename, statbuf, flags);
	kfree(newfilename);

	DEB((KERN_INFO "LSTAT64: result %li\n", ret));

	return ret;
}

#ifdef __i386__

asmlinkage int real_execve(struct pt_regs *regs)
{
	int error;
	char * filename;

	filename = getname((char *) regs->ebx);
	error = PTR_ERR(filename);
	if (IS_ERR(filename))
		goto out;
	error = do_execve(filename, (char **) regs->ecx, (char **) regs->edx, regs);
	if (error == 0)
		current->ptrace &= ~PT_DTRACE;
	putname(filename);

out:
	return error;
}

asmlinkage int virt_execve(struct pt_regs regs)
{
	int ret;
	char *newfilename;
	char *filename = (char *) regs.ebx;

	if(!cwd_virtual()) {
		ret = real_execve(&regs);
		if(ret != -ENOENT) 
			return ret;
	}
	else 
		ret = 0;

	newfilename = resolve_name(filename, 1, 1);
	if(!newfilename) {
		if(ret)
			return ret;
		else
			return real_execve(&regs);
	}
	if(IS_ERR(newfilename))
			return PTR_ERR(newfilename);

	DEB((KERN_INFO "EXECVE: trying '%s'\n", newfilename));

	ret = do_execve(newfilename, (char **) regs.ecx, (char **) regs.edx,
			&regs);
	if (ret == 0)
		current->ptrace &= ~PT_DTRACE;
	kfree(newfilename);

	DEB((KERN_INFO "EXECVE: result %i\n", ret));

	return ret;
}
#endif /* __i386__ */

void *replace_syscall(int index, void *new_syscall)
{
	void *orig_syscall = sys_call_table[index];

	printk(KERN_INFO "replacing syscall nr. %3i [%p] with [%p]\n", 
	       index, orig_syscall, new_syscall);
	sys_call_table[index] = new_syscall;
	
	return orig_syscall;
}

int init_module(void)
{
    printk(KERN_INFO "redir init (version %s)\n", REDIR_VERSION);

    orig_chdir    = replace_syscall(__NR_chdir,    virt_chdir);
    orig_stat     = replace_syscall(__NR_stat,     virt_stat);
    orig_lstat    = replace_syscall(__NR_lstat,    virt_lstat);
    orig_access   = replace_syscall(__NR_access,   virt_access);
    orig_open     = replace_syscall(__NR_open,     virt_open);
    orig_readlink = replace_syscall(__NR_readlink, virt_readlink);
    orig_getcwd   = replace_syscall(__NR_getcwd,   virt_getcwd);

    orig_stat64   = replace_syscall(__NR_stat64,   virt_stat64);
    orig_lstat64  = replace_syscall(__NR_lstat64,  virt_lstat64);

#ifdef __i386__
    orig_execve   = replace_syscall(__NR_execve,   virt_execve);
#endif

    return 0;
}


void cleanup_module(void)
{
    printk(KERN_INFO "redir cleanup\n");
   
    replace_syscall(__NR_chdir,    orig_chdir);
    replace_syscall(__NR_stat,     orig_stat);
    replace_syscall(__NR_lstat,    orig_lstat);
    replace_syscall(__NR_access,   orig_access);
    replace_syscall(__NR_open,     orig_open);
    replace_syscall(__NR_readlink, orig_readlink);
    replace_syscall(__NR_getcwd,   orig_getcwd);

    replace_syscall(__NR_stat64,   orig_stat64);
    replace_syscall(__NR_lstat64,  orig_lstat64);

#ifdef __i386__
    replace_syscall(__NR_execve,   orig_execve);
#endif

}
