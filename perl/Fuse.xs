#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <fuse.h>

#undef DEBUGf
#if 0
#define DEBUGf(f, a...) fprintf(stderr, "%s:%d (%i): " f,__BASE_FILE__,__LINE__,PL_stack_sp-PL_stack_base ,##a )
#else
#define DEBUGf(a...)
#endif

SV *_PLfuse_callbacks[18];

int _PLfuse_getattr(const char *file, struct stat *result) {
	dSP;
	int rv, statcount;
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,strlen(file))));
	PUTBACK;
	rv = call_sv(_PLfuse_callbacks[0],G_ARRAY);
	SPAGAIN;
	if(rv != 13) {
		if(rv > 1) {
			fprintf(stderr,"inappropriate number of returned values from getattr\n");
			rv = -ENOSYS;
		} else if(rv)
			rv = POPi;
		else
			rv = -ENOENT;
	} else {
		result->st_blksize = POPi;
		result->st_ctime = POPi;
		result->st_mtime = POPi;
		result->st_atime = POPi;
		/* What the HELL?  Perl says the blockcount is the last argument.
		 * Everything else says the blockcount is the last argument.  So why
		 * was it folded into the middle of the list? */
		result->st_blocks = POPi;
		result->st_size = POPi;
		result->st_rdev = POPi;
		result->st_gid = POPi;
		result->st_uid = POPi;
		result->st_nlink = POPi;
		result->st_mode = POPi;
		/*result->st_ino =*/ POPi;
		result->st_dev = POPi;
		rv = 0;
	}
	FREETMPS;
	LEAVE;
	PUTBACK;
	return rv;
}

int _PLfuse_readlink(const char *file,char *buf,size_t buflen) {
	int rv;
	char *rvstr;
	dSP;
	I32 ax;
	if(buflen < 1)
		return EINVAL;
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	PUTBACK;
	rv = call_sv(_PLfuse_callbacks[1],G_SCALAR);
	SPAGAIN;
	if(!rv)
		rv = -ENOENT;
	else {
		SV *mysv = POPs;
		if(SvTYPE(mysv) == SVt_IV || SvTYPE(mysv) == SVt_NV)
			rv = SvIV(mysv);
		else {
			strncpy(buf,SvPV_nolen(mysv),buflen);
			rv = 0;
		}
	}
	FREETMPS;
	LEAVE;
	buf[buflen-1] = 0;
	PUTBACK;
	return rv;
}

int _PLfuse_getdir(const char *file, fuse_dirh_t dirh, fuse_dirfil_t dirfil) {
	int prv, rv;
	dSP;
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	PUTBACK;
	prv = call_sv(_PLfuse_callbacks[2],G_ARRAY);
	SPAGAIN;
	if(prv) {
		rv = POPi;
		while(--prv)
			dirfil(dirh,POPp,0);
	} else {
		fprintf(stderr,"getdir() handler returned nothing!\n");
		rv = -ENOSYS;
	}
	FREETMPS;
	LEAVE;
	PUTBACK;
	return rv;
}

int _PLfuse_mknod (const char *file, mode_t mode, dev_t dev) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSViv(mode)));
	XPUSHs(sv_2mortal(newSViv(dev)));
	PUTBACK;
	rv = call_sv(_PLfuse_callbacks[3],G_SCALAR);
	SPAGAIN;
	if(rv)
		rv = POPi;
	else
		rv = 0;
	FREETMPS;
	LEAVE;
	PUTBACK;
	return rv;
}

int _PLfuse_mkdir (const char *file, mode_t mode) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
	DEBUGf("mkdir begin: %i\n",sp-PL_stack_base);
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSViv(mode)));
	PUTBACK;
	rv = call_sv(_PLfuse_callbacks[4],G_SCALAR);
	SPAGAIN;
	if(rv)
		rv = POPi;
	else
		rv = 0;
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("mkdir end: %i %i\n",sp-PL_stack_base,rv);
	return rv;
}


int _PLfuse_unlink (const char *file) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
	DEBUGf("unlink begin: %i\n",sp-PL_stack_base);
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	PUTBACK;
	rv = call_sv(_PLfuse_callbacks[5],G_SCALAR);
	SPAGAIN;
	if(rv)
		rv = POPi;
	else
		rv = 0;
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("unlink end: %i\n",sp-PL_stack_base);
	return rv;
}

int _PLfuse_rmdir (const char *file) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
	DEBUGf("rmdir begin: %i\n",sp-PL_stack_base);
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	PUTBACK;
	rv = call_sv(_PLfuse_callbacks[6],G_SCALAR);
	SPAGAIN;
	if(rv)
		rv = POPi;
	else
		rv = 0;
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("rmdir end: %i %i\n",sp-PL_stack_base,rv);
	return rv;
}

int _PLfuse_symlink (const char *file, const char *new) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
	DEBUGf("symlink begin: %i\n",sp-PL_stack_base);
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSVpv(new,0)));
	PUTBACK;
	rv = call_sv(_PLfuse_callbacks[7],G_SCALAR);
	SPAGAIN;
	if(rv)
		rv = POPi;
	else
		rv = 0;
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("symlink end: %i\n",sp-PL_stack_base);
	return rv;
}

int _PLfuse_rename (const char *file, const char *new) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
	DEBUGf("rename begin: %i\n",sp-PL_stack_base);
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSVpv(new,0)));
	PUTBACK;
	rv = call_sv(_PLfuse_callbacks[8],G_SCALAR);
	SPAGAIN;
	if(rv)
		rv = POPi;
	else
		rv = 0;
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("rename end: %i\n",sp-PL_stack_base);
	return rv;
}

int _PLfuse_link (const char *file, const char *new) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
	DEBUGf("link begin: %i\n",sp-PL_stack_base);
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSVpv(new,0)));
	PUTBACK;
	rv = call_sv(_PLfuse_callbacks[9],G_SCALAR);
	SPAGAIN;
	if(rv)
		rv = POPi;
	else
		rv = 0;
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("link end: %i\n",sp-PL_stack_base);
	return rv;
}

int _PLfuse_chmod (const char *file, mode_t mode) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
	DEBUGf("chmod begin: %i\n",sp-PL_stack_base);
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSViv(mode)));
	PUTBACK;
	rv = call_sv(_PLfuse_callbacks[10],G_SCALAR);
	SPAGAIN;
	if(rv)
		rv = POPi;
	else
		rv = 0;
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("chmod end: %i\n",sp-PL_stack_base);
	return rv;
}

int _PLfuse_chown (const char *file, uid_t uid, gid_t gid) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
	DEBUGf("chown begin: %i\n",sp-PL_stack_base);
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSViv(uid)));
	XPUSHs(sv_2mortal(newSViv(gid)));
	PUTBACK;
	rv = call_sv(_PLfuse_callbacks[11],G_SCALAR);
	SPAGAIN;
	if(rv)
		rv = POPi;
	else
		rv = 0;
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("chown end: %i\n",sp-PL_stack_base);
	return rv;
}

int _PLfuse_truncate (const char *file, off_t off) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
	DEBUGf("truncate begin: %i\n",sp-PL_stack_base);
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSViv(off)));
	PUTBACK;
	rv = call_sv(_PLfuse_callbacks[12],G_SCALAR);
	SPAGAIN;
	if(rv)
		rv = POPi;
	else
		rv = 0;
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("truncate end: %i\n",sp-PL_stack_base);
	return rv;
}

int _PLfuse_utime (const char *file, struct utimbuf *uti) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
	DEBUGf("utime begin: %i\n",sp-PL_stack_base);
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSViv(uti->actime)));
	XPUSHs(sv_2mortal(newSViv(uti->modtime)));
	PUTBACK;
	rv = call_sv(_PLfuse_callbacks[13],G_SCALAR);
	SPAGAIN;
	if(rv)
		rv = POPi;
	else
		rv = 0;
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("utime end: %i\n",sp-PL_stack_base);
	return rv;
}

int _PLfuse_open (const char *file, int flags) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
	DEBUGf("open begin: %i\n",sp-PL_stack_base);
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSViv(flags)));
	PUTBACK;
	rv = call_sv(_PLfuse_callbacks[14],G_SCALAR);
	SPAGAIN;
	if(rv)
		rv = POPi;
	else
		rv = 0;
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("open end: %i %i\n",sp-PL_stack_base,rv);
	return rv;
}

int _PLfuse_read (const char *file, char *buf, size_t buflen, off_t off) {
	int rv;
	char *rvstr;
	dSP;
	DEBUGf("read begin: %i\n",sp-PL_stack_base);
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSViv(buflen)));
	XPUSHs(sv_2mortal(newSViv(off)));
	PUTBACK;
	rv = call_sv(_PLfuse_callbacks[15],G_SCALAR);
	SPAGAIN;
	if(!rv)
		rv = -ENOENT;
	else {
		SV *mysv = POPs;
		if(SvTYPE(mysv) == SVt_NV || SvTYPE(mysv) == SVt_IV)
			rv = SvIV(mysv);
		else {
			if(SvPOK(mysv)) {
				rv = SvCUR(mysv);
			} else {
				rv = 0;
			}
			if(rv > buflen)
				croak("read() handler returned more than buflen! (%i > %i)",rv,buflen);
			if(rv)
				memcpy(buf,SvPV_nolen(mysv),rv);
		}
	}
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("read end: %i %i\n",sp-PL_stack_base,rv);
	return rv;
}

int _PLfuse_write (const char *file, const char *buf, size_t buflen, off_t off) {
	int rv;
	char *rvstr;
	dSP;
	DEBUGf("write begin: %i\n",sp-PL_stack_base);
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	XPUSHs(sv_2mortal(newSVpvn(buf,buflen)));
	XPUSHs(sv_2mortal(newSViv(off)));
	PUTBACK;
	rv = call_sv(_PLfuse_callbacks[16],G_SCALAR);
	SPAGAIN;
	if(rv)
		rv = POPi;
	else
		rv = 0;
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("write end: %i\n",sp-PL_stack_base);
	return rv;
}

int _PLfuse_statfs (const char *file, struct statfs *st) {
	int rv;
	char *rvstr;
	dSP;
	DEBUGf("statfs begin: %i\n",sp-PL_stack_base);
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	PUTBACK;
	rv = call_sv(_PLfuse_callbacks[17],G_ARRAY);
	SPAGAIN;
	if(rv > 5) {
		st->f_bsize    = POPi;
		st->f_bfree    = POPi;
		st->f_blocks   = POPi;
		st->f_ffree    = POPi;
		st->f_files    = POPi;
		st->f_namelen  = POPi;
		if(rv > 6)
			rv = POPi;
		else
			rv = 0;
	} else
	if(rv > 1)
		croak("inappropriate number of returned values from statfs");
	else
	if(rv)
		rv = POPi;
	else
		rv = -ENOSYS;
	FREETMPS;
	LEAVE;
	PUTBACK;
	DEBUGf("statfs end: %i\n",sp-PL_stack_base);
	return rv;
}

struct fuse_operations _available_ops = {
getattr:	_PLfuse_getattr,
			_PLfuse_readlink,
			_PLfuse_getdir,
			_PLfuse_mknod,
			_PLfuse_mkdir,
			_PLfuse_unlink,
			_PLfuse_rmdir,
			_PLfuse_symlink,
			_PLfuse_rename,
			_PLfuse_link,
			_PLfuse_chmod,
			_PLfuse_chown,
			_PLfuse_truncate,
			_PLfuse_utime,
			_PLfuse_open,
			_PLfuse_read,
			_PLfuse_write,
			_PLfuse_statfs
};

MODULE = Fuse		PACKAGE = Fuse
PROTOTYPES: DISABLE

void
perl_fuse_main(...)
	PREINIT:
	struct fuse_operations fops = {NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL};
	int i, fd, varnum = 0, debug, have_mnt;
	char *mountpoint;
	STRLEN n_a;
	STRLEN l;
	INIT:
	if(items != 20) {
		fprintf(stderr,"Perl<->C inconsistency or internal error\n");
		XSRETURN_UNDEF;
	}
	CODE:
	debug = SvIV(ST(0));
	mountpoint = SvPV_nolen(ST(1));
	/* FIXME: reevaluate multithreading support when perl6 arrives */
	for(i=0;i<18;i++) {
		SV *var = ST(i+2);
		if((var != &PL_sv_undef) && SvROK(var)) {
			if(SvTYPE(SvRV(var)) == SVt_PVCV) {
				void **tmp1 = (void**)&_available_ops, **tmp2 = (void**)&fops;
				tmp2[i] = tmp1[i];
				_PLfuse_callbacks[i] = var;
			} else
				croak("arg is not a code reference!");
		}
	}
	/* FIXME: need to pass fusermount arguments */
	fd = fuse_mount(mountpoint,NULL);
	if(fd < 0)
		croak("could not mount fuse filesystem!");
	fuse_loop(fuse_new(fd,debug ? "debug" : NULL,&fops));
