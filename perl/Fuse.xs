#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <fuse.h>

static int
not_here(char *s)
{
    croak("%s not implemented on this architecture", s);
    return -1;
}

static double
constant(char *name, int len, int arg)
{
    errno = ENOENT;
    return 0;
}

SV *_PLfuse_callbacks[17];

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
	if(rv < 7) {
		if(rv > 1)
			croak("inappropriate number of returned values from getattr");
		if(rv)
			rv = POPi;
		else
			rv = -EINVAL;
	} else {
		if(rv > 9)
			croak("inappropriate number of returned values from getattr");
		result->st_ctime = result->st_mtime = result->st_atime = POPi;
		result->st_mode = POPi;
		result->st_nlink = POPi;
		result->st_uid = POPi;
		result->st_gid = POPi;
		result->st_size = POPi;
		result->st_blocks = POPi;
		if(rv > 7) {
			if(rv > 8)
				result->st_blksize = POPi;
			else
				result->st_blksize = 1024;
			rv = POPi;
		} else {
			result->st_blksize = 1024;
			rv = 0;
		}
	}
	FREETMPS;
	LEAVE;
	return rv;
}

int _PLfuse_readlink(const char *file,char *buf,size_t buflen) {
	int rv;
	char *rvstr;
	dXSARGS;
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	PUTBACK;
	rv = call_sv(_PLfuse_callbacks[1],G_SCALAR);
	SPAGAIN;
	if(!rv)
		rv = -ENOENT;
	else
		if(SvTYPE(ST(0)) == SVt_IV)
			rv = POPi;
		else {
			strncpy(buf,POPp,buflen);
			rv = 0;
		}
	FREETMPS;
	LEAVE;
	return rv;
}

int _PLfuse_getdir(const char *file, fuse_dirh_t dirh, fuse_dirfil_t dirfil) {
	int prv, rv;
	dXSARGS;
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(file,0)));
	PUTBACK;
	prv = call_sv(_PLfuse_callbacks[2],G_ARRAY);
	SPAGAIN;
	if(prv) {
		SV *mysv = POPs;
		if(!SvIOK(mysv)) {
			fprintf(stderr,"last getdir retval needs to be numeric (e.g. 0 or -ENOENT) (%s)\n",SvPV_nolen(mysv));
			rv = -ENOSYS;
		} else {
			rv = SvIV(mysv);
			while(--prv)
				dirfil(dirh,POPp,0);
		}
	} else {
		fprintf(stderr,"getdir() handler returned nothing!\n");
		rv = -ENOSYS;
	}
	FREETMPS;
	LEAVE;
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
	return rv;
}

int _PLfuse_mkdir (const char *file, mode_t mode) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
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
	return rv;
}


int _PLfuse_unlink (const char *file) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
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
	return rv;
}

int _PLfuse_rmdir (const char *file) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
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
	return rv;
}

int _PLfuse_symlink (const char *file, const char *new) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
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
	return rv;
}

int _PLfuse_rename (const char *file, const char *new) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
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
	return rv;
}

int _PLfuse_link (const char *file, const char *new) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
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
	return rv;
}

int _PLfuse_chmod (const char *file, mode_t mode) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
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
	return rv;
}

int _PLfuse_chown (const char *file, uid_t uid, gid_t gid) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
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
	return rv;
}

int _PLfuse_truncate (const char *file, off_t off) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
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
	return rv;
}

int _PLfuse_utime (const char *file, struct utimbuf *uti) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
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
	return rv;
}

int _PLfuse_open (const char *file, int flags) {
	int rv;
	SV *rvsv;
	char *rvstr;
	dSP;
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
	return rv;
}

int _PLfuse_read (const char *file, char *buf, size_t buflen, off_t off) {
	int rv;
	char *rvstr;
	dXSARGS;
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
		SV *mysv = sv_2mortal(POPs);
		if(SvTYPE(mysv) == SVt_IV)
			rv = SvIV(mysv);
		else {
			rv = SvLEN(mysv);
			if(rv > buflen)
				croak("read() handler returned more than buflen!");
			if(rv)
				memcpy(buf,SvPV_nolen(mysv),rv);
		}
	}
	return rv;
}

int _PLfuse_write (const char *file, const char *buf, size_t buflen, off_t off) {
	int rv;
	char *rvstr;
	dSP;
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
			_PLfuse_write
};

MODULE = Fuse		PACKAGE = Fuse
PROTOTYPES: DISABLE


double
constant(sv,arg)
    PREINIT:
	STRLEN		len;
    INPUT:
	SV *		sv
	char *		s = SvPV(sv, len);
	int		arg
    CODE:
	RETVAL = constant(s,len,arg);
    OUTPUT:
	RETVAL

void
perl_fuse_main(...)
	PREINIT:
	struct fuse_operations fops = {NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL};
	int i, varnum = 0, threads, debug, argc;
	char **argv;
	STRLEN n_a;
	STRLEN l;
	INIT:
	if(items != 21) {
		fprintf(stderr,"Perl<->C inconsistency or internal error\n");
		XSRETURN_UNDEF;
	}
	CODE:
	threads = !SvIV(ST(1));
	debug = SvIV(ST(2));
	if(threads && debug) {
		argc = 4;
		argv = ((char*[]){NULL,NULL,"-s","-d"});
	} else if(threads) {
		argc = 3;
		argv = ((char*[]){NULL,NULL,"-s"});
	} else if(debug) {
		argc = 3;
		argv = ((char*[]){NULL,NULL,"-d"});
	} else {
		argc = 2;
		argv = ((char*[]){"str","mnt"});
	}
	argv[0] = SvPV(ST(0),n_a);
	if(strlen(SvPV(ST(3),n_a)))
		argv[1] = SvPV(ST(3),n_a);
	else
		argc--;
	
	for(i=0;i<17;i++) {
		SV *var = ST(i+4);
		if((var != &PL_sv_undef) && SvROK(var)) {
			if(SvTYPE(SvRV(var)) == SVt_PVCV) {
				void **tmp1 = (void**)&_available_ops, **tmp2 = (void**)&fops;
				tmp2[i] = tmp1[i];
				_PLfuse_callbacks[i] = var;
			} else
				croak("arg is not a code reference!");
		}
	}
	fuse_main(argc,argv,&fops);
