//@+leo-ver=4
//@+node:@file _fusemodule.c
//@@language c
/*
    Copyright (C) 2001  Jeff Epler  <jepler@unpythonic.dhs.org>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    Updated for libfuse API changes
    2004 Steven James <pyro@linuxlabs.com> and
    Linux Labs International, Inc. http://www.linuxlabs.com

    
*/

//@+others
//@+node:includes
#include <Python.h>
#include "fuse.h"
#include <time.h>
//@-node:includes
//@+node:globals

static PyObject *getattr_cb=NULL, *readlink_cb=NULL, *getdir_cb=NULL,
  *mknod_cb=NULL, *mkdir_cb=NULL, *unlink_cb=NULL, *rmdir_cb=NULL,
  *symlink_cb=NULL, *rename_cb=NULL, *link_cb=NULL, *chmod_cb=NULL,
  *chown_cb=NULL, *truncate_cb=NULL, *utime_cb=NULL,
  *open_cb=NULL, *read_cb=NULL, *write_cb=NULL, *release_cb=NULL,
  *statfs_cb=NULL, *fsync_cb=NULL
  ;

static int debuglevel=0;

//@-node:globals
//@+node:PROLOGUE
#define PROLOGUE \
int ret = -EINVAL; \
if (!v) { PyErr_Print(); goto OUT; } \
if(v == Py_None) { ret = 0; goto OUT_DECREF; } \
if(PyInt_Check(v)) { ret = PyInt_AsLong(v); goto OUT_DECREF; }

//@-node:PROLOGUE
//@+node:EPILOGUE
#define EPILOGUE \
OUT_DECREF: \
	Py_DECREF(v); \
OUT: \
	return ret; 
//@-node:EPILOGUE
//@+node:getattr_func

/* 
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 * Changed by David McNab (david@rebirthing.co.nz) to work with recent pythons.
 * Namely, replacing PyTuple_* with PySequence_*, and checking numerical values
 * with both PyInt_Check and PyLong_Check.
 */

static int getattr_func(const char *path, struct stat *st)
{
int i;
PyObject *v = PyObject_CallFunction(getattr_cb, "s", path);
PROLOGUE

if(!PySequence_Check(v)) { goto OUT_DECREF; }
if(PySequence_Size(v) < 10) { goto OUT_DECREF; }
for(i=0; i<10; i++)
{
    PyObject *tmp = PySequence_GetItem(v, i);
	if (!(PyInt_Check(tmp) || PyLong_Check(tmp))) goto OUT_DECREF;
}

st->st_mode = PyInt_AsLong(PySequence_GetItem(v, 0));
st->st_ino  = PyInt_AsLong(PySequence_GetItem(v, 1));
st->st_dev  = PyInt_AsLong(PySequence_GetItem(v, 2));
st->st_nlink= PyInt_AsLong(PySequence_GetItem(v, 3));
st->st_uid  = PyInt_AsLong(PySequence_GetItem(v, 4));
st->st_gid  = PyInt_AsLong(PySequence_GetItem(v, 5));
st->st_size = PyInt_AsLong(PySequence_GetItem(v, 6));
st->st_atime= PyInt_AsLong(PySequence_GetItem(v, 7));
st->st_mtime= PyInt_AsLong(PySequence_GetItem(v, 8));
st->st_ctime= PyInt_AsLong(PySequence_GetItem(v, 9));

/* Fill in fields not provided by Python lstat() */
st->st_blksize= 4096;
st->st_blocks= (st->st_size + 511)/512;
st->st_ino  = 0;

ret = 0;
EPILOGUE
}

//@-node:getattr_func
//@+node:readlink_func

static int readlink_func(const char *path, char *link, size_t size)
{
	PyObject *v = PyObject_CallFunction(readlink_cb, "s", path);
	char *s;
	PROLOGUE

	if(!PyString_Check(v)) { ret = -EINVAL; goto OUT_DECREF; }
	s = PyString_AsString(v);
	strncpy(link, s, size);
	link[size-1] = '\0';
	ret = 0;

	EPILOGUE
}
//@-node:readlink_func
//@+node:getdir_add_entry

static int getdir_add_entry(PyObject *w, fuse_dirh_t dh, fuse_dirfil_t df)
{
	PyObject *o0;
	PyObject *o1;
	int ret = -EINVAL;

	if(!PySequence_Check(w)) {
		printf("getdir item not sequence\n");
		goto out;
	}
	if(PySequence_Length(w) != 2) {
		printf("getdir item not len 2\n");
		goto out;
	}
	o0 = PySequence_GetItem(w, 0);
	o1 = PySequence_GetItem(w, 1);

	if(!PyString_Check(o0)) {
		printf("getdir item[0] not string\n");
		goto out_decref;
	}
	if(!PyInt_Check(o1)) {
		printf("getdir item[1] not int\n");
		goto out_decref;
	}

	ret = df(dh, PyString_AsString(o0), PyInt_AsLong(o1));	

out_decref:
	Py_DECREF(o0);
	Py_DECREF(o1);

out:
	return ret;
}
//@-node:getdir_add_entry
//@+node:getdir_func

static int getdir_func(const char *path, fuse_dirh_t dh, fuse_dirfil_t df)
{
	PyObject *v = PyObject_CallFunction(getdir_cb, "s", path);
	int i;
	PROLOGUE

	if(!PySequence_Check(v)) {
		printf("getdir_func not sequence\n");
		goto OUT_DECREF;
	}
	for(i=0; i < PySequence_Length(v); i++) {
		PyObject *w = PySequence_GetItem(v, i);
		ret = getdir_add_entry(w, dh, df);
		Py_DECREF(w);
		if(ret != 0)
			goto OUT_DECREF;
	}
	ret = 0;

	EPILOGUE
}
//@-node:getdir_func
//@+node:mknod_func

static int mknod_func(const char *path, mode_t m, dev_t d)
{
	PyObject *v = PyObject_CallFunction(mknod_cb, "sii", path, m, d);
	PROLOGUE
	EPILOGUE
}
//@-node:mknod_func
//@+node:mkdir_func

static int mkdir_func(const char *path, mode_t m)
{
	PyObject *v = PyObject_CallFunction(mkdir_cb, "si", path, m);
	PROLOGUE
	EPILOGUE
}
//@-node:mkdir_func
//@+node:unlink_func

static int unlink_func(const char *path)
{
	PyObject *v = PyObject_CallFunction(unlink_cb, "s", path);
	PROLOGUE
	EPILOGUE
}
//@-node:unlink_func
//@+node:rmdir_func

static int rmdir_func(const char *path)
{
	PyObject *v = PyObject_CallFunction(rmdir_cb, "s", path);
	PROLOGUE
	EPILOGUE
}
//@-node:rmdir_func
//@+node:symlink_func

static int symlink_func(const char *path, const char *path1)
{
	PyObject *v = PyObject_CallFunction(symlink_cb, "ss", path, path1);
	PROLOGUE
	EPILOGUE
}
//@-node:symlink_func
//@+node:rename_func

static int rename_func(const char *path, const char *path1)
{
	PyObject *v = PyObject_CallFunction(rename_cb, "ss", path, path1);
	PROLOGUE
	EPILOGUE
}
//@-node:rename_func
//@+node:link_func

static int link_func(const char *path, const char *path1)
{
	PyObject *v = PyObject_CallFunction(link_cb, "ss", path, path1);
	PROLOGUE
	EPILOGUE
}
//@-node:link_func
//@+node:chmod_func

static int chmod_func(const char *path, mode_t m) 
{
	PyObject *v = PyObject_CallFunction(chmod_cb, "si", path, m);
	PROLOGUE
	EPILOGUE
}
//@-node:chmod_func
//@+node:chown_func

static int chown_func(const char *path, uid_t u, gid_t g) 
{
	PyObject *v = PyObject_CallFunction(chown_cb, "sii", path, u, g);
	PROLOGUE
	EPILOGUE
}
//@-node:chown_func
//@+node:truncate_func

static int truncate_func(const char *path, off_t o)
{
	PyObject *v = PyObject_CallFunction(truncate_cb, "si", path, o);
	PROLOGUE
	EPILOGUE
}
//@-node:truncate_func
//@+node:utime_func

static int utime_func(const char *path, struct utimbuf *u) {
	int actime = u ? u->actime : time(NULL);
	int modtime = u ? u->modtime : actime;
	PyObject *v = PyObject_CallFunction(utime_cb, "s(ii)",
					path, actime, modtime);
	PROLOGUE
	EPILOGUE
}
//@-node:utime_func
//@+node:read_func

static int read_func(const char *path, char *buf, size_t s, off_t off)
{
	PyObject *v = PyObject_CallFunction(read_cb, "sii", path, s, off);
	PROLOGUE
	if(PyString_Check(v)) {
		if(PyString_Size(v) > s) goto OUT_DECREF;
		memcpy(buf, PyString_AsString(v), PyString_Size(v));
		ret = PyString_Size(v);
	}
	EPILOGUE
}
//@-node:read_func
//@+node:write_func

static int write_func(const char *path, const char *buf, size_t t, off_t off)
{
	PyObject *v = PyObject_CallFunction(write_cb,"ss#i", path, buf, t, off);
	PROLOGUE
	EPILOGUE
}
//@-node:write_func
//@+node:open_func

static int open_func(const char *path, int mode)
{
	PyObject *v = PyObject_CallFunction(open_cb, "si", path, mode);
	PROLOGUE
    printf("open_func: path=%s\n", path);
	EPILOGUE
}
//@-node:open_func
//@+node:release_func
static int release_func(const char *path, int flags)
{
  PyObject *v = PyObject_CallFunction(release_cb, "si", path, flags);
  PROLOGUE
    //printf("release_func: path=%s flags=%d\n", path, flags);
  EPILOGUE
}
//@-node:release_func
//@+node:statfs_func
static int statfs_func( const char *dummy, struct statfs *fst)
{
  int i;
  long retvalues[6];
  PyObject *v = PyObject_CallFunction(statfs_cb, "");
PROLOGUE

  if (!PySequence_Check(v))
    { goto OUT_DECREF; }
 if (PySequence_Size(v) < 6)
   { goto OUT_DECREF; }
 for(i=0; i<6; i++)
   {
     PyObject *tmp = PySequence_GetItem(v, i);
     retvalues[i] = PyInt_Check(tmp)
       ? PyInt_AsLong(tmp)
       : (PyLong_Check(tmp)
          ? PyLong_AsLong(tmp)
          : 0);
   }

 fst->f_bsize	= retvalues[0];
 fst->f_blocks	= retvalues[1];
 fst->f_bfree	= retvalues[2];
 fst->f_files	= retvalues[3];
 fst->f_ffree	= retvalues[4];
 fst->f_namelen	= retvalues[5];

 ret = 0;
 
#ifdef IGNORE_THIS
 printf("block_size=%ld, blocks=%ld, blocks_free=%ld, files=%ld, files_free=%ld, namelen=%ld\n",
        retvalues[0], retvalues[1], retvalues[2], retvalues[3], retvalues[4], retvalues[5]);
#endif

EPILOGUE

}

//@-node:statfs_func
//@+node:fsync_func
static int fsync_func(const char *path, int isfsyncfile)
{
	PyObject *v = PyObject_CallFunction(fsync_cb, "si", path, isfsyncfile);
	PROLOGUE
	EPILOGUE
}

//@-node:fsync_func
//@+node:process_cmd

static void process_cmd(struct fuse *f, struct fuse_cmd *cmd, void *data)
{
	PyInterpreterState *interp = (PyInterpreterState *) data;
	PyThreadState *state;

	PyEval_AcquireLock();
	state = PyThreadState_New(interp);
	PyThreadState_Swap(state);
	__fuse_process_cmd(f, cmd);
	PyThreadState_Clear(state);
	PyThreadState_Swap(NULL);
	PyThreadState_Delete(state);
	PyEval_ReleaseLock();
}
//@-node:process_cmd
//@+node:pyfuse_loop_mt

static void pyfuse_loop_mt(struct fuse *f)
{
	PyInterpreterState *interp;
	PyThreadState *save;

	PyEval_InitThreads();
	interp = PyThreadState_Get()->interp;
	save = PyEval_SaveThread();
	__fuse_loop_mt(f, process_cmd, interp);
	/* Not yet reached: */
	PyEval_RestoreThread(save);
}
//@-node:pyfuse_loop_mt
//@+node:Fuse_main

static struct fuse *fuse=NULL;

static PyObject *
Fuse_main(PyObject *self, PyObject *args, PyObject *kw)
{
	int fd;
	int multithreaded=0;
	char *lopts=NULL;
	char *kopts=NULL;
	char *mountpoint;

	struct fuse_operations op;

	static char  *kwlist[] = {
		"getattr", "readlink", "getdir", "mknod",
		"mkdir", "unlink", "rmdir", "symlink", "rename",
		"link", "chmod", "chown", "truncate", "utime",
		"open", "read", "write", "release", "statfs", "fsync",
		"mountpoint", "kopts", "lopts", "multithreaded", 
		"debug", NULL};
	
	memset(&op, 0, sizeof(op));

	if (!PyArg_ParseTupleAndKeywords(args, kw, "|OOOOOOOOOOOOOOOOOOOOsssii", 
					kwlist, &getattr_cb, &readlink_cb, &getdir_cb, &mknod_cb,
					&mkdir_cb, &unlink_cb, &rmdir_cb, &symlink_cb, &rename_cb,
					&link_cb, &chmod_cb, &chown_cb, &truncate_cb, &utime_cb,
					&open_cb, &read_cb, &write_cb, &release_cb, &statfs_cb, &fsync_cb,
					&mountpoint, &kopts, &lopts, &multithreaded, &debuglevel))
		return NULL;
	
#define DO_ONE_ATTR(name) if(name ## _cb) { Py_INCREF(name ## _cb); op.name = name ## _func; } else { op.name = NULL; }

	DO_ONE_ATTR(getattr);
	DO_ONE_ATTR(readlink);
	DO_ONE_ATTR(getdir);
	DO_ONE_ATTR(mknod);
	DO_ONE_ATTR(mkdir);
	DO_ONE_ATTR(unlink);
	DO_ONE_ATTR(rmdir);
	DO_ONE_ATTR(symlink);
	DO_ONE_ATTR(rename);
	DO_ONE_ATTR(link);
	DO_ONE_ATTR(chmod);
	DO_ONE_ATTR(chown);
	DO_ONE_ATTR(truncate);
	DO_ONE_ATTR(utime);
	DO_ONE_ATTR(open);
	DO_ONE_ATTR(read);
	DO_ONE_ATTR(write);
	DO_ONE_ATTR(release);
	DO_ONE_ATTR(statfs);
	DO_ONE_ATTR(fsync);

	fd = fuse_mount(mountpoint, kopts);
	fuse = fuse_new(fd, lopts, &op);
	if(multithreaded)
		pyfuse_loop_mt(fuse);
	else
		fuse_loop(fuse);

    //printf("Fuse_main: called\n");

	Py_INCREF(Py_None);
	return Py_None;
}
//@-node:Fuse_main
//@+node:DL_EXPORT
//@+at 
//@nonl
// List of functions defined in the module
//@-at
//@@c
static char FuseInvalidate__doc__[] =
	"Tell Fuse kernel module to explicitly invalidate a cached inode's contents\n";

static PyObject *FuseInvalidate( PyObject *self, PyObject *args) {
	char *path;
	PyObject *ret;
	int err;

	PyString_Check(args);

	path = PyString_AsString(args);

	err = fuse_invalidate(fuse, path);

	ret = PyInt_FromLong(err);

	return(ret);
}

static char FuseGetContext__doc__[] =
	"Return the context of a filesystem operation in a dict. uid, gid, pid\n";

static PyObject *FuseGetContext( PyObject *self, PyObject *args) {
	struct fuse_context *fc;
	PyObject *ret;
	PyObject *num;

	fc = fuse_get_context();
	ret = PyDict_New();

	if(!ret)
		return(NULL);

	num = PyInt_FromLong( fc->uid);
	PyDict_SetItemString( ret, "uid", num);	

	num = PyInt_FromLong( fc->gid);
	PyDict_SetItemString( ret, "gid", num);	

	num = PyInt_FromLong( fc->pid);
	PyDict_SetItemString( ret, "pid", num);	

	return(ret);

}

static PyMethodDef Fuse_methods[] = {
	{"main",	(PyCFunction)Fuse_main,	 METH_VARARGS|METH_KEYWORDS},
	{"FuseGetContext", (PyCFunction)FuseGetContext, METH_VARARGS, FuseGetContext__doc__},
	{"FuseInvalidate", (PyCFunction)FuseInvalidate, METH_VARARGS, FuseInvalidate__doc__},
	{NULL,		NULL}		/* sentinel */
};


/* Initialization function for the module (*must* be called init_fuse) */

DL_EXPORT(void)
init_fuse(void)
{
	PyObject *m, *d;
	static PyObject *ErrorObject;
 
	/* Create the module and add the functions */
	m = Py_InitModule("_fuse", Fuse_methods);

	/* Add some symbolic constants to the module */
	d = PyModule_GetDict(m);
	ErrorObject = PyErr_NewException("fuse.error", NULL, NULL);
	PyDict_SetItemString(d, "error", ErrorObject);
//	PyDict_SetItemString(d, "DEBUG", PyInt_FromLong(FUSE_DEBUG));
}
//@-node:DL_EXPORT
//@-others

//@-node:@file _fusemodule.c
//@-leo
