#include "Python.h"
#include "fuse.h"
#include <time.h>

static PyObject *ErrorObject;

PyObject *getattr_cb=NULL, *readlink_cb=NULL, *getdir_cb=NULL,
	 *mknod_cb=NULL, *mkdir_cb=NULL, *unlink_cb=NULL, *rmdir_cb=NULL,
	 *symlink_cb=NULL, *rename_cb=NULL, *link_cb=NULL, *chmod_cb=NULL,
	 *chown_cb=NULL, *truncate_cb=NULL, *utime_cb=NULL,
	 *open_cb=NULL, *read_cb=NULL, *write_cb=NULL;
struct fuse *fuse=NULL;


#define PROLOGUE \
	int ret = -EINVAL; \
	if (!v) { PyErr_Print(); goto OUT; } \
	if(v == Py_None) { ret = 0; goto OUT_DECREF; } \
	if(PyInt_Check(v)) { ret = PyInt_AsLong(v); goto OUT_DECREF; }

#define EPILOGUE \
	OUT_DECREF: \
		Py_DECREF(v); \
	OUT: \
		return ret; 
static int getattr_func(const char *path, struct stat *st) {
	int i;
	PyObject *v = PyObject_CallFunction(getattr_cb, "s", path);
	PROLOGUE

	if(!PyTuple_Check(v)) { goto OUT_DECREF; }
	if(PyTuple_Size(v) < 10) { goto OUT_DECREF; }
	for(i=0; i<10; i++) {
		if (!PyInt_Check(PyTuple_GetItem(v, 0))) goto OUT_DECREF;
	}

	st->st_mode = PyInt_AsLong(PyTuple_GetItem(v, 0));
	st->st_ino  = PyInt_AsLong(PyTuple_GetItem(v, 1));
	st->st_dev  = PyInt_AsLong(PyTuple_GetItem(v, 2));
	st->st_nlink= PyInt_AsLong(PyTuple_GetItem(v, 3));
	st->st_uid  = PyInt_AsLong(PyTuple_GetItem(v, 4));
	st->st_gid  = PyInt_AsLong(PyTuple_GetItem(v, 5));
	st->st_size = PyInt_AsLong(PyTuple_GetItem(v, 6));
	st->st_atime= PyInt_AsLong(PyTuple_GetItem(v, 7));
	st->st_mtime= PyInt_AsLong(PyTuple_GetItem(v, 8));
	st->st_ctime= PyInt_AsLong(PyTuple_GetItem(v, 9));

	/* Fill in fields not provided by Python lstat() */
	st->st_blksize= 4096;
	st->st_blocks= (st->st_size + 511)/512;
	st->st_ino  = 0;

	ret = 0;
	EPILOGUE
}

static int readlink_func(const char *path, char *link, size_t size) {
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

static int getdir_func(const char *path, fuse_dirh_t dh, fuse_dirfil_t df) {
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

int mknod_func(const char *path, mode_t m, dev_t d) {
	PyObject *v = PyObject_CallFunction(mknod_cb, "sii", path, m, d);
	PROLOGUE
	EPILOGUE
}

int mkdir_func(const char *path, mode_t m) {
	PyObject *v = PyObject_CallFunction(mkdir_cb, "si", path, m);
	PROLOGUE
	EPILOGUE
}

int unlink_func(const char *path) {
	PyObject *v = PyObject_CallFunction(unlink_cb, "s", path);
	PROLOGUE
	EPILOGUE
}

int rmdir_func(const char *path) {
	PyObject *v = PyObject_CallFunction(rmdir_cb, "s", path);
	PROLOGUE
	EPILOGUE
}

int symlink_func(const char *path, const char *path1) {
	PyObject *v = PyObject_CallFunction(symlink_cb, "ss", path, path1);
	PROLOGUE
	EPILOGUE
}

int rename_func(const char *path, const char *path1) {
	PyObject *v = PyObject_CallFunction(rename_cb, "ss", path, path1);
	PROLOGUE
	EPILOGUE
}

int link_func(const char *path, const char *path1) {
	PyObject *v = PyObject_CallFunction(link_cb, "ss", path, path1);
	PROLOGUE
	EPILOGUE
}

int chmod_func(const char *path, mode_t m) {
	PyObject *v = PyObject_CallFunction(chmod_cb, "si", path, m);
	PROLOGUE
	EPILOGUE
}

int chown_func(const char *path, uid_t u, gid_t g) {
	PyObject *v = PyObject_CallFunction(chown_cb, "sii", path, u, g);
	PROLOGUE
	EPILOGUE
}

int truncate_func(const char *path, off_t o) {
	PyObject *v = PyObject_CallFunction(truncate_cb, "si", path, o);
	PROLOGUE
	EPILOGUE
}

int utime_func(const char *path, struct utimbuf *u) {
	int actime = u ? u->actime : time(NULL);
	int modtime = u ? u->modtime : actime;
	PyObject *v = PyObject_CallFunction(utime_cb, "s(ii)",
					path, actime, modtime);
	PROLOGUE
	EPILOGUE
}

int read_func(const char *path, char *buf, size_t s, off_t off) {
	PyObject *v = PyObject_CallFunction(read_cb, "sii", path, s, off);
	PROLOGUE
	if(PyString_Check(v)) {
		if(PyString_Size(v) > s) goto OUT_DECREF;
		memcpy(buf, PyString_AsString(v), PyString_Size(v));
		ret = PyString_Size(v);
	}
	EPILOGUE
}

int write_func(const char *path, const char *buf, size_t t, off_t off) {
	PyObject *v = PyObject_CallFunction(write_cb,"ss#i", path, buf, t, off);
	PROLOGUE
	EPILOGUE
}

int open_func(const char *path, int mode) {
	PyObject *v = PyObject_CallFunction(open_cb, "si", path, mode);
	PROLOGUE
	EPILOGUE
}

static PyObject *
Fuse_main(PyObject *self, PyObject *args, PyObject *kw)
{
	int flags=0;

	struct fuse_operations op;

	static char  *kwlist[] = {
		"getattr", "readlink", "getdir", "mknod",
		"mkdir", "unlink", "rmdir", "symlink", "rename",
		"link", "chmod", "chown", "truncate", "utime",
		"open", "read", "write", "flags", NULL};
				
	if (!PyArg_ParseTupleAndKeywords(args, kw, "|OOOOOOOOOOOOOOOOOi", 
		kwlist, &getattr_cb, &readlink_cb, &getdir_cb, &mknod_cb,
		&mkdir_cb, &unlink_cb, &rmdir_cb, &symlink_cb, &rename_cb,
		&link_cb, &chmod_cb, &chown_cb, &truncate_cb, &utime_cb,
		&open_cb, &read_cb, &write_cb, &flags))
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

	fuse = fuse_new(0, flags);
	fuse_set_operations(fuse, &op);	
	fuse_loop(fuse);

	Py_INCREF(Py_None);
	return Py_None;
}

/* List of functions defined in the module */

static PyMethodDef Fuse_methods[] = {
	{"main",	(PyCFunction)Fuse_main,	 METH_VARARGS|METH_KEYWORDS},
	{NULL,		NULL}		/* sentinel */
};


/* Initialization function for the module (*must* be called init_fuse) */

DL_EXPORT(void)
init_fuse(void)
{
	PyObject *m, *d;

	/* Create the module and add the functions */
	m = Py_InitModule("_fuse", Fuse_methods);

	/* Add some symbolic constants to the module */
	d = PyModule_GetDict(m);
	ErrorObject = PyErr_NewException("fuse.error", NULL, NULL);
	PyDict_SetItemString(d, "error", ErrorObject);
	PyDict_SetItemString(d, "DEBUG", PyInt_FromLong(FUSE_DEBUG));
}
