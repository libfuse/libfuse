<?xml version="1.0" encoding="UTF-8"?>
<leo_file>
<leo_header file_format="2" tnodes="0" max_tnode_index="69" clone_windows="0"/>
<globals body_outline_ratio="0.2448559670781893">
	<global_window_position top="129" left="90" height="631" width="1124"/>
	<global_log_window_position top="0" left="0" height="0" width="0"/>
</globals>
<preferences>
</preferences>
<find_panel_settings>
	<find_string></find_string>
	<change_string></change_string>
</find_panel_settings>
<vnodes>
<v t="davidmcnab.121303142957" a="E"><vh>fuse python bindings</vh>
<v t="davidmcnab.121303142957.1" a="E" tnodeList="davidmcnab.121303142957.1,davidmcnab.121303142957.2,davidmcnab.121303142957.3,davidmcnab.121303142957.4,davidmcnab.121303142957.5,davidmcnab.121303142957.6,davidmcnab.121303142957.7,davidmcnab.121303142957.8,davidmcnab.121303142957.9,davidmcnab.121303142957.10,davidmcnab.121303142957.11,davidmcnab.121303142957.12,davidmcnab.121303142957.13,davidmcnab.121303142957.14,davidmcnab.121303142957.15,davidmcnab.121303142957.16,davidmcnab.121303142957.17,davidmcnab.121303142957.18,davidmcnab.121303142957.19,davidmcnab.121303142957.20,davidmcnab.121303142957.21,davidmcnab.121303142957.22,davidmcnab.121303142957.23,davidmcnab.121303142957.24,davidmcnab.121303144441,davidmcnab.121303144441.1,davidmcnab.121303142957.25,davidmcnab.121303142957.26,davidmcnab.121303142957.27,davidmcnab.121303142957.28"><vh>@file _fusemodule.c</vh>
<v t="davidmcnab.121303142957.2"><vh>includes</vh></v>
<v t="davidmcnab.121303142957.3" a="M"><vh>globals</vh></v>
<v t="davidmcnab.121303142957.4"><vh>PROLOGUE</vh></v>
<v t="davidmcnab.121303142957.5"><vh>EPILOGUE</vh></v>
<v t="davidmcnab.121303142957.6"><vh>getattr_func</vh></v>
<v t="davidmcnab.121303142957.7"><vh>readlink_func</vh></v>
<v t="davidmcnab.121303142957.8"><vh>getdir_add_entry</vh></v>
<v t="davidmcnab.121303142957.9"><vh>getdir_func</vh></v>
<v t="davidmcnab.121303142957.10"><vh>mknod_func</vh></v>
<v t="davidmcnab.121303142957.11"><vh>mkdir_func</vh></v>
<v t="davidmcnab.121303142957.12"><vh>unlink_func</vh></v>
<v t="davidmcnab.121303142957.13"><vh>rmdir_func</vh></v>
<v t="davidmcnab.121303142957.14"><vh>symlink_func</vh></v>
<v t="davidmcnab.121303142957.15"><vh>rename_func</vh></v>
<v t="davidmcnab.121303142957.16"><vh>link_func</vh></v>
<v t="davidmcnab.121303142957.17"><vh>chmod_func</vh></v>
<v t="davidmcnab.121303142957.18"><vh>chown_func</vh></v>
<v t="davidmcnab.121303142957.19"><vh>truncate_func</vh></v>
<v t="davidmcnab.121303142957.20"><vh>utime_func</vh></v>
<v t="davidmcnab.121303142957.21"><vh>read_func</vh></v>
<v t="davidmcnab.121303142957.22"><vh>write_func</vh></v>
<v t="davidmcnab.121303142957.23"><vh>open_func</vh></v>
<v t="davidmcnab.121303142957.24" a="M"><vh>release_func</vh></v>
<v t="davidmcnab.121303144441"><vh>statfs_func</vh></v>
<v t="davidmcnab.121303144441.1"><vh>fsync_func</vh></v>
<v t="davidmcnab.121303142957.25" a="M"><vh>process_cmd</vh></v>
<v t="davidmcnab.121303142957.26"><vh>pyfuse_loop_mt</vh></v>
<v t="davidmcnab.121303142957.27" a="M"><vh>Fuse_main</vh></v>
<v t="davidmcnab.121303142957.28"><vh>DL_EXPORT</vh></v>
</v>
<v t="davidmcnab.121303142957.29" tnodeList="davidmcnab.121303142957.29,davidmcnab.121303142957.30,davidmcnab.121303142957.31,davidmcnab.121303142957.32,davidmcnab.121303142957.33,davidmcnab.121303142957.34,davidmcnab.121303142957.35,davidmcnab.121303142957.36,davidmcnab.121303142957.37"><vh>@file fuse.py</vh>
<v t="davidmcnab.121303142957.30"><vh>imports</vh></v>
<v t="davidmcnab.121303142957.31" a="E"><vh>class ErrnoWrapper</vh>
<v t="davidmcnab.121303142957.32"><vh>__init__</vh></v>
<v t="davidmcnab.121303142957.33"><vh>__call__</vh></v>
</v>
<v t="davidmcnab.121303142957.34" a="E"><vh>class Fuse</vh>
<v t="davidmcnab.121303142957.35" a="M"><vh>attribs</vh></v>
<v t="davidmcnab.121303142957.36"><vh>__init__</vh></v>
<v t="davidmcnab.121303142957.37"><vh>main</vh></v>
</v>
</v>
<v t="davidmcnab.121303142957.38" tnodeList="davidmcnab.121303142957.38"><vh>@file Makefile</vh></v>
<v t="davidmcnab.121303142957.39" a="E" tnodeList="davidmcnab.121303142957.39,davidmcnab.121303142957.40,davidmcnab.121303142957.41,davidmcnab.121303142957.42,davidmcnab.121303142957.43,davidmcnab.121303142957.44,davidmcnab.121303142957.45,davidmcnab.121303142957.46,davidmcnab.121303142957.47,davidmcnab.121303142957.48,davidmcnab.121303142957.49,davidmcnab.121303142957.50,davidmcnab.121303142957.51,davidmcnab.121303142957.52,davidmcnab.121303142957.53,davidmcnab.121303142957.54,davidmcnab.121303142957.55,davidmcnab.121303142957.56,davidmcnab.121303142957.57,davidmcnab.121303142957.58,davidmcnab.121303142957.59,davidmcnab.121303142957.60,davidmcnab.121303142957.61,davidmcnab.121303142957.62,davidmcnab.121303144134,davidmcnab.121303144134.1,davidmcnab.121303142957.63"><vh>@file xmp.py</vh>
<v t="davidmcnab.121303142957.40"><vh>imports</vh></v>
<v t="davidmcnab.121303142957.41" a="E"><vh>class Xmp</vh>
<v t="davidmcnab.121303142957.42"><vh>__init__</vh></v>
<v t="davidmcnab.121303142957.43"><vh>mythread</vh></v>
<v t="davidmcnab.121303142957.44"><vh>attribs</vh></v>
<v t="davidmcnab.121303142957.45"><vh>getattr</vh></v>
<v t="davidmcnab.121303142957.46"><vh>readlink</vh></v>
<v t="davidmcnab.121303142957.47"><vh>getdir</vh></v>
<v t="davidmcnab.121303142957.48"><vh>unlink</vh></v>
<v t="davidmcnab.121303142957.49"><vh>rmdir</vh></v>
<v t="davidmcnab.121303142957.50"><vh>symlink</vh></v>
<v t="davidmcnab.121303142957.51"><vh>rename</vh></v>
<v t="davidmcnab.121303142957.52"><vh>link</vh></v>
<v t="davidmcnab.121303142957.53"><vh>chmod</vh></v>
<v t="davidmcnab.121303142957.54"><vh>chown</vh></v>
<v t="davidmcnab.121303142957.55"><vh>truncate</vh></v>
<v t="davidmcnab.121303142957.56"><vh>mknod</vh></v>
<v t="davidmcnab.121303142957.57"><vh>mkdir</vh></v>
<v t="davidmcnab.121303142957.58"><vh>utime</vh></v>
<v t="davidmcnab.121303142957.59"><vh>open</vh></v>
<v t="davidmcnab.121303142957.60"><vh>read</vh></v>
<v t="davidmcnab.121303142957.61"><vh>write</vh></v>
<v t="davidmcnab.121303142957.62" a="M"><vh>release</vh></v>
<v t="davidmcnab.121303144134"><vh>statfs</vh></v>
<v t="davidmcnab.121303144134.1"><vh>fsync</vh></v>
</v>
<v t="davidmcnab.121303142957.63"><vh>mainline</vh></v>
</v>
<v t="davidmcnab.121303142957.64" tnodeList="davidmcnab.121303142957.64"><vh>@file setup.py</vh></v>
<v t="davidmcnab.121303142957.65" tnodeList="davidmcnab.121303142957.65"><vh>@file README</vh></v>
<v t="davidmcnab.121303142957.67" a="E" tnodeList="davidmcnab.121303142957.67"><vh>@file mount.fuse</vh></v>
<v t="davidmcnab.121403050157" a="E"><vh>@file fuse.py</vh>
<v t="davidmcnab.121403050157.1"><vh>&lt;&lt; fuse declarations &gt;&gt;</vh></v>
<v t="davidmcnab.121403050157.2" a="E"><vh>class ErrnoWrapper</vh>
<v t="davidmcnab.121403050157.3"><vh>&lt;&lt; class ErrnoWrapper declarations &gt;&gt;</vh></v>
<v t="davidmcnab.121403050157.4"><vh>__init__</vh></v>
<v t="davidmcnab.121403050157.5" a="V"><vh>__call__</vh></v>
</v>
<v t="davidmcnab.121403050157.6" a="E"><vh>class Fuse</vh>
<v t="davidmcnab.121403050157.7"><vh>&lt;&lt; class Fuse declarations &gt;&gt;</vh></v>
<v t="davidmcnab.121403050157.8"><vh>__init__</vh></v>
<v t="davidmcnab.121403050157.9"><vh>main</vh></v>
</v>
</v>
</v>
</vnodes>
<tnodes>
<t tx="davidmcnab.121303142957"></t>
<t tx="davidmcnab.121303142957.1">@language c
/*
    Copyright (C) 2001  Jeff Epler  &lt;jepler@unpythonic.dhs.org&gt;

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

@others

</t>
<t tx="davidmcnab.121303142957.2">#include &lt;Python.h&gt;
#include &lt;fuse.h&gt;
#include &lt;time.h&gt;
</t>
<t tx="davidmcnab.121303142957.3">
static PyObject *getattr_cb=NULL, *readlink_cb=NULL, *getdir_cb=NULL,
  *mknod_cb=NULL, *mkdir_cb=NULL, *unlink_cb=NULL, *rmdir_cb=NULL,
  *symlink_cb=NULL, *rename_cb=NULL, *link_cb=NULL, *chmod_cb=NULL,
  *chown_cb=NULL, *truncate_cb=NULL, *utime_cb=NULL,
  *open_cb=NULL, *read_cb=NULL, *write_cb=NULL, *release_cb=NULL,
  *statfs_cb=NULL, *fsync_cb=NULL
  ;
</t>
<t tx="davidmcnab.121303142957.4">#define PROLOGUE \
int ret = -EINVAL; \
if (!v) { PyErr_Print(); goto OUT; } \
if(v == Py_None) { ret = 0; goto OUT_DECREF; } \
if(PyInt_Check(v)) { ret = PyInt_AsLong(v); goto OUT_DECREF; }

</t>
<t tx="davidmcnab.121303142957.5">#define EPILOGUE \
OUT_DECREF: \
	Py_DECREF(v); \
OUT: \
	return ret; 
</t>
<t tx="davidmcnab.121303142957.6">
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
if(PySequence_Size(v) &lt; 10) { goto OUT_DECREF; }
for(i=0; i&lt;10; i++)
{
    PyObject *tmp = PySequence_GetItem(v, i);
	if (!(PyInt_Check(tmp) || PyLong_Check(tmp))) goto OUT_DECREF;
}

st-&gt;st_mode = PyInt_AsLong(PySequence_GetItem(v, 0));
st-&gt;st_ino  = PyInt_AsLong(PySequence_GetItem(v, 1));
st-&gt;st_dev  = PyInt_AsLong(PySequence_GetItem(v, 2));
st-&gt;st_nlink= PyInt_AsLong(PySequence_GetItem(v, 3));
st-&gt;st_uid  = PyInt_AsLong(PySequence_GetItem(v, 4));
st-&gt;st_gid  = PyInt_AsLong(PySequence_GetItem(v, 5));
st-&gt;st_size = PyInt_AsLong(PySequence_GetItem(v, 6));
st-&gt;st_atime= PyInt_AsLong(PySequence_GetItem(v, 7));
st-&gt;st_mtime= PyInt_AsLong(PySequence_GetItem(v, 8));
st-&gt;st_ctime= PyInt_AsLong(PySequence_GetItem(v, 9));

/* Fill in fields not provided by Python lstat() */
st-&gt;st_blksize= 4096;
st-&gt;st_blocks= (st-&gt;st_size + 511)/512;
st-&gt;st_ino  = 0;

ret = 0;
EPILOGUE
}

</t>
<t tx="davidmcnab.121303142957.7">
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
</t>
<t tx="davidmcnab.121303142957.8">
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
</t>
<t tx="davidmcnab.121303142957.9">
static int getdir_func(const char *path, fuse_dirh_t dh, fuse_dirfil_t df)
{
	PyObject *v = PyObject_CallFunction(getdir_cb, "s", path);
	int i;
	PROLOGUE

	if(!PySequence_Check(v)) {
		printf("getdir_func not sequence\n");
		goto OUT_DECREF;
	}
	for(i=0; i &lt; PySequence_Length(v); i++) {
		PyObject *w = PySequence_GetItem(v, i);
		ret = getdir_add_entry(w, dh, df);
		Py_DECREF(w);
		if(ret != 0)
			goto OUT_DECREF;
	}
	ret = 0;

	EPILOGUE
}
</t>
<t tx="davidmcnab.121303142957.10">
static int mknod_func(const char *path, mode_t m, dev_t d)
{
	PyObject *v = PyObject_CallFunction(mknod_cb, "sii", path, m, d);
	PROLOGUE
	EPILOGUE
}
</t>
<t tx="davidmcnab.121303142957.11">
static int mkdir_func(const char *path, mode_t m)
{
	PyObject *v = PyObject_CallFunction(mkdir_cb, "si", path, m);
	PROLOGUE
	EPILOGUE
}
</t>
<t tx="davidmcnab.121303142957.12">
static int unlink_func(const char *path)
{
	PyObject *v = PyObject_CallFunction(unlink_cb, "s", path);
	PROLOGUE
	EPILOGUE
}
</t>
<t tx="davidmcnab.121303142957.13">
static int rmdir_func(const char *path)
{
	PyObject *v = PyObject_CallFunction(rmdir_cb, "s", path);
	PROLOGUE
	EPILOGUE
}
</t>
<t tx="davidmcnab.121303142957.14">
static int symlink_func(const char *path, const char *path1)
{
	PyObject *v = PyObject_CallFunction(symlink_cb, "ss", path, path1);
	PROLOGUE
	EPILOGUE
}
</t>
<t tx="davidmcnab.121303142957.15">
static int rename_func(const char *path, const char *path1)
{
	PyObject *v = PyObject_CallFunction(rename_cb, "ss", path, path1);
	PROLOGUE
	EPILOGUE
}
</t>
<t tx="davidmcnab.121303142957.16">
static int link_func(const char *path, const char *path1)
{
	PyObject *v = PyObject_CallFunction(link_cb, "ss", path, path1);
	PROLOGUE
	EPILOGUE
}
</t>
<t tx="davidmcnab.121303142957.17">
static int chmod_func(const char *path, mode_t m) 
{
	PyObject *v = PyObject_CallFunction(chmod_cb, "si", path, m);
	PROLOGUE
	EPILOGUE
}
</t>
<t tx="davidmcnab.121303142957.18">
static int chown_func(const char *path, uid_t u, gid_t g) 
{
	PyObject *v = PyObject_CallFunction(chown_cb, "sii", path, u, g);
	PROLOGUE
	EPILOGUE
}
</t>
<t tx="davidmcnab.121303142957.19">
static int truncate_func(const char *path, off_t o)
{
	PyObject *v = PyObject_CallFunction(truncate_cb, "si", path, o);
	PROLOGUE
	EPILOGUE
}
</t>
<t tx="davidmcnab.121303142957.20">
static int utime_func(const char *path, struct utimbuf *u) {
	int actime = u ? u-&gt;actime : time(NULL);
	int modtime = u ? u-&gt;modtime : actime;
	PyObject *v = PyObject_CallFunction(utime_cb, "s(ii)",
					path, actime, modtime);
	PROLOGUE
	EPILOGUE
}
</t>
<t tx="davidmcnab.121303142957.21">
static int read_func(const char *path, char *buf, size_t s, off_t off)
{
	PyObject *v = PyObject_CallFunction(read_cb, "sii", path, s, off);
	PROLOGUE
	if(PyString_Check(v)) {
		if(PyString_Size(v) &gt; s) goto OUT_DECREF;
		memcpy(buf, PyString_AsString(v), PyString_Size(v));
		ret = PyString_Size(v);
	}
	EPILOGUE
}
</t>
<t tx="davidmcnab.121303142957.22">
static int write_func(const char *path, const char *buf, size_t t, off_t off)
{
	PyObject *v = PyObject_CallFunction(write_cb,"ss#i", path, buf, t, off);
	PROLOGUE
	EPILOGUE
}
</t>
<t tx="davidmcnab.121303142957.23">
static int open_func(const char *path, int mode)
{
	PyObject *v = PyObject_CallFunction(open_cb, "si", path, mode);
	PROLOGUE
    printf("open_func: path=%s\n", path);
	EPILOGUE
}
</t>
<t tx="davidmcnab.121303142957.24">static int release_func(const char *path, int flags)
{
  PyObject *v = PyObject_CallFunction(release_cb, "si", path, flags);
  PROLOGUE
    //printf("release_func: path=%s flags=%d\n", path, flags);
  EPILOGUE
}
</t>
<t tx="davidmcnab.121303142957.25">
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
</t>
<t tx="davidmcnab.121303142957.26">
static void pyfuse_loop_mt(struct fuse *f)
{
	PyInterpreterState *interp;
	PyThreadState *save;

	PyEval_InitThreads();
	interp = PyThreadState_Get()-&gt;interp;
	save = PyEval_SaveThread();
	__fuse_loop_mt(f, process_cmd, interp);
	/* Not yet reached: */
	PyEval_RestoreThread(save);
}
</t>
<t tx="davidmcnab.121303142957.27">

static PyObject *
Fuse_main(PyObject *self, PyObject *args, PyObject *kw)
{
	int flags=0;
	int multithreaded=0;
	static struct fuse *fuse=NULL;

	struct fuse_operations op;

	static char  *kwlist[] = {
		"getattr", "readlink", "getdir", "mknod",
		"mkdir", "unlink", "rmdir", "symlink", "rename",
		"link", "chmod", "chown", "truncate", "utime",
		"open", "read", "write", "release", "statfs", "fsync",
        "flags", "multithreaded", NULL};
	
	memset(&amp;op, 0, sizeof(op));

	if (!PyArg_ParseTupleAndKeywords(args, kw, "|OOOOOOOOOOOOOOOOOOOOii", 
                                     kwlist, &amp;getattr_cb, &amp;readlink_cb, &amp;getdir_cb, &amp;mknod_cb,
                                     &amp;mkdir_cb, &amp;unlink_cb, &amp;rmdir_cb, &amp;symlink_cb, &amp;rename_cb,
                                     &amp;link_cb, &amp;chmod_cb, &amp;chown_cb, &amp;truncate_cb, &amp;utime_cb,
                                     &amp;open_cb, &amp;read_cb, &amp;write_cb, &amp;release_cb, &amp;statfs_cb, &amp;fsync_cb,
                                     &amp;flags, &amp;multithreaded))
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

	fuse = fuse_new(0, flags, &amp;op);
	if(multithreaded)
		pyfuse_loop_mt(fuse);
	else
		fuse_loop(fuse);

    //printf("Fuse_main: called\n");

	Py_INCREF(Py_None);
	return Py_None;
}
</t>
<t tx="davidmcnab.121303142957.28">@ List of functions defined in the module
@c

static PyMethodDef Fuse_methods[] = {
	{"main",	(PyCFunction)Fuse_main,	 METH_VARARGS|METH_KEYWORDS},
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
	PyDict_SetItemString(d, "DEBUG", PyInt_FromLong(FUSE_DEBUG));
}
</t>
<t tx="davidmcnab.121303142957.29">#
#    Copyright (C) 2001  Jeff Epler  &lt;jepler@unpythonic.dhs.org&gt;
#
#    This program can be distributed under the terms of the GNU GPL.
#    See the file COPYING.
#


@language python
@others
</t>
<t tx="davidmcnab.121303142957.30"># suppress version mismatch warnings
try:
    import warnings
    warnings.filterwarnings('ignore',
                            'Python C API version mismatch',
                            RuntimeWarning,
                            )
except:
    pass
 
from _fuse import main, DEBUG
import os, sys
from errno import *

</t>
<t tx="davidmcnab.121303142957.31">class ErrnoWrapper:
	@others
</t>
<t tx="davidmcnab.121303142957.32">def __init__(self, func):
	self.func = func
</t>
<t tx="davidmcnab.121303142957.33">def __call__(self, *args, **kw):
	try:
		return apply(self.func, args, kw)
	except (IOError, OSError), detail:
		# Sometimes this is an int, sometimes an instance...
		if hasattr(detail, "errno"): detail = detail.errno
		return -detail
</t>
<t tx="davidmcnab.121303142957.34">class Fuse:

	@others
</t>
<t tx="davidmcnab.121303142957.35">_attrs = ['getattr', 'readlink', 'getdir', 'mknod', 'mkdir',
	  'unlink', 'rmdir', 'symlink', 'rename', 'link', 'chmod',
	  'chown', 'truncate', 'utime', 'open', 'read', 'write', 'release',
      'statfs', 'fsync']

flags = 0
multithreaded = 0

</t>
<t tx="davidmcnab.121303142957.36">def __init__(self, *args, **kw):

    # default attributes
    self.optlist = []
    self.optdict = {}
    self.mountpoint = None

    # grab arguments, if any
    argv = sys.argv
    argc = len(argv)
    if argc &gt; 1:
        # we've been given the mountpoint
        self.mountpoint = argv[1]
    if argc &gt; 2:
        # we've received mount args
        optstr = argv[2]
        opts = optstr.split(",")
        for o in opts:
            try:
                k, v = o.split("=", 1)
                self.optdict[k] = v
            except:
                self.optlist.append(o)
</t>
<t tx="davidmcnab.121303142957.37">def main(self):
	d = {'flags': self.flags}
	d['multithreaded'] = self.multithreaded
	for a in self._attrs:
		if hasattr(self,a):
			d[a] = ErrnoWrapper(getattr(self, a))
	apply(main, (), d)
</t>
<t tx="davidmcnab.121303142957.38"># Makefile now uses distutils

_fusemodule.so: _fusemodule.c
	#gcc -g3 -I/usr/include/python2.1 _fusemodule.c -Wl,-shared -o _fusemodule.so -Wimplicit -lfuse &amp;&amp; python -c 'import _fuse'
	python setup.py build_ext --inplace

install: _fusemodule.so
	python setup.py install

clean:
	rm -rf _fusemodule.so *.pyc *.pyo *~ build
</t>
<t tx="davidmcnab.121303142957.39">@first #!/usr/bin/env python
#
#    Copyright (C) 2001  Jeff Epler  &lt;jepler@unpythonic.dhs.org&gt;
#
#    This program can be distributed under the terms of the GNU GPL.
#    See the file COPYING.
#

@others
</t>
<t tx="davidmcnab.121303142957.40">
from fuse import Fuse
import os
from errno import *
from stat import *

import thread
</t>
<t tx="davidmcnab.121303142957.41">class Xmp(Fuse):

	@others
</t>
<t tx="davidmcnab.121303142957.42">def __init__(self, *args, **kw):

    Fuse.__init__(self, *args, **kw)

    if 0:
        print "xmp.py:Xmp:mountpoint: %s" % repr(self.mountpoint)
        print "xmp.py:Xmp:unnamed mount options: %s" % self.optlist
        print "xmp.py:Xmp:named mount options: %s" % self.optdict

    # do stuff to set up your filesystem here, if you want
    #thread.start_new_thread(self.mythread, ())
    pass
</t>
<t tx="davidmcnab.121303142957.43">def mythread(self):

    """
    The beauty of the FUSE python implementation is that with the python interp
    running in foreground, you can have threads
    """    
    print "mythread: started"
    #while 1:
    #    time.sleep(120)
    #    print "mythread: ticking"

</t>
<t tx="davidmcnab.121303142957.44">flags = 1

</t>
<t tx="davidmcnab.121303142957.45">def getattr(self, path):
	return os.lstat(path)
</t>
<t tx="davidmcnab.121303142957.46">def readlink(self, path):
	return os.readlink(path)
</t>
<t tx="davidmcnab.121303142957.47">def getdir(self, path):
	return map(lambda x: (x,0), os.listdir(path))
</t>
<t tx="davidmcnab.121303142957.48">def unlink(self, path):
	return os.unlink(path)
</t>
<t tx="davidmcnab.121303142957.49">def rmdir(self, path):
	return os.rmdir(path)
</t>
<t tx="davidmcnab.121303142957.50">def symlink(self, path, path1):
	return os.symlink(path, path1)
</t>
<t tx="davidmcnab.121303142957.51">def rename(self, path, path1):
	return os.rename(path, path1)
</t>
<t tx="davidmcnab.121303142957.52">def link(self, path, path1):
	return os.link(path, path1)
</t>
<t tx="davidmcnab.121303142957.53">def chmod(self, path, mode):
	return os.chmod(path, mode)
</t>
<t tx="davidmcnab.121303142957.54">def chown(self, path, user, group):
	return os.chown(path, user, group)
</t>
<t tx="davidmcnab.121303142957.55">def truncate(self, path, size):
	f = open(path, "w+")
	return f.truncate(size)
</t>
<t tx="davidmcnab.121303142957.56">def mknod(self, path, mode, dev):
	""" Python has no os.mknod, so we can only do some things """
	if S_ISREG(mode):
		open(path, "w")
	else:
		return -EINVAL
</t>
<t tx="davidmcnab.121303142957.57">def mkdir(self, path, mode):
	return os.mkdir(path, mode)
</t>
<t tx="davidmcnab.121303142957.58">def utime(self, path, times):
	return os.utime(path, times)
</t>
<t tx="davidmcnab.121303142957.59">def open(self, path, flags):
    #print "xmp.py:Xmp:open: %s" % path
	os.close(os.open(path, flags))
	return 0

</t>
<t tx="davidmcnab.121303142957.60">def read(self, path, len, offset):
    #print "xmp.py:Xmp:read: %s" % path
	f = open(path, "r")
	f.seek(offset)
	return f.read(len)

</t>
<t tx="davidmcnab.121303142957.61">def write(self, path, buf, off):
    #print "xmp.py:Xmp:write: %s" % path
	f = open(path, "r+")
	f.seek(off)
	f.write(buf)
	return len(buf)

</t>
<t tx="davidmcnab.121303142957.62">def release(self, path, flags):
    print "xmp.py:Xmp:release: %s %s" % (path, flags)
    return 0
</t>
<t tx="davidmcnab.121303142957.63">
if __name__ == '__main__':

	server = Xmp()
	server.flags = 0
	server.multithreaded = 1;
	server.main()
</t>
<t tx="davidmcnab.121303142957.64">"""
distutils script for FUSE python module
"""

from distutils.core import setup, Extension

setup(name="fuse",
      version="0.1",
      ext_modules=[Extension("_fusemodule", ["_fusemodule.c"],
                             library_dirs=["../lib",],
                             libraries=["fuse",],
                             ),
                   ],
      py_modules=["fuse"],
      )

</t>
<t tx="davidmcnab.121303142957.65">@language

Refer to the INSTALL file for build/install instructions

General Information
===================

This is a Python[1] interface to FUSE[2].

FUSE (Filesystem in USErspace) is a simple interface for userspace
programs to export a virtual filesystem to the linux kernel.  FUSE
also aims to provide a secure method for non privileged users to
create and mount their own filesystem implementations.

When run from the commandline, "fuse.py" simply reexports the root
filesystem within the mount point as example/fusexmp does in the main
FUSE distribution.  It also offers a class, fuse.Fuse, which can be
subclassed to create a filesystem.  fuse.Xmp is the example filesystem
implementation.

In your subclass of fuse, add attributes with the expected names
("getattr", "readlink", etc) and call signatures (refer to fuse.Xmp)
then call main().  Make it runnable as a #! script, and mount with
	fusermount &lt;mount point&gt; &lt;script name&gt;
for some reason,
	fusermount &lt;mount point&gt; python &lt;script name&gt;
does not seem to work. (why?)

Update
======

Updated 13-Dec-2003 by David McNab &lt;david@rebirthing.co.nz&gt;

    - changed Makefile to use Pyton distutils
    - added setup.py for distutils

    - added 'code.leo' file for convenience of those who use the Leo
      code editor (leo.sf.net)
    
    - added support for 'statfs' and 'fsync' methods (refer xmp.py)

Updated Dec 2003 by David McNab &lt;david@rebirthing.co.nz&gt;:
    
    - added support for 'release' events (ie when file gets closed)
    - added __init__ to base class, which picks off parameters and
      stores them as instance attributes:
          - self.mountpoint - the mountpoint as given in the mount command
          - self.optlist - unnamed options (eg 'rw', 'exec' etc)
          - self.optdict - named options (eg, '-o arg1=val1,arg2=val2...' from mount cmd)
    - fixed incompatibility issues with recent pythons (original was broken
      under python2.3)

Limitations
===========

This is minimally tested, though I think I have exercised each function.
There's no documentation, docstrings, or tests.

Python's lstat() does not return some fields which must be filled in
(st_blksize, st_blocks, st_ino), and _fusemodule assumes that the return
value from the lstat() method is identical to Python's lstat().  This
limitation should be lifted, and some standard order chosen for these
three values.  For now, though, default values are chosen and du returns a
number similar to the "real" one.

The Python Global Interpreter Lock is not handled, so using
fuse.MULTITHREAD will not work.  Modifying the PROLOGUE and EPILOGUE
functions may take care of this.  For now, just run without
fuse.MULTITHREAD in flags.

Author
======

I'm Jeff Epler &lt;jepler@unpythonic.dhs.org&gt;.  I've been dabbling in
Python for nearly 7 years now, and interested (despite the lack of a
real practical use) in userspace filesystems ever since I couldn't get
userfs to compile way back in '93 or so.  FUSE is cool, but i'm still
not sure what it's good for in practical terms.

I don't know how high a level of interest I'll maintain in this project,
so if you want to do something with it feel free to do so.  Like FUSE,
this software is distributed under the terms of the GNU General Public
License, Version 2.  Future versions, if any, will be available at [3].


[1] http://www.python.org
[2] http://sourceforge.net/projects/avf/
[3] http://unpythonic.dhs.org/~jepler/fuse/
</t>
<t tx="davidmcnab.121303142957.67">@first #!/usr/bin/env python

"""
This utility allows FUSE filesystems to be mounted with the regular *nix
'mount' command, or even be listed in /etc/fstab

To enable this, you need to:
 1. set execute-permission on this script
 2. symlink this script into /sbin/mount.fuse

Usage:

 You can use this in 3 ways:
     1.  mount -t fuse /path/to/script/or/program /path/of/mount/point [options]
     2.  mount -t fuse none /path/of/mount/point -o fs=/path/to/script/or/prog[,opt=val...]
     3.  in /etc/fstab, add:
           /path/to/script/or/prog /path/of/mount/point fuse noauto[,...]
"""

import sys, os, time

progname = sys.argv[0]

def usage(ret):
    print "Usage: %s /path/to/fuse/fs /path/of/mountpoint [-o options]" % progname
    print "or:    %s none /path/of/mountpoint [-o fs=/path/to/fuse/fs[,...]]" % progname
    sys.exit(ret)

def main():

    # initial sanity check
    argc = len(sys.argv)
    if argc &lt; 3 or sys.argv[3] != "-o":
        usage(1)

    dev = sys.argv[1]
    mountpoint = sys.argv[2]

    # grab options, if any
    optdict = {}
    optlist = []
    if argc &gt; 4:
        odata = sys.argv[4]
        opts = odata.split(",")
        #print opts
        for o in opts:
            try:
                k, v = o.split("=", 1)
                optdict[k] = v
            except:
                optlist.append(o)
    else:
        odata = ""

    #print sys.argv
    if dev == 'none':
        if not optdict.has_key("fs"):
            print "%s: Must specify python file with 'fs' option\n" % progname
            usage(1)
        pyfile = optdict['fs']
    else:
        pyfile = dev

    if not os.path.isfile(pyfile):
        print "%s: file %s doesn't exist, or is not a file" % (progname, pyfile)
        sys.exit(1)
    pypath = os.path.abspath(pyfile)

    #print optdict, optlist

    # all seems ok - run our fuse fs as a child
    if os.fork() == 0:
        os.system("fusermount -c -x %s %s %s %s" % (mountpoint, pypath, mountpoint, odata))
    else:
        #print "parent exiting..."
        pass

if __name__ == '__main__':
    main()

</t>
<t tx="davidmcnab.121303144134">def statfs(self):
    """
    Should return a tuple with the following 6 elements:
        - blocksize - size of file blocks, in bytes
        - totalblocks - total number of blocks in the filesystem
        - freeblocks - number of free blocks
        - totalfiles - total number of file inodes
        - freefiles - nunber of free file inodes

    Feel free to set any of the above values to 0, which tells
    the kernel that the info is not available.
    """
    print "xmp.py:Xmp:statfs: returning fictitious values"
    blocks_size = 1024
    blocks = 100000
    blocks_free = 25000
    files = 100000
    files_free = 60000
    namelen = 80
    return (blocks_size, blocks, blocks_free, files, files_free, namelen)
</t>
<t tx="davidmcnab.121303144134.1">def fsync(self, path, isfsyncfile):
    print "xmp.py:Xmp:fsync: path=%s, isfsyncfile=%s" % (path, isfsyncfile)
    return 0

</t>
<t tx="davidmcnab.121303144441">static int statfs_func(struct fuse_statfs *fst)
{
  int i;
  long retvalues[6];
  PyObject *v = PyObject_CallFunction(statfs_cb, "");
PROLOGUE

  if (!PySequence_Check(v))
    { goto OUT_DECREF; }
 if (PySequence_Size(v) &lt; 6)
   { goto OUT_DECREF; }
 for(i=0; i&lt;6; i++)
   {
     PyObject *tmp = PySequence_GetItem(v, i);
     retvalues[i] = PyInt_Check(tmp)
       ? PyInt_AsLong(tmp)
       : (PyLong_Check(tmp)
          ? PyLong_AsLong(tmp)
          : 0);
   }

 fst-&gt;block_size  = retvalues[0];
 fst-&gt;blocks      = retvalues[1];
 fst-&gt;blocks_free = retvalues[2];
 fst-&gt;files       = retvalues[3];
 fst-&gt;files_free  = retvalues[4];
 fst-&gt;namelen     = retvalues[5];
 ret = 0;
 
#ifdef IGNORE_THIS
 printf("block_size=%ld, blocks=%ld, blocks_free=%ld, files=%ld, files_free=%ld, namelen=%ld\n",
        retvalues[0], retvalues[1], retvalues[2], retvalues[3], retvalues[4], retvalues[5]);
#endif

EPILOGUE

}

</t>
<t tx="davidmcnab.121303144441.1">static int fsync_func(const char *path, int isfsyncfile)
{
	PyObject *v = PyObject_CallFunction(fsync_cb, "si", path, isfsyncfile);
	PROLOGUE
	EPILOGUE
}

</t>
<t tx="davidmcnab.121403050157">@ignore
@language python
&lt;&lt; fuse declarations &gt;&gt;
@others
    #@-node:main
    #@-others
#@-node:class Fuse
#@-others
#@-node:@file fuse.py
#@-leo
</t>
<t tx="davidmcnab.121403050157.1">#@+leo-ver=4
#@+node:@file fuse.py
#
#    Copyright (C) 2001  Jeff Epler  &lt;jepler@unpythonic.dhs.org&gt;
#
#    This program can be distributed under the terms of the GNU GPL.
#    See the file COPYING.
#


#@@language python
#@+others
#@+node:imports
# suppress version mismatch warnings
try:
    import warnings
    warnings.filterwarnings('ignore',
                            'Python C API version mismatch',
                            RuntimeWarning,
                            )
except:
    pass
 
from _fuse import main, DEBUG
import os, sys
from errno import *

#@-node:imports
#@+node:class ErrnoWrapper
</t>
<t tx="davidmcnab.121403050157.2">class ErrnoWrapper:
	&lt;&lt; class ErrnoWrapper declarations &gt;&gt;
	@others
</t>
<t tx="davidmcnab.121403050157.3">    #@	@+others
    #@+node:__init__
</t>
<t tx="davidmcnab.121403050157.4">def __init__(self, func):
	self.func = func
</t>
<t tx="davidmcnab.121403050157.5">#@-node:__init__
#@+node:__call__
def __call__(self, *args, **kw):
	try:
		return apply(self.func, args, kw)
	except (IOError, OSError), detail:
		# Sometimes this is an int, sometimes an instance...
		if hasattr(detail, "errno"): detail = detail.errno
		return -detail
</t>
<t tx="davidmcnab.121403050157.6">    #@-node:__call__
    #@-others
#@-node:class ErrnoWrapper
#@+node:class Fuse
class Fuse:
	&lt;&lt; class Fuse declarations &gt;&gt;
	@others
</t>
<t tx="davidmcnab.121403050157.7">#@	@+others
#@+node:attribs
_attrs = ['getattr', 'readlink', 'getdir', 'mknod', 'mkdir',
	  'unlink', 'rmdir', 'symlink', 'rename', 'link', 'chmod',
	  'chown', 'truncate', 'utime', 'open', 'read', 'write', 'release',
      'statfs', 'fsync']

flags = 0
multithreaded = 0

#@-node:attribs
#@+node:__init__
</t>
<t tx="davidmcnab.121403050157.8">def __init__(self, *args, **kw):

    # default attributes
    self.optlist = []
    self.optdict = {}
    self.mountpoint = None

    # grab arguments, if any
    argv = sys.argv
    argc = len(argv)
    if argc &gt; 1:
        # we've been given the mountpoint
        self.mountpoint = argv[1]
    if argc &gt; 2:
        # we've received mount args
        optstr = argv[2]
        opts = optstr.split(",")
        for o in opts:
            try:
                k, v = o.split("=", 1)
                self.optdict[k] = v
            except:
                self.optlist.append(o)
</t>
<t tx="davidmcnab.121403050157.9">#@-node:__init__
#@+node:main
def main(self):
	d = {'flags': self.flags}
	d['multithreaded'] = self.multithreaded
	for a in self._attrs:
		if hasattr(self,a):
			d[a] = ErrnoWrapper(getattr(self, a))
	apply(main, (), d)
</t>
</tnodes>
</leo_file>
