#@+leo-ver=4
#@+node:@file Makefile
# Makefile now uses distutils

_fusemodule.so: _fusemodule.c
	#gcc -g3 -I/usr/include/python2.1 _fusemodule.c -Wl,-shared -o _fusemodule.so -Wimplicit -lfuse && python -c 'import _fuse'
	python setup.py build_ext --inplace

install: _fusemodule.so
	python setup.py install

clean:
	rm -rf _fusemodule.so *.pyc *.pyo *~ build
#@-node:@file Makefile
#@-leo
