_fusemodule.so: _fusemodule.c
	gcc -g3 -I/usr/include/python2.1 _fusemodule.c -Wl,-shared -o _fusemodule.so -Wimplicit -lfuse && python -c 'import _fuse'

clean:
	rm -f _fusemodule.so *.pyc *.pyo
