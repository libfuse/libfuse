_fusemodule.so: _fusemodule.c
	gcc -g3 -I/usr/include/python1.5 _fusemodule.c -Wl,-shared -o _fusemodule.so -Wimplicit -lfuse && python -c 'import _fuse'

clean:
	rm -f _fusemodule.so *.pyc *.pyo
