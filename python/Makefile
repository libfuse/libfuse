_fusemodule.so: _fusemodule.c
	gcc -g3 -I/usr/include/python1.5 _fusemodule.c -Wl,-shared -o _fusemodule.so -Wimplicit -lfuse && python -c 'import _fuse'

demo: _fusemodule.so
	-sudo umount tmp
	fusermount tmp ./fuse.py


clean:
	rm _fusemodule.so *.pyc *.pyo
