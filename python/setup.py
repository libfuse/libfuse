#@+leo-ver=4
#@+node:@file setup.py
"""
distutils script for FUSE python module
"""

from distutils.core import setup, Extension

setup(name="fuse",
      version="0.1",
      ext_modules=[Extension("_fusemodule", ["_fusemodule.c"],
                             library_dirs=["../lib/.libs",],
                             include_dirs=["../include",],
                             libraries=["fuse",],
                             ),
                   ],
      py_modules=["fuse"],
      )

#@-node:@file setup.py
#@-leo
