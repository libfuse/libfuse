genrule(
  name="config",
  outs=["include/config.h"],
  cmd="touch $@",
)

cc_library(
  name="fuse",
  visibility=["//visibility:public"],
  includes=["include",],
  hdrs=glob(["include/**/*.h"]) + [":config"],
  srcs=glob(
    include=["lib/**/*.c", "lib/**/*.h",], 
    exclude=["lib/mount_bsd.c", ]),
  defines=[
    "_FILE_OFFSET_BITS=64",
    "FUSE_USE_VERSION=30", 
    "FUSERMOUNT_DIR=\\\"/usr/local/bin\\\"",
    'PACKAGE_VERSION=\\\"3.0.0\\\"',
  ],
  linkopts=["-ldl", "-Wl,--version-script", "lib/fuse.lds"],
  deps=["lib/fuse.lds"],
)

