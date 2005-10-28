AC_INIT(fuse-kernel, 2.5.0-pre0)
AC_CONFIG_HEADERS([config.h])

AC_PROG_INSTALL

kernelsrc=
kernelbuild=
AC_ARG_WITH(kernel,
	[  --with-kernel=PATH      Specify location of kernel source ],
	[kernelsrc="$withval"; kernelbuild="$withval"])
AC_ARG_WITH(kernel-build,
	[  --with-kernel-build=PATH Specify location of kernel build ],
	[kernelbuild="$withval"])

AC_MSG_CHECKING([kernel source directory])
if test -z "$kernelsrc"; then
	kernelbuild=
	runver=`uname -r`
	sourcelink=/lib/modules/${runver}/source
	buildlink=/lib/modules/${runver}/build

	if test -e $sourcelink; then
		kernelsrc=`(cd $sourcelink; /bin/pwd)`
	fi
	if test -e $buildlink; then
		kernelbuild=`(cd $buildlink; /bin/pwd)`
	fi
	if test -z "$kernelsrc"; then
		kernelsrc=$kernelbuild
	fi
	if test -z "$kernelsrc" -o -z "$kernelbuild"; then
		AC_MSG_RESULT([Not found])
		AC_MSG_ERROR([
*** Please specify the location of the kernel source with
*** the '--with-kernel=SRCDIR' option])
	fi
fi
AC_MSG_RESULT([$kernelsrc])
AC_MSG_CHECKING([kernel build directory])
AC_MSG_RESULT([$kernelbuild])

AC_ARG_ENABLE(kernel-module,
	[  --enable-kernel-module  Compile kernel module ])

AC_MSG_CHECKING([kernel source version])
if test -r $kernelbuild/include/linux/version.h; then
	kernsrcver=`(echo "#include <linux/version.h>"; echo "kernsrcver=UTS_RELEASE") | cpp -I $kernelbuild/include | grep "^kernsrcver=" | cut -d \" -f 2`
fi
if test -z "$kernsrcver"; then
	AC_MSG_RESULT([Not found])
	AC_MSG_ERROR([
*** Cannot determine the version of the linux kernel source. Please
*** prepare the kernel before running this script])
fi
AC_MSG_RESULT([$kernsrcver])
majver=`echo "$kernsrcver" | cut -f-2 -d.`
kmoduledir=${INSTALL_MOD_PATH}/lib/modules/$kernsrcver
AC_SUBST(kernelsrc)
AC_SUBST(majver)
AC_SUBST(kmoduledir)

ENABLE_FUSE_MODULE=y
if echo "$kernsrcver" | grep -q "^2.4"; then
       	old_cflags="$CFLAGS"
       	CFLAGS="-I${kernelsrc}/include -Wall -O2 -fno-strict-aliasing -D__KERNEL__"
	AC_CHECK_DECL(i_size_read,
		AC_DEFINE(HAVE_I_SIZE_FUNC, 1,
			[Kernel has i_size_read() and i_size_write() functions]),,
		[#include <linux/fs.h>])
	AC_CHECK_DECL(recalc_sigpending_tsk,
		AC_DEFINE(HAVE_RECALC_SIGPENDING_TSK, 1,
			[Kernel has recalc_sigpending_tsk() function]),,
		[#include <linux/sched.h>])
	CFLAGS="$old_cflags"
else
	fuse_configured=no
	kernel_autoconf=$kernelbuild/include/linux/autoconf.h
	AC_MSG_CHECKING([if FUSE is configured in the kernel])
	if test -f $kernel_autoconf; then
		if grep -q "^#define CONFIG_FUSE_FS 1" $kernel_autoconf || grep -q "^#define CONFIG_FUSE_FS_MODULE 1" $kernel_autoconf; then
			fuse_configured=yes
		fi
	fi
	AC_MSG_RESULT([$fuse_configured])
	if test -z "$enable_kernel_module" -a "$fuse_configured" = yes; then
		ENABLE_FUSE_MODULE=n
		AC_MSG_NOTICE([NOTE:     Detected that FUSE is already present in the kernel, so])
		AC_MSG_NOTICE([NOTE:     building of kernel module is disabled.  To force building])
		AC_MSG_NOTICE([NOTE:     of kernel module use the '--enable-kernel-module' option.])
	fi
fi
if test "$enable_kernel_module" = no; then
	ENABLE_FUSE_MODULE=n
fi

AC_SUBST(ENABLE_FUSE_MODULE)

if test "$ENABLE_FUSE_MODULE" = y; then
	AC_MSG_CHECKING([if kernel has extended attribute support])
	if test -f $kernelsrc/include/linux/xattr.h; then
		AC_DEFINE(HAVE_KERNEL_XATTR, 1, [Kernel has xattr support])
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
	fi

	AC_MSG_CHECKING([whether lookup_instantiate_filp is defined])
	if test -f $kernelsrc/include/linux/namei.h && egrep -q "lookup_instantiate_filp" $kernelsrc/include/linux/namei.h; then
		AC_DEFINE(HAVE_LOOKUP_INSTANTIATE_FILP, 1, [lookup_instantiate_filp() is defined])
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
	fi

	isuml=no
	KERNELMAKE_PARAMS=
	KERNELCPPFLAGS=
	AC_MSG_CHECKING([if this is user mode linux])
	if test -f $kernelbuild/include/linux/autoconf.h && egrep -q "^#define CONFIG_(USERMODE|UML) 1" $kernelbuild/include/linux/autoconf.h; then
		isuml=yes
		KERNELMAKE_PARAMS="ARCH=um"
		KERNELCPPFLAGS="-D__arch_um__ -DSUBARCH=\\\"i386\\\" -D_LARGEFILE64_SOURCE -I${kernelsrc}/arch/um/include -Derrno=kernel_errno -I${kernelsrc}/arch/um/kernel/tt/include -I${kernelsrc}/arch/um/kernel/skas/include"
	fi
	AC_MSG_RESULT([$isuml])
	if test "$kernelbuild" != "$kernelsrc"; then
		KERNELMAKE_PARAMS="$KERNELMAKE_PARAMS O=$kernelbuild"
	fi
	AC_SUBST(KERNELMAKE_PARAMS)
	AC_SUBST(KERNELCPPFLAGS)
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
