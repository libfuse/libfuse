AC_INIT(fuse-kernel, 2.6.0-pre3)
AC_CONFIG_HEADERS([config.h])

AC_PROG_INSTALL

runver=`uname -r`
ENABLE_FUSE_MODULE=y
KERNELCFLAGS=

kernelsrc=
kernelbuild=
AC_ARG_WITH(kernel,
	[  --with-kernel=PATH      Specify location of kernel source ],
	[kernelsrc="$withval"; kernelbuild="$withval"])
AC_ARG_WITH(kernel-build,
	[  --with-kernel-build=PATH Specify location of kernel build ],
	[kernelbuild="$withval"])
AC_ARG_ENABLE(kernel-module,
	[  --enable-kernel-module  Compile kernel module ])

if test -z "$enable_kernel_module" -a -z "$kernelbuild" && echo "$runver" | grep -q "^2.6"; then
	checkmodule=no
	AC_MSG_CHECKING([if FUSE is loaded as a module])
	if cat /proc/modules | grep -q "^fuse "; then
		AC_MSG_RESULT([yes])
		checkmodule=yes
	else
		AC_MSG_RESULT([no])
		AC_MSG_CHECKING([if FUSE module is built into the kernel])
		if test -e /sys/class/misc/fuse; then
			AC_MSG_RESULT([yes])
			ENABLE_FUSE_MODULE=n
		else
			AC_MSG_RESULT([no])
			checkmodule=yes
		fi
	fi
	if test "$checkmodule" = yes; then
		AC_MSG_CHECKING([if FUSE module is from official kernel])
		if test ! -f /lib/modules/${runver}/kernel/fs/fuse/fuse.ko; then
			AC_MSG_RESULT([no])
		elif fgrep -q "fuse distribution version: " /lib/modules/${runver}/kernel/fs/fuse/fuse.ko 2> /dev/null; then
			AC_MSG_RESULT([no])
		else
			AC_MSG_RESULT([yes])
			ENABLE_FUSE_MODULE=n
		fi
	fi
fi

if test "$ENABLE_FUSE_MODULE" = y; then
	AC_MSG_CHECKING([kernel source directory])
	if test -z "$kernelsrc"; then
		kernelbuild=
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
		AC_MSG_CHECKING([if '-msoft-float' option is valid])
		CFLAGS="-msoft-float"
		have_msoft_float=no
		AC_TRY_COMPILE([], [], [have_msoft_float=yes])
		AC_MSG_RESULT([$have_msoft_float])
		if test "$have_msoft_float" = yes; then
			KERNELCFLAGS="$CFLAGS"
		fi
		CFLAGS="$old_cflags"
		AC_MSG_CHECKING([architecture])
		arch=`/bin/ls -l ${kernelsrc}/include/asm | sed "s/.*-> asm-//"`
		AC_MSG_RESULT([$arch])
		if test "$arch" = x86_64; then
			KERNELCFLAGS="$KERNELCFLAGS -mno-red-zone -mcmodel=kernel -fno-reorder-blocks -finline-limit=2000"
		fi
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
		fi
	fi
fi

if test "$ENABLE_FUSE_MODULE" = n; then
	AC_MSG_NOTICE([NOTE:     Detected that FUSE is already present in the kernel, so])
	AC_MSG_NOTICE([NOTE:     building of kernel module is disabled.  To force building])
	AC_MSG_NOTICE([NOTE:     of kernel module use the '--enable-kernel-module' option.])
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
	AC_MSG_CHECKING([if kernel defines kzalloc function])
	if egrep -qw "kzalloc" $kernelsrc/include/linux/slab.h; then
		AC_DEFINE(HAVE_KZALLOC, 1, [kzalloc() is defined])
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
	fi

	AC_MSG_CHECKING([if kernel defines fs_subsys])
	if egrep -qw "fs_subsys" $kernelsrc/include/linux/fs.h; then
		AC_DEFINE(HAVE_FS_SUBSYS, 1, [fs_subsys is defined])
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
	AC_SUBST(KERNELCFLAGS)
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
