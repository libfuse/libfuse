AC_INIT(fuse-kernel, 2.2-pre0)
AC_CONFIG_HEADERS([config.h])

AC_PROG_INSTALL

AC_MSG_CHECKING([kernel source directory])
kernelsrc=
AC_ARG_WITH(kernel,
	[  --with-kernel=PATH      Specify location of kernel source ],
	[kernelsrc="$withval"])

if test -z "$kernelsrc"; then
	buildlink=/lib/modules/`uname -r`/build
	if test -e $buildlink; then
		kernelsrc=`(cd $buildlink; /bin/pwd)`
	else
		AC_MSG_RESULT([Not found])
		AC_MSG_ERROR([
*** Please specify the location of the kernel source with
*** the '--with-kernel=SRCDIR' option])
	fi
fi
AC_MSG_RESULT([$kernelsrc])

AC_MSG_CHECKING([kernel source version])
if test -r $kernelsrc/include/linux/version.h; then
	kernsrcver=`(echo "#include <linux/version.h>"; echo "kernsrcver=UTS_RELEASE") | cpp -I $kernelsrc/include | grep "^kernsrcver=" | cut -d \" -f 2`
fi
if test -z "$kernsrcver"; then
	AC_MSG_RESULT([Not found])
	AC_MSG_ERROR([
*** Cannot determine the version of the linux kernel source. Please 
*** configure the kernel before running this script])
fi
AC_MSG_RESULT([$kernsrcver])
majver=`echo "$kernsrcver" | cut -f-2 -d.`
kmoduledir=/lib/modules/$kernsrcver
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
	CFLAGS="$old_cflags"
fi

AC_MSG_CHECKING([whether fs_subsys is declared])
if grep -q fs_subsys $kernelsrc/include/linux/fs.h; then
	AC_DEFINE(HAVE_FS_SUBSYS, 1, [Kernel defines fs_subsys])
	AC_MSG_RESULT([yes])
else
	AC_MSG_RESULT([no])
fi

AC_MSG_CHECKING([if kernel has extended attribute support])
if test -f $kernelsrc/include/linux/xattr.h; then
	AC_DEFINE(HAVE_KERNEL_XATTR, 1, [Kernel has xattr support])
	AC_MSG_RESULT([yes])
else
	AC_MSG_RESULT([no])
fi

isuml=no
KERNELMAKE_PARAMS=
KERNELCPPFLAGS=
AC_MSG_CHECKING([if this is user mode linux])
if test -f $kernelsrc/include/linux/autoconf.h && grep -q "^#define CONFIG_USERMODE 1" $kernelsrc/include/linux/autoconf.h; then
	isuml=yes
	KERNELMAKE_PARAMS="ARCH=um"
	KERNELCPPFLAGS="-D__arch_um__ -DSUBARCH=\\\"i386\\\" -D_LARGEFILE64_SOURCE -I${kernelsrc}/arch/um/include -Derrno=kernel_errno -I${kernelsrc}/arch/um/kernel/tt/include -I${kernelsrc}/arch/um/kernel/skas/include"
fi
AC_MSG_RESULT([$isuml])
AC_SUBST(KERNELMAKE_PARAMS)
AC_SUBST(KERNELCPPFLAGS)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
