project('libfuse3', ['c'], version: '3.14.1',
        meson_version: '>= 0.51',
        default_options: [
            'buildtype=debugoptimized',
            'cpp_std=c++11',
            'warning_level=2',
        ])


platform = host_machine.system()
if platform == 'darwin'
  error('libfuse does not support OS-X.\n' +
        'Take a look at http://osxfuse.github.io/ instead')
elif platform == 'cygwin' or platform == 'windows'
  error('libfuse does not support Windows.\n' +
        'Take a look at http://www.secfs.net/winfsp/ instead')       
endif

cc = meson.get_compiler('c')

#
# Feature detection, only available at libfuse compilation time,
# but not for application linking to libfuse.
#
private_cfg = configuration_data()

#
# Feature detection, the resulting config file is installed
# with the package.
# Note: Symbols need to be care fully named, to avoid conflicts
#       with applications linking to libfuse and including
#       this config.
#
public_cfg = configuration_data()

# Default includes when checking for presence of functions and
# struct members
include_default = '''
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
'''
args_default = [ '-D_GNU_SOURCE' ]

private_cfg.set_quoted('PACKAGE_VERSION', meson.project_version())

# Test for presence of some functions
test_funcs = [ 'fork', 'fstatat', 'openat', 'readlinkat', 'pipe2',
               'splice', 'vmsplice', 'posix_fallocate', 'fdatasync',
               'utimensat', 'copy_file_range', 'fallocate' ]
foreach func : test_funcs
    private_cfg.set('HAVE_' + func.to_upper(),
        cc.has_function(func, prefix: include_default, args: args_default))
endforeach
private_cfg.set('HAVE_SETXATTR', 
        cc.has_function('setxattr', prefix: '#include <sys/xattr.h>'))
private_cfg.set('HAVE_ICONV', 
        cc.has_function('iconv', prefix: '#include <iconv.h>'))

# Test if structs have specific member
private_cfg.set('HAVE_STRUCT_STAT_ST_ATIM',
         cc.has_member('struct stat', 'st_atim',
                       prefix: include_default,
                       args: args_default))
private_cfg.set('HAVE_STRUCT_STAT_ST_ATIMESPEC',
         cc.has_member('struct stat', 'st_atimespec',
                       prefix: include_default,
                       args: args_default))

#
# Compiler configuration
#
add_project_arguments('-D_REENTRANT', '-DHAVE_LIBFUSE_PRIVATE_CONFIG_H', '-Wno-sign-compare',
                      '-Wstrict-prototypes', '-Wmissing-declarations', '-Wwrite-strings',
                      '-fno-strict-aliasing', language: 'c')
add_project_arguments('-D_REENTRANT', '-DHAVE_LIBFUSE_PRIVATE_CONFIG_H', '-D_GNU_SOURCE',
                     '-Wno-sign-compare', '-Wmissing-declarations',
                     '-Wwrite-strings', '-fno-strict-aliasing', language: 'cpp')

# Some (stupid) GCC versions warn about unused return values even when they are
# casted to void. This makes -Wunused-result pretty useless, since there is no
# way to suppress the warning when we really *want* to ignore the value.
code = '''
__attribute__((warn_unused_result)) int get_4() {
    return 4;
}
int main(void) {
    (void) get_4();
    return 0;
}'''
if not cc.compiles(code, args: [ '-O0', '-Werror=unused-result' ])
     message('Compiler warns about unused result even when casting to void')
     add_project_arguments('-Wno-unused-result', language: 'c')
endif

# It is hard to detect if the libc supports versioned symbols. Only gnu-libc
# seems to provide that, but then glibc is the main target for libfuse, so
# enable it by default
versioned_symbols = 1

# This is an attempt to detect if another libc is used.
code = '''
int main(void) {
#if (defined(__UCLIBC__) || defined(__APPLE__))
#error /* libc does not have versioned symbols */
#endif
    return 0;
}'''
if not cc.compiles(code, args: [ '-O0' ])
  versioned_symbols = 0
endif

# The detection can be overridden, which is useful for other (above unhandled)
# libcs and also especially useful for testing
if get_option('disable-libc-symbol-version')
     versioned_symbols = 0
endif

if versioned_symbols == 1
     message('Enabling versioned libc symbols')
     public_cfg.set('LIBFUSE_BUILT_WITH_VERSIONED_SYMBOLS', 1)

     # gcc-10 and newer support the symver attribute which we need to use if we
     # want to support LTO
     # recent clang and gcc both support __has_attribute (and if they are too old
     # to have __has_attribute, then they are too old to support symver)
     # other compilers might not have __has_attribute, but in those cases
     # it is safe for this check to fail and for us to fallback to the old _asm_
     # method for symver. Anyway the attributes not supported by __has_attribute()
     # unfortunately return true giving a false positive. So let's try to build
     # using __attribute__ ((symver )) and see the result.
     code = '''
     __attribute__ ((symver ("test@TEST")))
     void foo(void) {
     }

     int main(void) {
         return 0;
     }'''
     if cc.compiles(code, args: [ '-O0', '-c', '-Werror'])
          message('Compiler supports symver attribute')
          add_project_arguments('-DHAVE_SYMVER_ATTRIBUTE', language: 'c')
     else
          message('Compiler does not support symver attribute')
     endif
else
     message('Disabling versioned libc symbols')
endif

# Older versions of musl libc don't unescape entries in /etc/mtab
# Try to detect this behaviour, and work around, if necessary.
detect_getmntent_needs_unescape = '''
#define _GNU_SOURCE
#include <mntent.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define dir_space_tab "dir\\040space\\011tab"

int main()
{
    const char *fake_mtab = "name " dir_space_tab " type opts 0 0\n";
    FILE *f = fmemopen((void *)fake_mtab, strlen(fake_mtab) + 1, "r");
    struct mntent *entp = getmntent(f);
    fclose(f);
    if(NULL == entp)
        exit(EXIT_FAILURE);
    if (0 == strcmp(entp->mnt_dir, dir_space_tab))
        printf("needs escaping\n");
    else
        printf("no need to escape\n");
}
'''

result = cc.run(detect_getmntent_needs_unescape)
if result.compiled() and result.returncode() == 0 and result.stdout().strip() == 'needs escaping'
  message('getmntent does not unescape')
  add_project_arguments('-DGETMNTENT_NEEDS_UNESCAPING', language: 'c')
endif

# Write private test results into fuse_config.h (stored in build directory)
configure_file(output: 'fuse_config.h', configuration : private_cfg)

# Write the test results, installed with the package,
# symbols need to be properly prefixed to avoid
# symbol (define) conflicts
configure_file(output: 'libfuse_config.h',
               configuration : public_cfg,
               install: true, install_dir: join_paths(get_option('includedir'), 'fuse3'))

# '.' will refer to current build directory, which contains config.h
include_dirs = include_directories('include', 'lib', '.')

# Common dependencies
thread_dep = dependency('threads') 

#
# Read build files from sub-directories
#
subdirs = [ 'lib', 'include']
if get_option('utils') and not platform.endswith('bsd') and platform != 'dragonfly'
  subdirs += [ 'util', 'doc' ]
endif

if get_option('examples')
  subdirs += 'example'
endif

if get_option('tests')
  subdirs += 'test'
endif

foreach n : subdirs
    subdir(n)
endforeach

