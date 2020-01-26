# CMake equivalent of libfuse's meson.build
# Every attempt has been made to match all the functionality provided by meson
# Use at your own risk

cmake_minimum_required (VERSION 3.12.0)
set (CMAKE_VERBOSE_MAKEFILE FALSE)

project (libfuse3
         VERSION 3.9.0
         DESCRIPTION "The reference implementation of the Linux FUSE (Filesystem in Userspace) interface"
         HOMEPAGE_URL https://github.com/libfuse/libfuse
	 LANGUAGES C CXX )

if (NOT EXISTS ${CMAKE_BINARY_DIR}/CMakeCache.txt)
  if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "" FORCE)
  endif()
endif()



if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  message(FATAL_ERROR "libfuse does not support OS-X.\n"
                      "Take a look at http://osxfuse.github.io/ instead")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "cygwin" OR ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  message(FATAL_ERROR "libfuse does not support Windows.\n"
                      "Take a look at http://www.secfs.net/winfsp/ instead")
endif()


include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckStructHasMember)


check_include_file("stdio.h" HAVE_STDIO_H)
check_include_file("stdlib.h" HAVE_STDLIB_H)
check_include_file("stddef.h" HAVE_STDDEF_H)
check_include_file("unistd.h" HAVE_MEMORY_H)
check_include_file("sys/types.h" HAVE_SYS_TYPES_H)
check_include_file("sys/stat.h" HAVE_SYS_STAT_H)
check_include_file("fcntl.h" HAVE_FCNTL_H)


check_function_exists("fork" HAVE_FORK)
check_function_exists("fstatat" HAVE_FSTATAT)
check_function_exists("openat" HAVE_OPENAT)
check_function_exists("readlinkat" HAVE_READLINKAT)
check_function_exists("pipe2" HAVE_PIPE2)
check_function_exists("splice" HAVE_SPLICE)
check_function_exists("vmsplice" HAVE_VMSPLICE)
check_function_exists("posix_fallocate" HAVE_POSIX_FALLOCATE)
check_function_exists("fdatasync" HAVE_FDATASYNC)
check_function_exists("utimensat" HAVE_UTIMENSAT)
check_function_exists("copy_file_range" HAVE_COPY_FILE_RANGE)

# For some reason the meson build checks these seperately
check_symbol_exists("setxattr" "sys/xattr.h" HAVE_SETXATTR)
check_symbol_exists("iconv" "iconv.h" HAVE_ICONV)

CHECK_STRUCT_HAS_MEMBER("struct stat" st_atim sys/stat.h HAVE_STRUCT_STAT_ST_ATIM LANGUAGE C)
CHECK_STRUCT_HAS_MEMBER("struct stat" st_atimespec sys/stat.h HAVE_STRUCT_STAT_ST_ATIMESPEC LANGUAGE C)

add_compile_options("-Dlinux=1" "-D_REENTRANT" "-DHAVE_CONFIG_H" "-Wall" "-Wextra" "-Wno-sign-compare"
                      "-Wstrict-prototypes" "-Wmissing-declarations" "-Wwrite-strings"
                      "-fno-strict-aliasing")

# This comment appears in meson.build -
# not sure why the author thinks it's stupid to warn about an unused return values
# Seems like the right thing to do is fix the code, instead of cast to void.
## Some (stupid) GCC versions warn about unused return values even when they are
## casted to void. This makes -Wunused-result pretty useless, since there is no
## way to suppress the warning when we really *want* to ignore the value.
set(CHECK_UNUSED_RESULT_WARNING "
__attribute__((warn_unused_result)) int get_4() {
    return 4;
}
int main(void) {
    (void) get_4();
    return 0;
}")

CHECK_C_SOURCE_COMPILES("${CHECK_UNUSED_RESULT_WARNING}" CHECK_UNUSED_RESULT)
if(CHECK_UNUSED_RESULT)
  message(WARNING "Compiler warns about unused result even when casting to void")
  add_compile_options("-Wno-unused-result")
endif()

set(INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/lib" "${PROJECT_BINARY_DIR}/.")

include(FindThreads)
find_package( Threads REQUIRED )
# Trying to reproduce meson.build - but, some of what that does seems a little sloppy
# Including this:  globally add threading to everything !
# Prefer add_link_options - but my version of cmake doesn't support
# Besides, it's not clear that it would be better to use target_link_libraries
link_libraries(Threads::Threads)
add_compile_options(${CMAKE_THREAD_LIBS_INIT})

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/lib)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/include)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/test)

option(OPTION_BUILD_UTILS "Also build utils and docs" OFF)
if(OPTION_BUILD_UTILS)
  if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "BSD" AND NOT  ${CMAKE_SYSTEM_NAME} MATCHES "DRAGONFLY" )
    message("Also building utils and docs")
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/util)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/doc)
  endif()
else()
	message("NOT building utils and docs (hint: OPTION_BUILD_UTILS)")
endif()

option(OPTION_BUILD_EXAMPLES "Also build examples" OFF)
if(OPTION_BUILD_EXAMPLES)
  message("Also building examples")
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/example)
else()
	message("NOT building examples (hint: OPTION_BUILD_EXAMPLES)")
endif()

configure_file (
    "${PROJECT_SOURCE_DIR}/config.h.in"
    "${PROJECT_BINARY_DIR}/config.h"
)
