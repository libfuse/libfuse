# CMake equivalent of libfuse's meson.build
# Every attempt has been made to match all the functionality provided by meson
# Use at your own risk

cmake_minimum_required (VERSION 3.12.0)
set (CMAKE_VERBOSE_MAKEFILE FALSE)

include(GNUInstallDirs)

install(FILES fusermount3.1 mount.fuse3.8 
        DESTINATION ${CMAKE_INSTALL_MANDIR})

