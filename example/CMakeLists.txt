# CMake equivalent of libfuse's meson.build
# Every attempt has been made to match all the functionality provided by meson
# Use at your own risk

cmake_minimum_required (VERSION 3.12.0)
set (CMAKE_VERBOSE_MAKEFILE FALSE)

if( DEFINED NDEBUG )
        message(WARNING "NDEBUG is defined, you will almost definitely experience problems")
endif()

set(EXAMPLES passthrough passthrough_fh hello hello_ll printcap ioctl_client
             poll_client ioctl cuse cuse_client)

if (NOT ${CMAKE_SYSTEM_NAME} MATCHES "bsd$" AND NOT ${CMAKE_SYSTEM_NAME} STREQUAL "dragonfly")
    list(APPEND EXAMPLES passthrough_ll)

    # According to Conrad Meyer <cem@freebsd.org>, FreeBSD doesn't
    # support mounting files, This is enforced in vfs_domount_first()
    # with the v_type != VDIR check.
    list(APPEND EXAMPLES "null")
endif()

set(THREADED_EXAMPLES notify_inval_inode invalidate_path notify_store_retrieve
                      notify_inval_entry poll)

foreach( EXAMPLE ${EXAMPLES} )
    add_executable(${EXAMPLE} ${EXAMPLE}.c)
    target_link_libraries(${EXAMPLE} fuse3)
endforeach()


foreach( EXAMPLE ${THREADED_EXAMPLES} )
    add_executable(${EXAMPLE} ${EXAMPLE}.c)
    target_link_libraries(${EXAMPLE} ${CMAKE_THREAD_LIBS_INIT} fuse3)
endforeach()

# TODO: Link passthrough_fh with ulockmgr if available
