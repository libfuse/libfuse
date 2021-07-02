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

# meson build has a check for CPP compiler use, we don't bother !
#if not platform.endswith('bsd') and platform != 'dragonfly' and add_languages('cpp', required : false)
if (NOT ${CMAKE_SYSTEM_NAME} MATCHES "bsd$" AND NOT ${CMAKE_SYSTEM_NAME} STREQUAL "dragonfly")
    add_executable(passthrough_hp passthrough_hp.cc)
    target_link_libraries(passthrough_hp ${CMAKE_THREAD_LIBS_INIT} fuse3)
    # The problem with setting global compile options !
    get_target_property(_target_cxx_flags passthrough_hp COMPILE_OPTIONS)
    if(_target_cxx_flags)
        list(REMOVE_ITEM _target_cxx_flags -Wstrict-prototypes)
        set_target_properties(passthrough_hp PROPERTIES COMPILE_OPTIONS "${_target_cxx_flags}")
    endif()
endif()

# TODO: Link passthrough_fh with ulockmgr if available
