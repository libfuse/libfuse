# CMake equivalent of libfuse's meson.build
# Every attempt has been made to match all the functionality provided by meson
# Use at your own risk

cmake_minimum_required (VERSION 3.12.0)
set (CMAKE_VERBOSE_MAKEFILE FALSE)

if( DEFINED NDEBUG )
	message(WARNING "NDEBUG is defined, you will almost definitely experience problems")
endif()

add_executable( test_write_cache)
target_sources( test_write_cache PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/test_write_cache.c )
target_include_directories(test_write_cache PUBLIC ${INCLUDE_DIRS})
target_link_libraries(test_write_cache fuse3 ${CMAKE_THREAD_LIBS_INIT})

add_executable(test_setattr)
target_sources(test_setattr PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/test_setattr.c)
target_include_directories(test_setattr PUBLIC ${INCLUDE_DIRS})
target_link_libraries(test_setattr fuse3 ${CMAKE_THREAD_LIBS_INIT})

add_executable(test_syscalls)
target_sources(test_syscalls PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/test_syscalls.c)
target_include_directories(test_syscalls PUBLIC ${INCLUDE_DIRS})
#target_link_libraries(test_syscalls fuse3 ${CMAKE_THREAD_LIBS_INIT})

set(TEST_SCRIPTS conftest.py pytest.ini test_examples.py util.py test_ctests.py)

add_custom_target(test_scripts)
foreach(TEST_SCRIPT ${TEST_SCRIPTS})
  add_custom_command(TARGET test_scripts PRE_BUILD
                     COMMAND ${CMAKE_COMMAND} -E
                         copy ${CMAKE_CURRENT_SOURCE_DIR}/${TEST_SCRIPT} ${CMAKE_CURRENT_BINARY_DIR}/.)
endforeach()
add_dependencies(fuse3 test_scripts)
