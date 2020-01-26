# CMake equivalent of libfuse's meson.build
# Every attempt has been made to match all the functionality provided by meson
# Use at your own risk

cmake_minimum_required (VERSION 3.12.0)
set (CMAKE_VERBOSE_MAKEFILE FALSE)

# We do this slightly out of order compared to meson.build (because CMake is more logical ?)
# In meson it seems you collect all your variables first, then construct the target from them
add_library(fuse3 SHARED fuse.c fuse_i.h fuse_loop.c fuse_loop_mt.c fuse_lowlevel.c
              fuse_misc.h fuse_opt.c fuse_signals.c buffer.c cuse_lowlevel.c helper.c
              mount_util.c modules/subdir.c fuse_log.c)

if(${CMAKE_SYSTEM_NAME} MATCHES "BSD")
  target_sources(fuse3 PUBLIC mount_bsd.c)
else()
  target_sources(fuse3 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/mount.c)
endif()

if(HAVE_ICONV)
  target_sources(fuse3 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/modules/iconv.c)
endif()

target_include_directories(fuse3 PUBLIC ${INCLUDE_DIRS})

target_link_libraries(fuse3 ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})

if(${CMAKE_SYSTEM_NAME} MATCHES "netbsd")
   # Totally unsure about netbsd, included for consistency - but commented
   # find_package(perfuse)
   # if (PERFUSE_FOUND)
   #    target_link_libraries(fuse3 PERFUSE_LIBS)
   # endif()
   # find_package(puffs)
   # if (PUFFS_FOUND)
   #    target_link_libraries(fuse3 PUFFS_LIBS)
   # endif()
else()
   # Required for clock_gettime before glibc 2.17
   find_library (RT_LIBRARIES rt
      PATHS /usr/local/lib /usr/lib /lib ${CMAKE_EXTRA_LIBRARIES}
   )
   if(RT_LIBRARIES)
      target_link_libraries(fuse3 ${RT_LIBRARIES})
   endif()
endif()

set(BINDIR "bindir" CACHE STRING "mount path subdirectory default: [bindir]")
set(FUSERMOUNT_DIR "${CMAKE_INSTALL_PREFIX}/${BINDIR}" CACHE STRING "The mount path (not exactly sure what this is)" )

target_compile_definitions(fuse3 PUBLIC FUSE_USE_VERSION=35
                                        FUSERMOUNT_DIR=\"${FUSERMOUNT_DIR}\"
                                        PACKAGE_VERSION=\"${CMAKE_PROJECT_VERSION}\")
# Should be changed to target_link_options (requires 3.13.X)
set (CMAKE_SHARED_LINKER_FLAGS "-Wl,--version-script,${CMAKE_CURRENT_SOURCE_DIR}/fuse_versionscript")
#target_compile_options(fuse3 PUBLIC -Wl,--version-script,${CMAKE_CURRENT_SOURCE_DIR}/fuse_versionscript)
