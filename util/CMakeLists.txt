# CMake equivalent of libfuse's meson.build
# Every attempt has been made to match all the functionality provided by meson
# Use at your own risk

cmake_minimum_required (VERSION 3.12.0)
set (CMAKE_VERBOSE_MAKEFILE FALSE)

include(GNUInstallDirs)

set(MESON_SOURCE_ROOT ${CMAKE_PROJECT_SOURCE_DIR})
set(FUSECONF_PATH ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SYSCONFDIR}/fuse.conf)

#executable('fusermount3', ['fusermount.c', '../lib/mount_util.c'],
#           include_directories: include_dirs,
#           install: true,
#           install_dir: get_option('bindir'),
#           c_args: '-DFUSE_CONF="@0@"'.format(fuseconf_path))
add_executable(fusermount3 fusermount.c ../lib/mount_util.c)

target_include_directories(fusermount3
                           PUBLIC ${INCLUDE_DIRS})
target_compile_definitions(fusermount3
                           PUBLIC FUSE_CONF=\"${FUSECONF_PATH}\")
install(TARGETS fusermount3 RUNTIME
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ)

#executable('mount.fuse3', ['mount.fuse.c'],
#           include_directories: include_dirs,
#           link_with: [ libfuse ],
#           install: true,
#           install_dir: get_option('sbindir'),
#           c_args: '-DFUSE_USE_VERSION=34')

add_executable(mount.fuse3 mount.fuse.c )

target_include_directories(mount.fuse3
                           PUBLIC ${INCLUDE_DIRS})
target_link_libraries(mount.fuse3 fuse3)

target_compile_definitions(mount.fuse3
						   PUBLIC FUSE_USE_VERSION=35)
install(TARGETS mount.fuse3 RUNTIME
        DESTINATION ${CMAKE_INSTALL_SBINDIR})


#udevrulesdir = get_option('udevrulesdir')
#if udevrulesdir == ''
#  udev = dependency('udev')
#  udevrulesdir = join_paths(udev.get_pkgconfig_variable('udevdir'), 'rules.d')
#endif
option(UDEV_RULES_DIR
       "Target directory for udev rule installation. Ensure you have permissions to write to this directory."
       "/etc/udev/rules.d"
)

#
#meson.add_install_script('install_helper.sh',
#                         join_paths(get_option('prefix'), get_option('sysconfdir')),
#                         join_paths(get_option('prefix'), get_option('bindir')),
#                         udevrulesdir)
install(CODE "execute_process(COMMAND MESON_SOURCE_ROOT=${MESON_SOURCE_ROOT} ${CMAKE_CURRENT_SOURCE_DIR}/install_helper.sh
                             ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SYSCONFDIR}
                             ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}
                             ${UDEV_RULES_DIR})"
)
