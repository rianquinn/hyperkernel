#
# Bareflank Hyperkernel
# Copyright (C) 2018 Assured Information Security, Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

# ------------------------------------------------------------------------------
# HKD Driver
# ------------------------------------------------------------------------------

if(WIN32)
    return()
endif()

file(TO_NATIVE_PATH "${SOURCE_ROOT_DIR}" SOURCE_ROOT_DIR_NATIVE)

add_custom_target_category("Hyperkernel Driver")

add_custom_target(hkd_build
    COMMAND ${HK_SOURCE_UTIL_DIR}/driver_build.sh ${HK_SOURCE_ROOT_DIR} ${SOURCE_ROOT_DIR_NATIVE}
    USES_TERMINAL
)
add_custom_target_info(
    TARGET hkd_build
    COMMENT "Build the hyperkernel driver"
)

add_custom_target(hkd_clean
    COMMAND ${HK_SOURCE_UTIL_DIR}/driver_clean.sh ${HK_SOURCE_ROOT_DIR} ${SOURCE_ROOT_DIR_NATIVE}
    USES_TERMINAL
)
add_custom_target_info(
    TARGET hkd_clean
    COMMENT "Clean the hyperkernel driver"
)

add_custom_target(hkd_load
    COMMAND ${HK_SOURCE_UTIL_DIR}/driver_load.sh ${HK_SOURCE_ROOT_DIR}  ${SOURCE_ROOT_DIR_NATIVE}
    USES_TERMINAL
)
add_custom_target_info(
    TARGET hkd_load
    COMMENT "Load the hyperkernel driver"
)

add_custom_target(hkd_unload
    COMMAND ${HK_SOURCE_UTIL_DIR}/driver_unload.sh ${HK_SOURCE_ROOT_DIR} ${SOURCE_ROOT_DIR_NATIVE}
    USES_TERMINAL
)
add_custom_target_info(
    TARGET hkd_unload
    COMMENT "Unload the hyperkernel driver"
)

add_custom_target(
    hkd_quick
    COMMAND ${CMAKE_COMMAND} --build . --target hkd_unload
    COMMAND ${CMAKE_COMMAND} --build . --target hkd_clean
    COMMAND ${CMAKE_COMMAND} --build . --target hkd_build
    COMMAND ${CMAKE_COMMAND} --build . --target hkd_load
    USES_TERMINAL
)
add_custom_target_info(
    TARGET hkd_quick
    COMMENT "Unload, clean, build, and load the Bareflank driver"
)

# add_dependencies(driver_build hkd_build)
# add_dependencies(driver_clean hkd_clean)
# add_dependencies(driver_load hkd_load)
# add_dependencies(driver_unload hkd_unload)
# add_dependencies(driver_quick hkd_quick)
