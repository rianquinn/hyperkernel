/*
 * Bareflank Hyperkernel
 * Copyright (C) 2018 Assured Information Security, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef HYPERKERNEL_BFDRIVERINTERFACE_H
#define HYPERKERNEL_BFDRIVERINTERFACE_H

#include <bftypes.h>
#include <bfdebugringinterface.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Common                                                                     */
/* -------------------------------------------------------------------------- */

#ifndef HKD_NAME
#define HKD_NAME "hkd"
#endif

#ifndef HKD_MAGIC
#define HKD_MAGIC 0xBF
#endif

#ifndef HKD_DEVICETYPE
#define HKD_DEVICETYPE 0xBEEF
#endif

#define IOCTL_MMAP_CMD 0x801
#define IOCTL_MUNMAP_CMD 0x802

/**
 * struct hkd_mmap
 *
 * @addr[out] the address of the mapping
 *
 * @size[in] the number of bytes to map
 * @prot[in] prot mask (see mmap(2))
 * @flags[in] flags (see mmap(2))
 */
struct hkd_mmap {
    void *addr;
    int size;
    int prot;
    int flags;
};

/* -------------------------------------------------------------------------- */
/* Linux Interfaces                                                           */
/* -------------------------------------------------------------------------- */

#ifdef __linux__

#define IOCTL_MMAP _IOWR(HKD_MAGIC, IOCTL_MMAP_CMD, struct hkd_mmap)
#define IOCTL_MUNMAP _IOW(HKD_MAGIC, IOCTL_MUNMAP_CMD, struct hkd_mmap)

#endif

/* -------------------------------------------------------------------------- */
/* Windows Interfaces                                                         */
/* -------------------------------------------------------------------------- */

#if defined(_WIN32) || defined(__CYGWIN__)

#include <initguid.h>

DEFINE_GUID(
    GUID_DEVINTERFACE_bareflank,
    0x1d9c9218,
    0x3c88,
    0x4b81,
    0x8e,
    0x81,
    0xb4,
    0x62,
    0x2a,
    0x4d,
    0xcb,
    0x44);

#define IOCTL_ADD_MODULE CTL_CODE(BAREFLANK_DEVICETYPE, IOCTL_ADD_MODULE_CMD, METHOD_IN_DIRECT, FILE_WRITE_DATA)
#define IOCTL_LOAD_VMM CTL_CODE(BAREFLANK_DEVICETYPE, IOCTL_LOAD_VMM_CMD, METHOD_BUFFERED, 0)
#define IOCTL_UNLOAD_VMM CTL_CODE(BAREFLANK_DEVICETYPE, IOCTL_UNLOAD_VMM_CMD, METHOD_BUFFERED, 0)
#define IOCTL_START_VMM CTL_CODE(BAREFLANK_DEVICETYPE, IOCTL_START_VMM_CMD, METHOD_BUFFERED, 0)
#define IOCTL_STOP_VMM CTL_CODE(BAREFLANK_DEVICETYPE, IOCTL_STOP_VMM_CMD, METHOD_BUFFERED, 0)
#define IOCTL_DUMP_VMM CTL_CODE(BAREFLANK_DEVICETYPE, IOCTL_DUMP_VMM_CMD, METHOD_OUT_DIRECT, FILE_READ_DATA)
#define IOCTL_VMM_STATUS CTL_CODE(BAREFLANK_DEVICETYPE, IOCTL_VMM_STATUS_CMD, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_SET_VCPUID CTL_CODE(BAREFLANK_DEVICETYPE, IOCTL_SET_VCPUID_CMD, METHOD_IN_DIRECT, FILE_WRITE_DATA)

#endif

#ifdef __cplusplus
}
#endif

#endif
