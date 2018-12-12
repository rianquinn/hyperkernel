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

#ifndef BUILDERINTERFACE_H
#define BUILDERINTERFACE_H

#include <bftypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Common                                                                     */
/* -------------------------------------------------------------------------- */

#ifndef BUILDER_NAME
#define BUILDER_NAME "bareflank_builder"
#endif

#ifndef BUILDER_MAJOR
#define BUILDER_MAJOR 151
#endif

#ifndef BUILDER_DEVICETYPE
#define BUILDER_DEVICETYPE 0xF00D
#endif

#define IOCTL_LOAD_ELF_CMD 0x801

/**
 * @struct load_elf_args
 *
 * This structure is used to load and ELF file as a guest VM. This is the
 * information the builder needs to create a domain and load its resources
 * prior to execution.
 *
 * @var load_elf_args::file
 *     the ELF file to load
 * @var load_elf_args::file_size
 *     the length of the ELF file to load
 * @var load_elf_args::cmdline
 *     the command line arguments to pass to the Linux kernel on boot
 * @var load_elf_args::cmdline_length
 *     the length of the command line arguments
 * @var load_elf_args::domainid
 *     the domain ID of the VM to create and load
 * @var load_elf_args::ram_size
 *     the amount of RAM to give to the domain
 */
struct load_elf_args {
    const char *file;
    uint64_t file_length;

    const char *cmdline;
    uint64_t cmdline_length;

    uint64_t domainid;
    uint64_t ram_size;
};

/* -------------------------------------------------------------------------- */
/* Linux Interfaces                                                           */
/* -------------------------------------------------------------------------- */

#ifdef __linux__

#define IOCTL_LOAD_ELF _IOW(BUILDER_MAJOR, IOCTL_LOAD_ELF_CMD, struct load_elf_args *)

#endif

/* -------------------------------------------------------------------------- */
/* Windows Interfaces                                                         */
/* -------------------------------------------------------------------------- */

#if defined(_WIN32) || defined(__CYGWIN__)

#include <initguid.h>

DEFINE_GUID(
    GUID_DEVINTERFACE_builder,
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

#define IOCTL_LOAD_ELF CTL_CODE(BUILDER_DEVICETYPE, IOCTL_LOAD_ELF_CMD, METHOD_IN_DIRECT, FILE_WRITE_DATA)

#endif

#ifdef __cplusplus
}
#endif

#endif
