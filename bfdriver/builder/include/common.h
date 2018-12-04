/*
 * Bareflank Hypervisor
 * Copyright (C) 2015 Assured Information Security, Inc.
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

#ifndef COMMON_H
#define COMMON_H

#include <bftypes.h>
#include <bferrorcodes.h>
#include <bfelf_loader.h>
#include <bfdebugringinterface.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Build ELF
 *
 * The following function builds a guest VM based on a provided ELF file.
 * To accomplish this, the following function will allocate RAM, load RAM
 * with the contents of the provided ELF file, and then set up the guest's
 * memory map.
 *
 * @param file the file to add to memory
 * @param fsize the size of the file in bytes
 * @param rsize the size of RAM in bytes
 * @return BF_SUCCESS on success, negative error code on failure
 */
int64_t
common_build_elf(const char *file, uint64_t fsize, uint64_t rsize);

#ifdef __cplusplus
}
#endif

#endif
