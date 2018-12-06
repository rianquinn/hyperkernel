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
#include <bfbuilderinterface.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HYPERVISOR_NOT_LOADED bfscast(status_t, 0x8000000000000001)
#define CREATE_FROM_ELF_FAILED bfscast(status_t, 0x8000000000000002)
#define DESTROY_FAILED bfscast(status_t, 0x8000000000000002)

struct vm_t {
    struct crt_info_t crt_info;
    struct bfelf_loader_t bfelf_loader;
    struct bfelf_binary_t bfelf_binary;

    void *entry;
    uint64_t domainid;

    int used;
};

/**
 * Create VM from ELF
 *
 * The following function builds a guest VM based on a provided ELF file.
 * To accomplish this, the following function will allocate RAM, load RAM
 * with the contents of the provided ELF file, and then set up the guest's
 * memory map.
 *
 * Note that this function takes a VM object. This object will be cleared
 * by this function so it should point to a VM object that is currently
 * not being used by another VM (i.e. unsused).
 *
 * @param vm the vm_t object associated with the vm
 * @param args the create_from_elf_args arguments needed to create the VM
 * @return BF_SUCCESS on success, negative error code on failure
 */
int64_t
common_create_from_elf(struct vm_t *vm, struct create_from_elf_args *args);

/**
 * Destroy VM
 *
 * This function will destory a VM by telling the hypervisor to remove all
 * internal resources associated with the VM.
 *
 * @param vm the vm_t object associated with the vm
 * @return BF_SUCCESS on success, negative error code on failure
 */
int64_t
common_destroy(struct vm_t *vm);

#ifdef __cplusplus
}
#endif

#endif
