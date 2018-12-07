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

#include <bfdebug.h>
#include <bfgpalayout.h>
#include <bfhypercall.h>

#include <common.h>

/* -------------------------------------------------------------------------- */
/* Donate Functions                                                           */
/* -------------------------------------------------------------------------- */

status_t
donate_buffer(
    domainid_t domainid, uint64_t gva, uint64_t domain_gpa, uint64_t size, uint64_t type)
{
    uint64_t i;

    for (i = 0; i < size; i += 0x1000) {
        status_t ret = 0;
        uint64_t gpa = (uint64_t)platform_virt_to_phys((void *)(gva + i));

        ret = __domain_op__donate_gpa(domainid, gpa, domain_gpa + i, type);
        if (ret != SUCCESS) {
            BFALERT("donate_buffer: __domain_op__donate_gpa failed\n");
            return FAILURE;
        }
    }

    return SUCCESS;
}

status_t
donate_single_gpa_to_buffer(
    domainid_t domainid, uint64_t gva, uint64_t domain_gpa, uint64_t size)
{
    uint64_t i;
    uint64_t gpa = (uint64_t)platform_virt_to_phys((void *)gva);

    for (i = 0; i < size; i += 0x1000) {
        status_t ret = 0;

        ret = __domain_op__donate_gpa(domainid, gpa, domain_gpa + i, MAP_RO);
        if (ret != SUCCESS) {
            BFALERT("donate_single_gpa_to_buffer: __domain_op__donate_gpa failed\n");
            return FAILURE;
        }
    }

    return SUCCESS;
}

// /* -------------------------------------------------------------------------- */
// /* E820 Map                                                                   */
// /* -------------------------------------------------------------------------- */

// status_t
// setup_e820_map()
// {
//     status_t ret;

//     ret = __domain_op__add_e820_entry(
//         vm->domainid,
//         0,
//         0x1000,
//         XEN_HVM_MEMMAP_TYPE_UNUSABLE
//     );

//     if (ret != SUCCESS) {
//         BFALERT("__domain_op__add_e820_entry failed\n");
//         return FAILURE;
//     }

//     ret = __domain_op__add_e820_entry(
//         vm->domainid,
//         0x1000,
//         0x5000,
//         XEN_HVM_MEMMAP_TYPE_RESERVED
//     );

//     if (ret != SUCCESS) {
//         BFALERT("__domain_op__add_e820_entry failed\n");
//         return FAILURE;
//     }

//     ret = __domain_op__add_e820_entry(
//         vm->domainid,
//         0x6000,
//         0x1000,
//         XEN_HVM_MEMMAP_TYPE_RAM
//     );

//     if (ret != SUCCESS) {
//         BFALERT("__domain_op__add_e820_entry failed\n");
//         return FAILURE;
//     }

//     ret = __domain_op__add_e820_entry(
//         vm->domainid,
//         0x7000,
//         0x1000,
//         XEN_HVM_MEMMAP_TYPE_RAM
//     );

//     if (ret != SUCCESS) {
//         BFALERT("__domain_op__add_e820_entry failed\n");
//         return FAILURE;
//     }

//     ret = __domain_op__add_e820_entry(
//         vm->domainid,
//         0x8000,
//         0x1000,
//         XEN_HVM_MEMMAP_TYPE_RAM
//     );

//     if (ret != SUCCESS) {
//         BFALERT("__domain_op__add_e820_entry failed\n");
//         return FAILURE;
//     }

//     // ret = __domain_op__add_e820_entry(
//     //     vm->domainid,
//     //     0x9000,
//     //     0x1000,
//     //     XEN_HVM_MEMMAP_TYPE_RAM
//     // );

//     // if (ret != SUCCESS) {
//     //     BFALERT("__domain_op__add_e820_entry failed\n");
//     //     return FAILURE;
//     // }

//     ret = __domain_op__add_e820_entry(
//         vm->domainid,
//         0xA000,
//         REAL_MODE_SIZE,
//         XEN_HVM_MEMMAP_TYPE_RAM
//     );

//     if (ret != SUCCESS) {
//         BFALERT("__domain_op__add_e820_entry failed\n");
//         return FAILURE;
//     }

//     ret = __domain_op__add_e820_entry(
//         vm->domainid,
//         0xA000 + REAL_MODE_SIZE,
//         g_ram_addr - (0xA000 + REAL_MODE_SIZE),
//         XEN_HVM_MEMMAP_TYPE_UNUSABLE
//     );

//     if (ret != SUCCESS) {
//         BFALERT("__domain_op__add_e820_entry failed\n");
//         return FAILURE;
//     }

//     ret = __domain_op__add_e820_entry(
//         vm->domainid,
//         g_ram_addr,
//         g_ram_size,
//         XEN_HVM_MEMMAP_TYPE_RAM
//     );

//     if (ret != SUCCESS) {
//         BFALERT("__domain_op__add_e820_entry failed\n");
//         return FAILURE;
//     }

//     return SUCCESS;
// }

// /* -------------------------------------------------------------------------- */
// /* Helpers                                                                    */
// /* -------------------------------------------------------------------------- */

// status_t
// setup_xen_start_info()
// {
//     status_t ret;

//     g_reserved_4000 = (reserved_4000_t *)alloc_page();
//     if (g_reserved_4000 == 0) {
//         BFALERT("g_reserved_4000 alloc failed: %s\n", strerror(errno));
//         return FAILURE;
//     }

//     g_reserved_4000->start_info.magic = XEN_HVM_START_MAGIC_VALUE;
//     g_reserved_4000->start_info.version = 0;
//     g_reserved_4000->start_info.cmdline_paddr = 0x5000;
//     g_reserved_4000->start_info.rsdp_paddr = ACPI_RSDP_GPA;

//     ret = domain_op__map_gpa((uint64_t)g_reserved_4000, 0x4000, MAP_RO);
//     if (ret != BF_SUCCESS) {
//         BFALERT("__domain_op__map_gpa failed\n");
//         return FAILURE;
//     }

//     ret = __vcpu_op__set_rbx(vm->vcpuid, 0x4000);
//     if (ret != SUCCESS) {
//         BFALERT("__vcpu_op__set_rbx failed\n");
//         return FAILURE;
//     }

//     return SUCCESS;
// }

// status_t
// setup_xen_cmdline()
// {
//     status_t ret;
//     const char *cmdline = "console=uart,io,0x3F8,115200n8 init=/hello";

//     /**
//      * TODO:
//      * - We need to use a "--" similar to gdb to get the command line options
//      * from the user so that they can be added here
//      */

//     g_reserved_5000 = (reserved_5000_t *)alloc_page();
//     if (g_reserved_5000 == 0) {
//         BFALERT("g_reserved_5000 alloc failed: %s\n", strerror(errno));
//         return FAILURE;
//     }

//     ret = domain_op__map_gpa((uint64_t)g_reserved_5000, 0x5000, MAP_RO);
//     if (ret != BF_SUCCESS) {
//         BFALERT("__domain_op__map_gpa failed\n");
//         return FAILURE;
//     }

//     strncpy(g_reserved_5000->cmdline, cmdline, 0x1000);
//     return SUCCESS;
// }

// status_t
// setup_xen_shared_info_page()
// {
//     status_t ret;

//     g_reserved_6000 = (reserved_6000_t *)alloc_page();
//     if (g_reserved_6000 == 0) {
//         BFALERT("g_reserved_6000 alloc failed: %s\n", strerror(errno));
//         return FAILURE;
//     }

//     memset((char *)g_reserved_6000, 0, 0x1000);
//     ret = domain_op__map_gpa((uint64_t)g_reserved_6000, 0x6000, MAP_RW);
//     if (ret != BF_SUCCESS) {
//         BFALERT("__domain_op__map_gpa failed\n");
//         return FAILURE;
//     }

//     return SUCCESS;
// }

// status_t
// setup_xen_console()
// {
//     status_t ret;

//     g_reserved_7000 = (reserved_7000_t *)alloc_page();
//     if (g_reserved_7000 == 0) {
//         BFALERT("g_reserved_7000 alloc failed: %s\n", strerror(errno));
//         return FAILURE;
//     }

//     ret = domain_op__map_gpa((uint64_t)g_reserved_7000, 0x7000, MAP_RW);
//     if (ret != BF_SUCCESS) {
//         BFALERT("__domain_op__map_gpa failed\n");
//         return FAILURE;
//     }

//     return SUCCESS;
// }

// status_t
// setup_xen_store()
// {
//     status_t ret;

//     g_reserved_8000 = (reserved_8000_t *)alloc_page();
//     if (g_reserved_8000 == 0) {
//         BFALERT("g_reserved_8000 alloc failed: %s\n", strerror(errno));
//         return FAILURE;
//     }

//     ret = domain_op__map_gpa((uint64_t)g_reserved_8000, 0x8000, MAP_RW);
//     if (ret != BF_SUCCESS) {
//         BFALERT("__domain_op__map_gpa failed\n");
//         return FAILURE;
//     }

//     return SUCCESS;
// }

// status_t
// setup_rm_trampoline()
// {
//     status_t ret;
//     uint32_t size = REAL_MODE_SIZE;

//     g_reserved_A000 = (reserved_A000_t *)alloc_buffer(size);
//     if (g_reserved_A000 == 0) {
//         BFALERT("g_reserved_A000 alloc failed: %s\n", strerror(errno));
//         return FAILURE;
//     }

//     ret = domain_op__map_buffer((uint64_t)g_reserved_A000, 0xA000, size, MAP_RWE);
//     if (ret != BF_SUCCESS) {
//         BFALERT("__domain_op__map_buffer failed\n");
//         return FAILURE;
//     }

//     return SUCCESS;
// }

// status_t
// setup_xen_disabled()
// {
//     status_t ret;

//     /**
//      * Note:
//      *
//      * The following disables specific portions of memory by mapping them to
//      * a zero page. Specifically, the guest might attempt to access these
//      * pages expecting to find something, which they will not. If we don't map
//      * these, the guest will attempt to access them anyways and crash from an
//      * EPT violation
//      */

//     g_zero_page = alloc_page();
//     if (g_zero_page == 0) {
//         BFALERT("g_zero_page alloc failed: %s\n", strerror(errno));
//         return FAILURE;
//     }

//     /* Zero Page */
//     ret = domain_op__map_gpa_single_gva((uint64_t)g_zero_page, 0x0, 0x1000, MAP_RO);
//     if (ret != BF_SUCCESS) {
//         BFALERT("domain_op__map_gpa_single_gva failed\n");
//         return FAILURE;
//     }

//     /* Disable DMI */
//     ret = domain_op__map_gpa_single_gva((uint64_t)g_zero_page, 0xF0000, 0x10000, MAP_RO);
//     if (ret != BF_SUCCESS) {
//         BFALERT("domain_op__map_gpa_single_gva failed\n");
//         return FAILURE;
//     }

//     /* Disable Video BIOS region */
//     ret = domain_op__map_gpa_single_gva((uint64_t)g_zero_page, 0xC0000, 0x10000, MAP_RO);
//     if (ret != BF_SUCCESS) {
//         BFALERT("domain_op__map_gpa_single_gva failed\n");
//         return FAILURE;
//     }

//     /* ROMs */
//     ret = domain_op__map_gpa_single_gva((uint64_t)g_zero_page, 0xD0000, 0x10000, MAP_RO);
//     if (ret != BF_SUCCESS) {
//         BFALERT("domain_op__map_gpa_single_gva failed\n");
//         return FAILURE;
//     }

//     /* ROMs */
//     ret = domain_op__map_gpa_single_gva((uint64_t)g_zero_page, 0xE4000, 0x10000 - 0x4000, MAP_RO);
//     if (ret != BF_SUCCESS) {
//         BFALERT("domain_op__map_gpa_single_gva failed\n");
//         return FAILURE;
//     }

//     // TODO:
//     //
//     // To support MP, we will have to remove the following and provide an
//     // actual MP table that mimics the ACPI tables as both are required.
//     //
//     // https://elixir.bootlin.com/linux/v3.7/source/arch/x86/kernel/mpparse.c#L604
//     //

//     /* MP Table */
//     ret = domain_op__map_gpa_single_gva((uint64_t)g_zero_page, 0x9F000, 0x1000, MAP_RO);
//     if (ret != BF_SUCCESS) {
//         BFALERT("domain_op__map_gpa_single_gva failed\n");
//         return FAILURE;
//     }

//     return SUCCESS;
// }

/* -------------------------------------------------------------------------- */
/* Implementation                                                             */
/* -------------------------------------------------------------------------- */

int64_t
common_create_from_elf(
    struct vm_t *vm, struct create_from_elf_args *args)
{
    status_t ret;
    uint64_t gva, gpa;

    if (_cpuid_eax(0xBF00) != 0xBF01) {
        return HYPERVISOR_NOT_LOADED;
    }

    vm->domainid = __domain_op__create_domain();
    if (vm->domainid == INVALID_DOMAINID) {
        BFALERT("__domain_op__create_domain failed\n");
        return CREATE_FROM_ELF_FAILED;
    }

    vm->bfelf_binary.file = args->file;
    vm->bfelf_binary.file_size = args->file_size;
    vm->bfelf_binary.exec = 0;
    vm->bfelf_binary.exec_size = args->size;
    vm->bfelf_binary.start_addr = START_ADDR;

    ret = bfelf_load(
        &vm->bfelf_binary, 1, &vm->entry, &vm->crt_info, &vm->bfelf_loader);
    if (ret != BF_SUCCESS) {
        return ret;
    }

    gva = (uint64_t)vm->bfelf_binary.exec;
    gpa = (uint64_t)START_ADDR;

    ret = donate_buffer(vm->domainid, gva, gpa, args->size, MAP_RWE);
    if (ret != SUCCESS) {
        return ret;
    }

    args->domainid = vm->domainid;
    return BF_SUCCESS;
}

int64_t
common_destroy(struct vm_t *vm)
{
    status_t ret;

    ret = __domain_op__destroy_domain(vm->domainid);
    if (ret != SUCCESS) {
        BFALERT("__domain_op__destroy_domain failed\n");
        return FAILURE;
    }

    return BF_SUCCESS;
}
