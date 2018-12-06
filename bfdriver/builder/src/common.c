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
#include <bfhypercall.h>

#include <common.h>

/* -------------------------------------------------------------------------- */
/* VM State Info                                                              */
/* -------------------------------------------------------------------------- */

struct vm_t {
    struct crt_info_t crt_info;
    struct bfelf_loader_t bfelf_loader;
    struct bfelf_binary_t bfelf_binary;

    void *entry;
    uint64_t domainid;

    int used;
};

#define MAX_VMS 0x1000
struct vm_t g_vms[MAX_VMS] = {0};

// /* -------------------------------------------------------------------------- */
// /* Global                                                                     */
// /* -------------------------------------------------------------------------- */

// uint64_t g_ram_addr = 0x1000000;
// uint64_t g_ram_size = 0;

// /* -------------------------------------------------------------------------- */
// /* Domain Functions                                                           */
// /* -------------------------------------------------------------------------- */

// status_t
// domain_op__map_gpa(uint64_t gva, uint64_t gpa, uint64_t type)
// {
//     status_t ret;

//     ret = __domain_op__map_gpa(g_vm.domainid, gva, gpa, type);
//     if (ret != SUCCESS) {
//         BFALERT("__domain_op__map_gpa failed\n");
//         return FAILURE;
//     }

//     return SUCCESS;
// }

// status_t
// domain_op__map_gpa_single_gva(
//     uint64_t gva, uint64_t gpa, uint64_t size, uint64_t type)
// {
//     uint64_t index;

//     for (index = 0; index < size; index += 0x1000) {
//         status_t ret = domain_op__map_gpa(
//             gva, gpa + index, type
//         );

//         if (ret != SUCCESS) {
//             BFALERT("map_mem failed\n");
//             return FAILURE;
//         }
//     }

//     return SUCCESS;
// }


// status_t
// domain_op__map_buffer(
//     uint64_t gva, uint64_t gpa, uint64_t size, uint64_t type)
// {
//     uint64_t index;

//     for (index = 0; index < size; index += 0x1000) {
//         status_t ret = domain_op__map_gpa(
//             gva + index, gpa + index, type
//         );

//         if (ret != SUCCESS) {
//             BFALERT("map_mem failed\n");
//             return FAILURE;
//         }
//     }

//     return SUCCESS;
// }

// /* -------------------------------------------------------------------------- */
// /* E820 Map                                                                   */
// /* -------------------------------------------------------------------------- */

// status_t
// setup_e820_map()
// {
//     status_t ret;

//     ret = __domain_op__add_e820_entry(
//         g_vm.domainid,
//         0,
//         0x1000,
//         XEN_HVM_MEMMAP_TYPE_UNUSABLE
//     );

//     if (ret != SUCCESS) {
//         BFALERT("__domain_op__add_e820_entry failed\n");
//         return FAILURE;
//     }

//     ret = __domain_op__add_e820_entry(
//         g_vm.domainid,
//         0x1000,
//         0x5000,
//         XEN_HVM_MEMMAP_TYPE_RESERVED
//     );

//     if (ret != SUCCESS) {
//         BFALERT("__domain_op__add_e820_entry failed\n");
//         return FAILURE;
//     }

//     ret = __domain_op__add_e820_entry(
//         g_vm.domainid,
//         0x6000,
//         0x1000,
//         XEN_HVM_MEMMAP_TYPE_RAM
//     );

//     if (ret != SUCCESS) {
//         BFALERT("__domain_op__add_e820_entry failed\n");
//         return FAILURE;
//     }

//     ret = __domain_op__add_e820_entry(
//         g_vm.domainid,
//         0x7000,
//         0x1000,
//         XEN_HVM_MEMMAP_TYPE_RAM
//     );

//     if (ret != SUCCESS) {
//         BFALERT("__domain_op__add_e820_entry failed\n");
//         return FAILURE;
//     }

//     ret = __domain_op__add_e820_entry(
//         g_vm.domainid,
//         0x8000,
//         0x1000,
//         XEN_HVM_MEMMAP_TYPE_RAM
//     );

//     if (ret != SUCCESS) {
//         BFALERT("__domain_op__add_e820_entry failed\n");
//         return FAILURE;
//     }

//     // ret = __domain_op__add_e820_entry(
//     //     g_vm.domainid,
//     //     0x9000,
//     //     0x1000,
//     //     XEN_HVM_MEMMAP_TYPE_RAM
//     // );

//     // if (ret != SUCCESS) {
//     //     BFALERT("__domain_op__add_e820_entry failed\n");
//     //     return FAILURE;
//     // }

//     ret = __domain_op__add_e820_entry(
//         g_vm.domainid,
//         0xA000,
//         REAL_MODE_SIZE,
//         XEN_HVM_MEMMAP_TYPE_RAM
//     );

//     if (ret != SUCCESS) {
//         BFALERT("__domain_op__add_e820_entry failed\n");
//         return FAILURE;
//     }

//     ret = __domain_op__add_e820_entry(
//         g_vm.domainid,
//         0xA000 + REAL_MODE_SIZE,
//         g_ram_addr - (0xA000 + REAL_MODE_SIZE),
//         XEN_HVM_MEMMAP_TYPE_UNUSABLE
//     );

//     if (ret != SUCCESS) {
//         BFALERT("__domain_op__add_e820_entry failed\n");
//         return FAILURE;
//     }

//     ret = __domain_op__add_e820_entry(
//         g_vm.domainid,
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

//     ret = __vcpu_op__set_rbx(g_vm.vcpuid, 0x4000);
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

// /* -------------------------------------------------------------------------- */
// /* Helpers                                                                    */
// /* -------------------------------------------------------------------------- */

// status_t
// binary_load(void)
// {
//     status_t ret;
//     uint64_t gva;

//     /**
//      * NOTE:
//      *
//      * For PIE, we need to provide an address (g_ram_addr). This will be
//      * overwritten if the binary is non-PIE (i.e. static), which is why we
//      * have to get the start address again after we call bfelf_load
//      *
//      * NOTE:
//      *
//      * This is where we allocate RAM. We let the ELF loader allocate RAM for
//      * us, and fill in the first part of RAM with the ELF file. The ELF
//      * loader will ensure RAM is zero'd out, and will ensure the RAM is page
//      * aligned, which is needed for mapping.
//     */

//     g_vm.bfelf_binary.exec_size = g_ram_size;
//     g_vm.bfelf_binary.start_addr = (void *)g_ram_addr;

//     ret = bfelf_load(&g_vm.bfelf_binary, 1, &g_vm.entry, &g_vm.crt_info, &g_vm.bfelf_loader);
//     if (ret != BF_SUCCESS) {
//         BFALERT("bfelf_load: 0x%016" PRIx64 "\n", ret);
//         return FAILURE;
//     }

//     gva = (uint64_t)g_vm.bfelf_binary.exec;
//     g_ram_addr = (uint64_t)g_vm.bfelf_binary.start_addr;

//     ret = domain_op__map_buffer(gva, g_ram_addr, g_ram_size, MAP_RWE);
//     if (ret != SUCCESS) {
//         BFALERT("bfelf_load: 0x%016" PRIx64 "\n", ret);
//         return FAILURE;
//     }

//     return SUCCESS;
// }

/* -------------------------------------------------------------------------- */
/* Implementation                                                             */
/* -------------------------------------------------------------------------- */

int64_t
common_create_from_elf(const struct create_from_elf_args *args)
{
    int i;
    struct vm_t *vm;

    if (_cpuid_eax(0xBF00) != 0xBF01) {
        return HYPERVISOR_NOT_LOADED;
    }

    for (i = 0; i < MAX_VMS; i++) {
        vm = &g_vms[i];
        if (vm->used == 0) {
            break;
        }
    }

    if (i == MAX_VMS) {
        BFALERT("MAX_VMS reached. No more VMs can be created\n");
        return CREATE_FROM_ELF_FAILED;
    }

    platform_memset(vm, 0, sizeof(struct vm_t));

    vm->domainid = __domain_op__create_domain();
    if (vm->domainid == INVALID_DOMAINID) {
        BFALERT("__domain_op__create_domain failed\n");
        return CREATE_FROM_ELF_FAILED;
    }

    // g_vm.bfelf_binary.file = data;
    // g_vm.bfelf_binary.file_size = size;

    vm->used = 1;
    return BF_SUCCESS;
}

int64_t
common_destroy(domainid_t domainid)
{
    int i;
    status_t ret;

    for (i = 0; i < MAX_VMS; i++) {
        vm = &g_vms[i];
        if (vm->used == 1 && vm->domainid == domainid) {
            break;
        }
    }

    if (i == MAX_VMS) {
        BFALERT("MAX_VMS reached. Unable to locate VM\n");
        return CREATE_FROM_ELF_FAILED;
    }

    ret = __domain_op__destroy_domain(domainid);
    if (ret != SUCCESS) {
        BFALERT("__domain_op__destroy_domain failed\n");
        return FAILURE;
    }

    return BF_SUCCESS;
}
