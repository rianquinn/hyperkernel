/**
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

#ifndef BFEXEC_ELF_NOTE_H
#define BFEXEC_ELF_NOTE_H

#include <stdint.h>
#include <bfelf_loader.h>

#pragma pack(push, 1)
#ifdef __cplusplus
extern "C" {
#endif

/**
 * struct xen_elf_note
 *
 * Structure representing Xen ELF notes created by Linux. Even though
 * the 64-bit spec calls for 8-byte words, Linux uses 4 bytes.
 */
struct xen_elf_note {
    uint32_t namesz;
    uint32_t descsz;
    uint32_t type;
    uint8_t name[4];
    uint8_t *desc;
} __attribute__((packed));

/**
 * is_xen_elf_note
 *
 * @param buf the address of the memory to check
 * @return true iff the memory beginning at buf refers to a valid Xen note.
 */
inline int is_xen_elf_note(const char *buf)
{
    const struct xen_elf_note *note = (const struct xen_elf_note *)buf;
    if (note->namesz != 4) {
        return 0;
    }
    return strncmp(note->name, "Xen", 4) == 0;
}

inline void print_xen_elf_note(const struct xen_elf_note *note)
{
    const char *desc = (const char *)&note->desc;
    printf("Xen elfnote: \n");

    switch (note->type) {
        case XEN_ELFNOTE_GUEST_OS:
            printf("Guest OS: %s\n", desc);
            break;
        case XEN_ELFNOTE_GUEST_VERSION:
            printf("Guest version: %s\n", desc);
            break;
        case XEN_ELFNOTE_XEN_VERSION:
            printf("Xen version: %s\n", desc);
            break;
        case XEN_ELFNOTE_FEATURES:
            printf("Features: %s\n", desc);
            break;
        case XEN_ELFNOTE_PAE_MODE:
            printf("PAE mode: %s\n", desc);
            break;
        case XEN_ELFNOTE_LOADER:
            printf("Loader: %s\n", desc);
            break;
        case XEN_ELFNOTE_VIRT_BASE:
            printf("Virt base: 0x%" PRIx64 "\n", *(uint64_t *)desc);
            break;
        case XEN_ELFNOTE_INIT_P2M:
            printf("Init p2m: 0x%" PRIx64 "\n", *(uint64_t *)desc);
            break;
        case XEN_ELFNOTE_HYPERCALL_PAGE:
            printf("Hypercall page: 0x%" PRIx64 "\n", *(uint64_t *)desc);
            break;
        case XEN_ELFNOTE_HV_START_LOW:
            printf("HV start low: 0x%" PRIx64 "\n", *(uint64_t *)desc);
            break;
        case XEN_ELFNOTE_PADDR_OFFSET:
            printf("Paddr offset: 0x%" PRIx64 "\n", *(uint64_t *)desc);
            break;
        case XEN_ELFNOTE_SUPPORTED_FEATURES:
            printf("Supported features: 0x%" PRIx32 "\n", *(uint32_t *)desc);
            break;
        case XEN_ELFNOTE_SUSPEND_CANCEL:
            printf("Suspend cancel: 0x%" PRIx32 "\n", *(uint32_t *)desc);
            break;
        case XEN_ELFNOTE_MOD_START_PFN:
            printf("Mod start pfn: 0x%" PRIx32 "\n", *(uint32_t *)desc);
            break;
        case XEN_ELFNOTE_PHYS32_ENTRY:
            printf("PHYS32 entry: 0x%" PRIx32 "\n", *(uint32_t *)desc);
            break;
        default:
            printf("Unknown type: %d\n", note->type);
    }

    printf("\n");
}


#ifdef __cplusplus
}
#endif
#endif
