//
// Bareflank Extended APIs
// Copyright (C) 2018 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

/**
 *       0x0 +----------------------+ ---
 *           | Unusable             |  | Unusable
 *    0x1000 +----------------------+ ---
 *           | Initial GDT          |  |
 *    0x2000 +----------------------+  |
 *           | Initial IDT          |  |
 *    0x3000 +----------------------+  |
 *           | Initial TSS          |  | Reserved
 *    0x4000 +----------------------+  |
 *           | Xen Start Info       |  |
 *    0x5000 +----------------------+  |
 *           | Xen CMD Line         |  |
 *    0x6000 +----------------------+ ---
 *           | Xen shared Info Page |  | RAM
 *    0x7000 +----------------------+ ---
 *           | Unusable             |  | Unusable
 *   0xE0000 +----------------------+ ---
 *           | ACPI                 |  | Reserved
 *   0xF0000 +----------------------+ ---
 *           | Local APIC           |  | Reserved
 *  0x100000 +----------------------+ ---
 *           | Unusable             |  | Unusable
 * 0x1000000 +----------------------+ ---
 *           | Linux ELF (Xen PVH)  |  |
 *       XXX +----------------------+  | RAM
 *           | Usable RAM           |  |
 * 0x9000000 +----------------------+ ---
 */

#ifndef GPA_LAYOUT_H
#define GPA_LAYOUT_H

#define CONSOLE_GPA         0x07000
#define STORE_GPA           0x08000

#define ACPI_RSDP_GPA       0xE0000
#define ACPI_XSDT_GPA       0xE1000
#define ACPI_MADT_GPA       0xE2000
#define ACPI_FADT_GPA       0xE3000
#define ACPI_DSDT_GPA       0xE4000

#define LAPIC_GPA           0xFEE00000
#define IOAPIC_GPA          0xFEC00000

#define START_ADDR          ((void *)0x1000000)

#endif
