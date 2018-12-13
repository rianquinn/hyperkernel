//
// Bareflank Hyperkernel
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

#ifndef VERBOSE_H
#define VERBOSE_H

#define create_elf_vm_verbose()                                                                                                             \
    if (verbose) {                                                                                                                          \
        std::cout << '\n';                                                                                                                  \
        std::cout << bfcolor_cyan    "Created VM from ELF file:\n" bfcolor_end;                                                             \
        std::cout << bfcolor_magenta "--------------------------------------------------------------------------------\n" bfcolor_end;      \
        std::cout << "      path" bfcolor_yellow " | " << bfcolor_green << file.path() << bfcolor_end "\n";                                 \
        std::cout << " domain id" bfcolor_yellow " | " << bfcolor_green << ioctl_args.domainid << bfcolor_end "\n";                         \
        std::cout << "  ram size" bfcolor_yellow " | " << bfcolor_green << (size / 0x1000000) << "MB" << bfcolor_end "\n";                  \
        std::cout << "   cmdline" bfcolor_yellow " | " << bfcolor_green << cmdl.data() << bfcolor_end "\n";                                 \
    }

#define attach_to_vm_verbose()                                                                                                              \
    if (verbose) {                                                                                                                          \
        std::cout << '\n';                                                                                                                  \
        std::cout << bfcolor_cyan    "Attaching to VM:\n" bfcolor_end;                                                                      \
        std::cout << bfcolor_magenta "--------------------------------------------------------------------------------\n" bfcolor_end;      \
        std::cout << " domain id" bfcolor_yellow " | " << bfcolor_green << g_domainid << bfcolor_end "\n";                                  \
        std::cout << '\n';                                                                                                                  \
    }

#define output_vm_uart_verbose()                                                                                                            \
    if (verbose) {                                                                                                                          \
        std::cout << '\n';                                                                                                                  \
        std::cout << bfcolor_cyan    "Output from VM's UART:\n" bfcolor_end;                                                                \
        std::cout << bfcolor_magenta "--------------------------------------------------------------------------------\n" bfcolor_end;      \
        std::cout << '\n';                                                                                                                  \
                                                                                                                                            \
        u = std::thread(uart_thread);                                                                                                       \
    }

#endif
