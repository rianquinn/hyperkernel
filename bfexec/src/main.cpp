//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#include <args.hxx>

#include <list>
#include <string>
#include <memory>
#include <iostream>

#include <bfgsl.h>
#include <ioctl.h>

auto ctl = std::make_unique<ioctl>();
//auto default_cmdline = console=uart,io,0x3F8,115200n8 init=/hello

static int
protected_main(int argc, const char *argv[])
{
    args::ArgumentParser parser("executes a virtual machine");
    args::HelpFlag help(parser, "help", "Display this help menu", {'h', "help"});

    args::Group elf(parser, "Loading ELF files:");
    args::Flag elf_enable(elf, "", "Create a VM using an ELF file", {"elf"});
    args::ValueFlag<std::string> elf_path(elf, "path", "The path to the ELF file to use", {"path"});
    args::ValueFlag<uint64_t> elf_ram_size(elf, "bytes", "Total size of RAM in bytes", {"ram"});
    args::ValueFlag<uint64_t> elf_uart(elf, "port #", "The port # to connect a UART to", {"uart"});
    args::ValueFlag<std::string> elf_init(elf, "path", "The init process to start", {"init"});

    try {
        parser.ParseCLI(argc, argv);
    }
    catch (args::Help) {
        std::cout << parser;
        return EXIT_SUCCESS;
    }
    catch (args::ParseError e) {
        std::cerr << e.what() << std::endl;
        std::cerr << parser;
        return EXIT_FAILURE;
    }
    catch (args::ValidationError e) {
        std::cerr << e.what() << std::endl;
        std::cerr << parser;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int
main(int argc, const char *argv[])
{
    try {
        return protected_main(argc, argv);
    }
    catch (const std::exception &e) {
        std::cerr << "Caught unhandled exception:" << '\n';
        std::cerr << "    - what(): " << e.what() << '\n';
    }
    catch (...) {
        std::cerr << "Caught unknown exception" << '\n';
    }

    return EXIT_FAILURE;
}
