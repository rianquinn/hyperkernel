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

#include <bfgsl.h>
#include <args.hxx>

#include <list>
#include <string>
#include <memory>
#include <iostream>

#include <ioctl.h>
#include <builderinterface.h>

#include <hve/arch/intel_x64/xen/public/xen.h>
#include <hve/arch/intel_x64/xen/public/elfnote.h>

auto ctl = std::make_unique<ioctl>();

args::ArgumentParser args_parser("executes a virtual machine");
args::HelpFlag args_help(args_parser, "help", "Display this help menu", {'h', "help"});

args::Group args_elf(args_parser, "Loading ELF files:");
args::Flag args_elf_enable(args_elf, "", "Create a VM using an ELF file", {"elf"});
args::ValueFlag<std::string> args_elf_path(args_elf, "path", "The path to the ELF file to use", {"path"});
args::ValueFlag<uint64_t> args_elf_ram_size(args_elf, "bytes", "Total size of RAM in bytes", {"ram"});
args::ValueFlag<uint64_t> args_elf_uart(args_elf, "port #", "The port # to connect a UART to", {"uart"});
args::ValueFlag<std::string> args_elf_init(args_elf, "path", "The init process to start", {"init"});
args::ValueFlag<uint64_t> args_elf_domainid(args_elf, "domainid", "The domainid to attach to", {"domaind"});

static int
build_elf()
{
    std::string cmdline;
    struct load_elf_args args{};

    if (!args_elf_path || args::get(args_elf_path).empty()) {
        throw std::runtime_error("Must specify --path");
    }

    std::ifstream stream(args::get(args_elf_path), std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Unable to open ELF file");
    }

    std::vector<uint8_t> file(std::istreambuf_iterator<uint8_t>(stream), {});
    uint64_t domainid = DOMID_INVALID;
    uint64_t ram_size = file.length() * 2;

    if (!elf_enable) {
    }

    args.file = file.data();
    args.file_length = file.length();
    args.cmdline = cmdline.data();
    args.cmdline_length = cmdline.length();
    args.domainid = domainid;
    args.ram_size = ram_size;

    ctl.call_ioctl_load_elf(args);
}


//auto default_cmdline = console=uart,io,0x3F8,115200n8 init=/hello

static int
protected_main(int argc, const char *argv[])
{
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

    if (!elf_enable) {
        throw std::runtime_error("Must specify --elf");
    }

    return build_elf();
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
