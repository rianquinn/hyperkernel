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
#include <bfdebug.h>
#include <bfstring.h>
#include <bfaffinity.h>
#include <bfbuilderinterface.h>

#include <list>
#include <memory>
#include <fstream>
#include <iostream>

#include <args.h>
#include <cmdl.h>
#include <file.h>
#include <ioctl.h>

#include <hve/arch/intel_x64/xen/public/xen.h>
#include <hve/arch/intel_x64/xen/public/elfnote.h>

auto ctl = std::make_unique<ioctl>();

static int
attach_to_vm(const args_type &args)
{
    bfignored(args);
    throw std::runtime_error("not supported yet!!!");
}

static int
create_elf_vm(const args_type &args)
{
    struct create_from_elf_args ioctl_args{};

    if (!args.count("path")) {
        throw cxxopts::OptionException("must specify --path");
    }

    bfn::cmdl cmdl;
    bfn::file file(args["path"].as<std::string>());

    uint64_t size = file.size() * 2;
    if (args.count("size")) {
        size = args["size"].as<uint64_t>();
    }

    uint64_t uart = 0;
    if (args.count("uart")) {
        uart = args["uart"].as<uint64_t>();
        cmdl.add(
            "console=uart,io," + bfn::to_string(uart, 16) + ",115200n8"
        );
    }

    if (args.count("init")) {
        cmdl.add("init=" + args["init"].as<std::string>());
    }

    ioctl_args.file = file.data();
    ioctl_args.file_size = file.size();
    ioctl_args.cmdl = cmdl.data();
    ioctl_args.cmdl_size = cmdl.size();
    ioctl_args.uart = uart;
    ioctl_args.size = size;

    if (verbose) {
        std::cout << bfcolor_magenta "-------------------------\n" bfcolor_end;
        std::cout << bfcolor_blue    "Creating VM from ELF file\n" bfcolor_end;
        std::cout << bfcolor_magenta "-------------------------\n" bfcolor_end;
        std::cout << "path: " << bfcolor_green << file.path() << bfcolor_end "\n";
        std::cout << "size: " << bfcolor_green << size << bfcolor_end "\n";
        std::cout << "cmdl: " << bfcolor_green << cmdl.data() << bfcolor_end "\n";
    }

    ctl->call_ioctl_create_from_elf(ioctl_args);
    ctl->call_ioctl_destroy(ioctl_args.domainid);

    return EXIT_SUCCESS;
}

static int
protected_main(const args_type &args)
{
    if (args.count("attach")) {
        return attach_to_vm(args);
    }

    if (args.count("elf")) {
        return create_elf_vm(args);
    }

    throw cxxopts::OptionException(
        "must specify --elf or --attach");
}

int
main(int argc, char *argv[])
{
    set_affinity(0);

    try {
        args_type args = parse_args(argc, argv);
        return protected_main(args);
    }
    catch (const cxxopts::OptionException &e) {
        std::cerr << "invalid arguments: " << e.what() << '\n';
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
