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

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/uart.h>

#include <iostream>

//--------------------------------------------------------------------------
// Implementation
//--------------------------------------------------------------------------

#define make_delegate(a,b)                                                                          \
    eapis::intel_x64::a::handler_delegate_t::create<uart, &uart::b>(this)

#define EMULATE_IO_INSTRUCTION(a,b,c)                                                               \
    m_vcpu->emulate_io_instruction(                                                                 \
        a, make_delegate(io_instruction_handler, b), make_delegate(io_instruction_handler, c))

namespace hyperkernel::intel_x64
{

uart::uart(
    gsl::not_null<vcpu *> vcpu, port_type port
) :
    m_vcpu{vcpu},
    m_port{port}
{
    EMULATE_IO_INSTRUCTION(port + 0, io_zero_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(port + 1, io_zero_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(port + 2, io_zero_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(port + 3, io_zero_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(port + 4, io_zero_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(port + 5, io_zero_handler, io_ignore_handler);
}

void
uart::enable()
{
    EMULATE_IO_INSTRUCTION(port + 0, reg0_in_handler, reg0_out_handler);
    EMULATE_IO_INSTRUCTION(port + 1, reg1_in_handler, reg1_out_handler);
    EMULATE_IO_INSTRUCTION(port + 2, reg2_in_handler, reg2_out_handler);
    EMULATE_IO_INSTRUCTION(port + 3, reg3_in_handler, reg3_out_handler);
    EMULATE_IO_INSTRUCTION(port + 4, reg4_in_handler, reg4_out_handler);
    EMULATE_IO_INSTRUCTION(port + 5, reg5_in_handler, reg5_out_handler);
}

bool
uart::io_zero_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0x0;
    return true;
}

bool
uart::io_ignore_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
uart::reg0_in_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    if (this->dlab()) {
        info.val = m_baud_rate_l;
    }
    else {
        info.val = 0x0;
    }

    return true;
}

bool
uart::reg1_in_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    if (this->dlab()) {
        info.val = m_baud_rate_h;
    }
    else {
        info.val = 0x0;
        bfwarning(0, "interrupt enable register read not supported");
    }

    return true;
}

bool
uart::reg2_in_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0x0;
    return true;
}

bool
uart::reg3_in_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_line_control_register;
    return true;
}

bool
uart::reg4_in_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0x0;
    return true;
}

bool
uart::reg5_in_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0x60;
    return true;
}

bool
uart::reg0_out_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    if (this->dlab()) {
        m_baud_rate_l = info.val;
    }
    else {
        std::cout << info.val;
    }

    return true;
}

bool
uart::reg1_out_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    if (this->dlab()) {
        m_baud_rate_h = info.val;
    }

    return true;
}

bool
uart::reg2_out_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
uart::reg3_out_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    m_line_control_register = info.val;
    return true;
}

bool
uart::reg4_out_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
uart::reg5_out_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

}
