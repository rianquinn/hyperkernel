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

#include <iostream>

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/vmcall/bf86_op.h>

namespace hyperkernel::intel_x64
{

vmcall_bf86_op_handler::vmcall_bf86_op_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_vmcall_handler(
        vmcall_handler_delegate(vmcall_bf86_op_handler, dispatch)
    );
}

void
vmcall_bf86_op_handler::bf86_op__emulate_outb(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        std::cout << gsl::narrow_cast<char>(vcpu->rcx());
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_bf86_op_handler::bf86_op__emulate_hlt(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto parent_vcpu = vcpu->parent_vcpu();

        parent_vcpu->load();
        parent_vcpu->return_success();
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

bool
vmcall_bf86_op_handler::dispatch(
    gsl::not_null<vcpu_t *> vcpu)
{
    if (vcpu->rax() != __enum_bf86_op) {
        return false;
    }

    switch(vcpu->rbx()) {
        case __enum_bf86_op__emulate_outb:
            this->bf86_op__emulate_outb(m_vcpu);
            return true;

        case __enum_bf86_op__emulate_hlt:
            this->bf86_op__emulate_hlt(m_vcpu);
            return true;

        default:
            break;
    };

    throw std::runtime_error("unknown bf86 opcode");
}

}
