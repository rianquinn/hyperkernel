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
#include <hve/arch/intel_x64/vmcall/domain_op.h>

namespace hyperkernel::intel_x64
{

vmcall_domain_op_handler::vmcall_domain_op_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_vmcall_handler(
        vmcall_handler_delegate(vmcall_domain_op_handler, dispatch)
    );
}

void
vmcall_domain_op_handler::domain_op__create_domain(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        vcpu->set_rax(domain::generate_domainid());
        g_dm->create(vcpu->rax(), nullptr);
    }
    catchall({
        vcpu->set_rax(INVALID_DOMAINID);
    })
}

void
vmcall_domain_op_handler::domain_op__donate_gpa(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto args =
            vcpu->map_arg<__domain_op__donate_gpa_arg_t>(vcpu->rcx());

        auto [hpa, unused] =
            vcpu->gpa_to_hpa(args->gpa);

        switch(args->type) {
            case MAP_RO:
                get_domain(args->domainid)->map_4k_ro(
                    args->domain_gpa, hpa
                );
                break;

            case MAP_RW:
                get_domain(args->domainid)->map_4k_rw(
                    args->domain_gpa, hpa
                );
                break;

            case MAP_RWE:
                get_domain(args->domainid)->map_4k_rwe(
                    args->domain_gpa, hpa
                );
                break;

            default:
                throw std::runtime_error("unknown map type");
        }

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_domain_op_handler::domain_op__add_e820_entry(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto args =
            vcpu->map_arg<__domain_op__add_e820_entry_arg_t>(vcpu->rcx());

        get_domain(args->domainid)->add_e820_entry({
            args->addr, args->size, args->type
        });

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_domain_op_handler::domain_op__destroy_domain(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        g_dm->destroy(vcpu->rcx(), nullptr);
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

bool
vmcall_domain_op_handler::dispatch(
    gsl::not_null<vcpu *> vcpu)
{
    if (vcpu->rax() != __enum_domain_op) {
        return false;
    }

    switch(vcpu->rbx()) {
        case __enum_domain_op__create_domain:
            this->domain_op__create_domain(vcpu);
            return true;

        case __enum_domain_op__donate_gpa:
            this->domain_op__donate_gpa(vcpu);
            return true;

        case __enum_domain_op__add_e820_entry:
            this->domain_op__add_e820_entry(vcpu);
            return true;

        case __enum_domain_op__destroy_domain:
            this->domain_op__destroy_domain(vcpu);
            return true;

        default:
            break;
    };

    throw std::runtime_error("unknown domain opcode");
}

}
