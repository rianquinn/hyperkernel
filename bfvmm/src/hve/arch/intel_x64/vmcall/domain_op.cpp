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
vmcall_domain_op_handler::domain_op__map_gpa(
    gsl::not_null<vcpu *> vcpu)
{
        auto domain_op__map_gpa_arg =
            vcpu->map_arg<__domain_op__map_gpa_arg_t>(vcpu->rcx());

    try {
        //auto domain_op__map_gpa_arg =
        //    vcpu->map_arg<__domain_op__map_gpa_arg_t>(vcpu->rcx());

        auto [hpa, unused] =
            vcpu->gva_to_hpa(domain_op__map_gpa_arg->gva);

        switch(domain_op__map_gpa_arg->type) {
            case MAP_RO:
                get_domain(domain_op__map_gpa_arg->domainid)->map_4k_ro(
                    domain_op__map_gpa_arg->gpa, hpa
                );
                break;

            case MAP_RW:
                get_domain(domain_op__map_gpa_arg->domainid)->map_4k_rw(
                    domain_op__map_gpa_arg->gpa, hpa
                );
                break;

            case MAP_RWE:
                get_domain(domain_op__map_gpa_arg->domainid)->map_4k_rwe(
                    domain_op__map_gpa_arg->gpa, hpa
                );
                break;

            default:
                throw std::runtime_error("unknown map type");
        }

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        bfdebug_nhex(0, "map_gpa: gva", domain_op__map_gpa_arg->gva);
        bfdebug_nhex(0, "map_gpa: gpa", domain_op__map_gpa_arg->gpa);

        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_domain_op_handler::domain_op__add_e820_entry(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto domain_op__add_e820_entry_arg =
            vcpu->map_arg<__domain_op__add_e820_entry_arg_t>(vcpu->rcx());

        get_domain(domain_op__add_e820_entry_arg->domainid)->add_e820_entry({
            domain_op__add_e820_entry_arg->addr,
            domain_op__add_e820_entry_arg->size,
            domain_op__add_e820_entry_arg->type
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
    gsl::not_null<vcpu_t *> vcpu)
{
    if (vcpu->rax() != __enum_domain_op) {
        return false;
    }

    switch(vcpu->rbx()) {
        case __enum_domain_op__create_domain:
            this->domain_op__create_domain(m_vcpu);
            return true;

        case __enum_domain_op__map_gpa:
            this->domain_op__map_gpa(m_vcpu);
            return true;

        case __enum_domain_op__add_e820_entry:
            this->domain_op__add_e820_entry(m_vcpu);
            return true;

        case __enum_domain_op__destroy_domain:
            this->domain_op__destroy_domain(m_vcpu);
            return true;

        default:
            break;
    };

    throw std::runtime_error("unknown domain opcode");
}

}
