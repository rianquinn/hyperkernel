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

#include <intrinsics.h>

#include <hve/arch/intel_x64/lapic.h>
#include <hve/arch/intel_x64/fault.h>

//--------------------------------------------------------------------------
// Implementation
//--------------------------------------------------------------------------

namespace hyperkernel::intel_x64
{

namespace lapic_n = ::eapis::intel_x64::lapic;

lapic::lapic(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu},
    m_lapic_page{make_page<uint32_t>()},
    m_lapic_view{m_lapic_page.get(), 0x1000 / 4}
{ }

void
lapic::init()
{
    auto hpa = g_mm->virtptr_to_physint(m_lapic_page.get());
    m_vcpu->map_4k_ro(this->base(), hpa);

    this->write(lapic_n::id::indx, lapic_n::id::reset_val);
    this->write(lapic_n::version::indx, lapic_n::version::reset_val);
    this->write(lapic_n::dfr::indx, lapic_n::dfr::reset_val);

    this->write(lapic_n::lvt::cmci::indx, lapic_n::lvt::reset_val);
    this->write(lapic_n::lvt::timer::indx, lapic_n::lvt::reset_val);
    this->write(lapic_n::lvt::lint0::indx, lapic_n::lvt::reset_val);
    this->write(lapic_n::lvt::lint1::indx, lapic_n::lvt::reset_val);
    this->write(lapic_n::lvt::error::indx, lapic_n::lvt::reset_val);

    this->write(lapic_n::svr::indx, lapic_n::svr::reset_val);
}

}
