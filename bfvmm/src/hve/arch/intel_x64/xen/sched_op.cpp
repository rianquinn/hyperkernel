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
#include <hve/arch/intel_x64/xen/sched_op.h>

#include <eapis/hve/arch/intel_x64/time.h>

using pet_handler_t =
    eapis::intel_x64::vmx_preemption_timer_handler::handler_delegate_t;

namespace hyperkernel::intel_x64
{

// This handler is registered with the parent vcpu, so @param vcpu is the
// parent of the PVH guest. The PVH guest is taken off the parent's schedule
// queue and run each time a PET exit occurs.
//
// The current scheme implies (time flows down):
// .
// child run()
// .
// .
// child SCHEDOP_yield, enqueue child, arm parent's PET, parent run()
// .
// .
// PET exit, dequeue child, child run()
// .
// .
//
// So for now, we are assuming the child will behave and call SCHEDOP_yield
// in a timely manner

static bool
handle_pet_exit(gsl::not_null<vcpu_t *> vcpu)
{
    auto parent = vcpu_cast(vcpu);
    parent->schedule_dequeue();
    parent->disable_vmx_preemption_timer();

    auto child = parent->schedule_next();
    child->load();
    child->run();

    return true;
}

sched_op::sched_op(gsl::not_null<vcpu *> vcpu, uint64_t tsc_freq_kHz)
:
    m_vcpu{vcpu},
    m_tsc_freq_kHz{tsc_freq_kHz}
{
    using namespace ::intel_x64::msrs;

    const auto ms_per_time_slice = 100; // arbitrary
    const auto div = ia32_vmx_misc::preemption_timer_decrement::get();

    m_pet_freq_kHz = tsc_freq_kHz >> div;
    m_ticks_per_slice = m_pet_freq_kHz * ms_per_time_slice;

    auto parent = vcpu->parent_vcpu();

    parent->add_vmx_preemption_timer_handler(
        pet_handler_t::create<handle_pet_exit>()
    );
}

// NOTE: Haven't been able to test this yet.
void
sched_op::handle_yield(gsl::not_null<vcpu *> vcpu)
{
//    auto parent = vcpu->parent_vcpu();
//
//    parent->load();
//    parent->schedule_enqueue(vcpu);
//    parent->set_vmx_preemption_timer(m_ticks_per_slice);
//    parent->enable_vmx_preemption_timer();
//    parent->run();
}

}
