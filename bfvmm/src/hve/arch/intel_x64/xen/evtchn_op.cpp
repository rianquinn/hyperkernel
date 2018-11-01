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

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/xen/evtchn_op.h>

// =============================================================================
// Implementation
// =============================================================================

namespace hyperkernel::intel_x64
{

evtchn_op_handler::evtchn_op_handler(gsl::not_null<vcpu *> vcpu)
:
    m_vcpu{vcpu}
{ }

void
evtchn_op_handler::init_control(gsl::not_null<evtchn_init_control_t *> ctl)
{
    // TODO: We probably should bring down the whole system due to invalid
    // guest arguments. Xen returns error codes like -EINVAL in rax
    bfdebug_nhex(0, "ctl->vcpu", ctl->vcpu);
    bfdebug_nhex(0, "m_vcpu->id", m_vcpu->id());
//    expects(ctl->vcpu == m_vcpu->id()); the guest passes 0x10
    expects(ctl->offset <= (4096 - sizeof(evtchn_fifo_control_block_t)));
    expects((ctl->offset & 0x7) == 0);

    ctl->link_bits = EVTCHN_FIFO_LINK_BITS;

    this->setup_control_block();
    this->map_control_block(ctl->control_gfn, ctl->offset);

    // set fifo port ops
    // setup ports
    //   -- struct evtchn
    //   -- port_is_valid
    //   -- evtchn_from_port
    //   -- is_bit_set shared_info
    //   -- set priority
}

void
evtchn_op_handler::setup_control_block()
{
    for (auto i = 0; i <= EVTCHN_FIFO_PRIORITY_MIN; i++) {
        m_queue[i].priority = i;
    }
}

void
evtchn_op_handler::map_control_block(uint64_t gfn, uint32_t offset)
{
    m_control_block_ump = m_vcpu->map_gpa_4k<uint8_t>(gfn << ::x64::pt::page_shift);
    if (!m_control_block_ump) {
        throw std::runtime_error("map_gpa_4k failed");
    }

    uint8_t *base = m_control_block_ump.get() + offset;
    m_control_block = reinterpret_cast<evtchn_fifo_control_block_t *>(base);

    for (auto i = 0; i <= EVTCHN_FIFO_PRIORITY_MIN; i++) {
        m_queue[i].head = &m_control_block->head[i];
    }
}

//TODO: do we really need this?
//bool
//evtchn_op_handler::port_is_valid(evtchn_port_t p)
//{
//    if (p >= m_max_evtchns) {
//        return 0;
//    }
//
//    //
//    // Looking at xen/xen/inclue/asm-x86/atomic.h, I'm not
//    // sure how read_atomic is any different from a normal read. Maybe
//    // I'm missing a macro?
//    //
////  return p < read_atomic(&d->valid_evtchns);
//    return p < m_valid_evtchns;
//}

}
