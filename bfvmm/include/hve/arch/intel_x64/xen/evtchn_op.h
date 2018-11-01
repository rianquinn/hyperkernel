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

#ifndef EVTCHNOP_INTEL_X64_HYPERKERNEL_H
#define EVTCHNOP_INTEL_X64_HYPERKERNEL_H

#include "../base.h"
#include "public/event_channel.h"

#include <eapis/hve/arch/x64/unmapper.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_HYPERKERNEL_HVE
#ifdef SHARED_HYPERKERNEL_HVE
#define EXPORT_HYPERKERNEL_HVE EXPORT_SYM
#else
#define EXPORT_HYPERKERNEL_HVE IMPORT_SYM
#endif
#else
#define EXPORT_HYPERKERNEL_HVE
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

namespace hyperkernel::intel_x64
{

class vcpu;

struct evtchn_fifo_queue {
    uint32_t *head;
    uint32_t tail;
    uint8_t priority;
    // std::mutex lock;
};

constexpr auto event_words_per_page =  PAGE_SIZE / sizeof(event_word_t);
constexpr auto max_event_array_pages = EVTCHN_FIFO_NR_CHANNELS / event_words_per_page;

class EXPORT_HYPERKERNEL_HVE evtchn_op_handler
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu of the evtchn_op_handler
    ///
    evtchn_op_handler(gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~evtchn_op_handler() = default;

    /// Init control
    ///
    /// @param[in,out] ctl the address of argument to EVTCHNOP_init_control
    ///
    void init_control(gsl::not_null<evtchn_init_control_t *> ctl);

private:

    void setup_control_block();
    void map_control_block(uint64_t gfn, uint32_t offset);
//    bool port_is_valid(evtchn_port_t p);

    // evtchn_fifo_vcpu
    std::array<struct evtchn_fifo_queue, EVTCHN_FIFO_MAX_QUEUES> m_queue{};
    eapis::x64::unique_map<uint8_t> m_control_block_ump{};
    evtchn_fifo_control_block_t *m_control_block{};

    // evtchn_fifo_domain
    std::array<event_word_t *, max_event_array_pages> m_event_array{};
    unsigned int m_num_evtchns{};
    unsigned int m_max_evtchns{EVTCHN_FIFO_NR_CHANNELS};
    unsigned int m_valid_evtchns{}; // number of allocated evtchns

    vcpu *m_vcpu;

public:

    /// @cond

    evtchn_op_handler(evtchn_op_handler &&) = default;
    evtchn_op_handler &operator=(evtchn_op_handler &&) = default;

    evtchn_op_handler(const evtchn_op_handler &) = delete;
    evtchn_op_handler &operator=(const evtchn_op_handler &) = delete;

    /// @endcond
};

}

#endif
