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

#ifndef EVTCHN_FIFO_INTEL_X64_HYPERKERNEL_H
#define EVTCHN_FIFO_INTEL_X64_HYPERKERNEL_H

#include <atomic>
#include <mutex>

#include "../base.h"
#include "public/event_channel.h"
#include "evtchn.h"
#include "xen_op.h"

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

namespace hyperkernel::intel_x64
{

class vcpu;
class xen_op_handler;

struct evtchn_fifo_queue {
    uint32_t *head;
    uint32_t tail;
    uint8_t priority;
    std::mutex lock;
};

class EXPORT_HYPERKERNEL_HVE evtchn_fifo
{
public:

    /// A "port" is the address of an event word and
    /// the address of an evtchn
    using port_t = evtchn_port_t;
    using word_t = std::atomic<event_word_t>;
    using chan_t = class evtchn;
    using queue_t = struct evtchn_fifo_queue;
    using bucket_t = page_ptr<chan_t>;

    static_assert(is_power_of_two(sizeof(word_t)));
    static_assert(is_power_of_two(sizeof(chan_t)));
    static_assert(is_power_of_two(sizeof(bucket_t)));

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu of the evtchn_fifo
    ///
    evtchn_fifo(
        gsl::not_null<vcpu *> vcpu,
        gsl::not_null<xen_op_handler *> handler
    );

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~evtchn_fifo() = default;

    /// Init control
    ///
    void init_control(gsl::not_null<evtchn_init_control_t *> ctl);

    /// Send
    ///
    void send(gsl::not_null<evtchn_send_t *> send);

private:

    // Static members
    //
    // We distinguish between channel capacity and the
    // current channel size in exactly the same way std::vector does.
    //
    static constexpr auto bits_per_xen_ulong = sizeof(xen_ulong_t) * 8;
    static constexpr auto chan_capacity = EVTCHN_FIFO_NR_CHANNELS;
    static constexpr auto word_per_page = ::x64::pt::page_size / sizeof(word_t);
    static constexpr auto event_word_capacity = chan_capacity / word_per_page;

    // Each evtchn must be aligned to evtchn_size for this to be right
    static constexpr auto bucket_per_group = ::x64::pt::page_size / sizeof(bucket_t);
    static constexpr auto chan_per_bucket = ::x64::pt::page_size / evtchn_size;
    static constexpr auto chan_per_group = chan_per_bucket * bucket_per_group;
    static constexpr auto event_group_capacity = chan_capacity / chan_per_group;

    // Member functions
    void make_bucket();

    void setup_ports();
    void setup_control_block();
    void map_control_block(uint64_t gfn, uint32_t offset);

    chan_t *port_to_chan(port_t port);
    word_t *port_to_word(port_t port);

    event_word_t read_event_word(port_t port);
    void write_event_word(port_t port, event_word_t val);

    bool port_is_valid(port_t port) const;

    bool is_pending(word_t word) const;
    bool is_masked(word_t word) const;
    bool is_linked(word_t word) const;
    bool is_busy(word_t word) const;

    void set_pending(word_t word);
    void set_masked(word_t word);
    void set_linked(word_t word);
    void set_busy(word_t word);

    void clear_pending(word_t word);
    void clear_masked(word_t word);
    void clear_linked(word_t word);
    void clear_busy(word_t word);

    // Data members
    std::atomic<uint64_t> m_valid_channels{};

    evtchn_fifo_control_block_t *m_ctl_blk{};
    eapis::x64::unique_map<uint8_t> m_ctl_blk_ump{};
    std::array<queue_t, EVTCHN_FIFO_MAX_QUEUES> m_queues{};

    std::vector<page_ptr<word_t>> m_event_word{};
    std::vector<page_ptr<chan_t>> m_event_group{};

    vcpu *m_vcpu;
    xen_op_handler *m_xen_handler;

public:

    /// @cond

    evtchn_fifo(evtchn_fifo &&) = default;
    evtchn_fifo &operator=(evtchn_fifo &&) = default;

    evtchn_fifo(const evtchn_fifo &) = delete;
    evtchn_fifo &operator=(const evtchn_fifo &) = delete;

    /// @endcond
};

}

#endif
