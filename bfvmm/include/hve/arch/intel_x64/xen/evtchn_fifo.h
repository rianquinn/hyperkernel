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

struct evtchn_fifo_queue {
    uint32_t *head;
    uint32_t tail;
    uint8_t priority;
    std::mutex lock;
};

class EXPORT_HYPERKERNEL_HVE evtchn_fifo
{
public:

    /// A "port" is the address of an event word
    using port_t = evtchn_port_t;
    using word_t = std::atomic<event_word_t>;
    using chan_t = class evtchn;
    using queue_t = struct evtchn_fifo_queue;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu of the evtchn_fifo
    ///
    evtchn_fifo(gsl::not_null<vcpu *> vcpu);

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

    static constexpr auto max_nr_channels = EVTCHN_FIFO_NR_CHANNELS;
    static constexpr auto event_words_per_page = ::x64::pt::page_size / sizeof(word_t);
    static constexpr auto max_event_words_pages = max_nr_channels / event_words_per_page;

    // Each evtchn must be aligned to evtchn_size for this to be right
    static constexpr auto evtchns_per_page = ::x64::pt::page_size / evtchn_size;
    static constexpr auto max_event_chans_pages = max_nr_channels / evtchns_per_page;

    void setup_control_block();
    void map_control_block(uint64_t gfn, uint32_t offset);

    word_t *word_from_port(port_t port);
    event_word_t read_event_word(port_t port);
    void write_event_word(port_t port, event_word_t val);

    uint64_t nr_channels() const;
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
    std::atomic<uint64_t> m_valid_channels;

    evtchn_fifo_control_block_t *m_ctl_blk{};
    eapis::x64::unique_map<uint8_t> m_ctl_blk_ump{};
    std::array<queue_t, EVTCHN_FIFO_MAX_QUEUES> m_queues{};

    std::vector<page_ptr<word_t>> m_event_words{};
    std::vector<page_ptr<chan_t>> m_event_chans{};

    vcpu *m_vcpu;

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
