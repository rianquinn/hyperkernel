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

#ifndef EVENT_INTEL_X64_HYPERKERNEL_H
#define EVENT_INTEL_X64_HYPERKERNEL_H

#include "../base.h"

#include "public/xen.h"
#include "public/event_channel.h"

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

namespace hyperkernel::intel_x64
{

// -----------------------------------------------------------------------------
// Event types and functions
//
// For reference, see:
//     xen/include/public/event_channel.h
//     xen/include/xen/event_fifo.h (in the xen tree)
//
// Note that xen's public/event_channel.h defines structs in the form
// 'struct evtchn_fifo_*' and constants in the form 'EVTCHN_FIFO*'.
//
// The form of Bareflank-specific structs and constants is the same as the xen
// ones, but with 'struct event_*' and 'event*' prefixes.
//
// -----------------------------------------------------------------------------

class vcpu;

using event_word_t = uint32_t;
using event_port_t = uint32_t;
using event_channel_t = class event_channel;

inline bool event_is_pending(const event_word_t *word)
{ return is_bit_set(*word, EVTCHN_FIFO_PENDING); }

inline bool event_is_masked(const event_word_t *word)
{ return is_bit_set(*word, EVTCHN_FIFO_MASKED); }

inline bool event_is_linked(const event_word_t *word)
{ return is_bit_set(*word, EVTCHN_FIFO_LINKED); }

inline bool event_is_busy(const event_word_t *word)
{ return is_bit_set(*word, EVTCHN_FIFO_BUSY); }

class EXPORT_HYPERKERNEL_HVE event_channel
{
public:

    enum state : { free, reserved, unbound, interdomain, pirq, virq, ipi };

    //TODO: std::mutex m_lock;
    //TODO: uint8_t m_xen_consumer:XEN_CONSUMER_BITS;
    //TODO: union {
    //    struct {
    //        domid_t remote_domid;
    //    } unbound;     /* state == ECS_UNBOUND */
    //    struct {
    //        evtchn_port_t  remote_port;
    //        struct domain *remote_dom;
    //    } interdomain; /* state == ECS_INTERDOMAIN */
    //    struct {
    //        u32            irq;
    //        evtchn_port_t  next_port;
    //        evtchn_port_t  prev_port;
    //    } pirq;        /* state == ECS_PIRQ */
    //    u16 virq;      /* state == ECS_VIRQ */
    //} u;

    uint64_t m_state;
    vcpuid_t m_notify_vcpuid;
    vcpuid_t m_last_vcpuid;
    event_port_t m_port;
    uint8_t m_pending;
    uint8_t m_priority{EVTCHN_FIFO_PRIORITY_DEFAULT};
    uint8_t m_last_priority;
    uint8_t __pad;

    // TODO: No ssid nor flask_sid XSM fields yet
} __attribute__((packed));

struct EXPORT_HYPERKERNEL_HVE event_queue
{
    event_word_t *m_head{};
    event_word_t m_tail{};
    uint8_t m_priority{};
    //TODO: std::mutex m_lock;
};

struct EXPORT_HYPERKERNEL_HVE event_ops
{
    using vcpu_t = hyperkernel::intel_x64::vcpu;
    using domain_t = hyperkernel::intel_x64::domain;
    using event_channel_t = hyperkernel::intel_x64::event_channel;

    using init_delegate_t = delegate<void(domain_t *, event_channel_t *)>;
    using set_pending_delegate_t = delegate<void(vcpu_t *, event_channel_t *)>;
    using clear_pending_delegate_t = delegate<void(domain_t *, event_channel_t *)>;
    using unmask_delegate_t = delegate<void(domain_t *, event_channel_t *)>;
    using is_pending_delegate_t = delegate<bool(const domain_t *, event_port_t)>;
    using is_masked_delegate_t = delegate<bool(const domain_t *, event_port_t)>;
    using is_busy_delegate_t = delegate<bool(const domain_t *, event_port_t)>;
    using set_priority_delegate_t = delegate<int(domain_t *, event_channel_t *, unsigned int priority)>;
    using print_state_delegate_t = delegate<void(domain_t *, const event_channel_t *)>;

    init_delegate_t m_init;
    set_pending_delegate_t m_set_pending;
    clear_pending_delegate_t m_clear_pending;
    unmask_delegate_t m_unmask;
    is_pending_delegate_t m_is_pending;
    is_masked_delegate_t m_is_masked;
    is_busy_delegate_t m_is_busy;
    set_priority_delegate_t m_set_priority;
    print_state_delegate_t m_print_state;
};

// -----------------------------------------------------------------------------
// Event constants
// -----------------------------------------------------------------------------

constexpr bool is_power_of_2(size_t size)
{
    return size > 0 && ((size & (size - 1)) == 0);
}

static_assert(is_power_of_2(sizeof(event_channel_t)));

constexpr auto page_size = 4096U;
constexpr auto event_words_per_page = page_size / sizeof(event_word_t); // 1024
constexpr auto nr_event_pages = EVTCHN_FIFO_NR_CHANNELS / event_words_per_page; // 128
constexpr auto event_buckets_per_page = page_size / sizeof(event_channel_t *); // 512
constexpr auto event_channels_per_bucket = page_size / sizeof(event_channel_t); // 128
constexpr auto event_channels_per_group = event_channels_per_bucket * event_buckets_per_group;
constexpr auto nr_event_groups = EVTCHN_FIFO_NR_CHANNELS / event_channels_per_group;

static_assert(is_power_of_2(nr_event_groups));

}

#endif
