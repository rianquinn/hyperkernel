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

#include <bfgsl.h>
#include <bfcallonce.h>

#include <errno.h>
#include <string.h>

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/xen/evtchn_op.h>


// When the guest receives an upcall, it does several things:
// (transplanted from xen/xen/arch/x86/guest/xen.c)
//
// vcpu_info->evtchn_upcall_pending = 0
// pending = atomic_read(vcpu_info->evtchn_pending_sel)
//      while (pending) {
//              b = first_set_bit(pending)
//              evtchn = shared_info->evtchn_pending[b]
//              clear_bit(b, &pending)
//              evtchn &= ~shared_info->evtchn_mask[b]
//              while (evtchn) {
//                      port = first_set_bit(evtchn)
//                      clear_bit(port, &evtchn)
//                      port += b * BITS_PER_LONG
//                      *process port*
//              }
//      }

// =============================================================================
// Implementation
// =============================================================================

static bfn::once_flag g_flag{};

namespace hyperkernel::intel_x64
{

evtchn_op::evtchn_op(
    gsl::not_null<vcpu *> vcpu,
    gsl::not_null<xen_op_handler *> handler)
:
    m_vcpu{vcpu},
    m_xen_op{handler}
{
    m_event_words.reserve(max_word_pages);
    m_event_chans.reserve(max_chan_pages);
}

void
evtchn_op::init_control(gsl::not_null<evtchn_init_control_t *> ctl)
{
    expects(ctl->vcpu == m_vcpu->lapicid());
    expects(ctl->offset <= (0x1000 - sizeof(evtchn_fifo_control_block_t)));
    expects((ctl->offset & 0x7) == 0);

    this->setup_control_block(ctl->control_gfn, ctl->offset);
    this->setup_ports();

    ctl->link_bits = EVTCHN_FIFO_LINK_BITS;
}

void
evtchn_op::set_callback_via(uint64_t via)
{
    expects(m_xen_op->shared_info());

    // At this point, the guest has initialized the evtchn
    // control structures and has just given us the vector
    // to inject whenever an upcall is pending.
    //
    m_cb_via = via;
    m_vcpu->queue_external_interrupt(via);
}

void
evtchn_op::bind_virq(gsl::not_null<evtchn_bind_virq_t *> bind)
{
    expects(bind->vcpu == 0);
    expects(m_virq_to_port.at(bind->virq) == null_port);

    switch (bind->virq) {
        case VIRQ_TIMER:
            this->bind_virq_timer(bind);
            break;

        default:
            throw std::runtime_error("unhandled bind VIRQ: " +
                                     std::to_string(bind->virq));
    }
}

void
evtchn_op::expand_array(gsl::not_null<evtchn_expand_array_t *> arr)
{ this->make_word_page(arr); }

void
evtchn_op::set_priority(const gsl::not_null<evtchn_set_priority_t *> pri)
{
    expects(pri->priority < m_queues.size());

    auto chan = this->port_to_chan(pri->port);
    expects(chan != nullptr);

    chan->set_priority(pri->priority);
}

void
evtchn_op::handle_vmx_pet(gsl::not_null<vcpu_t *> vcpu)
{
    bfignored(vcpu);

    auto port = m_virq_to_port[VIRQ_TIMER];
    expects(port > 0);

    auto chan = this->port_to_chan(port);
    expects(chan != nullptr);
    expects(chan->port() == port);
    expects(chan->state() == evtchn::state_virq);

    this->set_pending(chan);
    m_vcpu->disable_vmx_preemption_timer();
}

// =============================================================================
// Initialization
// =============================================================================

void
evtchn_op::setup_control_block(uint64_t gfn, uint32_t offset)
{
    const auto gpa = gfn << ::x64::pt::page_shift;
    m_ctl_blk_ump = m_vcpu->map_gpa_4k<uint8_t>(gpa);

    uint8_t *base = m_ctl_blk_ump.get() + offset;
    m_ctl_blk = reinterpret_cast<evtchn_fifo_control_block_t *>(base);

    for (auto i = 0; i <= EVTCHN_FIFO_PRIORITY_MIN; i++) {
        m_queues[i].priority = i;
        m_queues[i].head = &m_ctl_blk->head[i];
    }
}

void
evtchn_op::setup_ports()
{
    expects(m_event_words.size() == 0);
    expects(m_event_chans.size() == 0);
    expects(m_allocated_words == 0);
    expects(m_allocated_chans == 0);

    this->make_chan_page(null_port);
    this->port_to_chan(null_port)->set_state(evtchn::state_reserved);

    for (auto p = 1; p < chans_per_page; p++) {
        auto arr = m_xen_op->shared_info()->evtchn_pending;
        auto idx = p / bits_per_xen_ulong;
        auto bit = p % bits_per_xen_ulong;
        auto val = arr[idx];

        if (is_bit_set(bit, val)) {
            this->port_to_chan(p)->set_pending();
        }
    }

    auto info = &m_xen_op->shared_info()->vcpu_info[0];

    info->evtchn_upcall_pending = 1ULL;
    info->evtchn_pending_sel = ~0ULL;
}

void
evtchn_op::bind_virq_timer(gsl::not_null<evtchn_bind_virq_t *> bind)
{
    const auto virq = bind->virq;
    const auto vcpu = bind->vcpu;
    const auto port = this->make_new_port();

    auto chan = this->port_to_chan(port);

    chan->set_port(port);
    chan->set_state(evtchn::state_virq);
    chan->set_vcpuid(bind->vcpu);
    chan->set_virq(bind->virq);

    m_virq_to_port[virq] = port;
    bind->port = port;
}

int
evtchn_op::try_set_link(word_t *word, event_word_t *ew, port_t port)
{
    auto &expect = *ew;
    if (is_bit_cleared(expect, EVTCHN_FIFO_LINKED)) {
        return 0;
    }

    auto desire = (expect & ~((1 << EVTCHN_FIFO_BUSY) | port_mask)) | port;
    return word->compare_exchange_strong(expect, desire) ? 1 : -EAGAIN;
}


/*
 * See xen/xen/common/event_fifo.c for reference
 *
 * Atomically set the LINK field iff it is still LINKED.
 *
 * The guest is only permitted to make the following changes to a
 * LINKED event.
 *
 * - set MASKED
 * - clear MASKED
 * - clear PENDING
 * - clear LINKED (and LINK)
 *
 * We block unmasking by the guest by marking the tail word as BUSY,
 * therefore, the cmpxchg() may fail at most 4 times.
 */
bool
evtchn_op::set_link(word_t *word, port_t port)
{
    auto w = word->load();
    int ret = this->try_set_link(word, &w, port);

    if (ret >= 0) {
        return ret;
    }

    /*
     * Try again, this time after marking the word
     * busy to prevent guest unmasking.
     */
    this->word_set_busy(word);
    w = word->load();

    for (int i = 0; i < 4; i++) {
        ret = this->try_set_link(word, &w, port);
        if (ret >= 0) {
            if (ret == 0) {
                this->word_clear_busy(word);
            }
            return ret;
        }
    }

    bfalert_nhex(0, "Failed to link port:", port);
    this->word_clear_busy(word);

    return 0;

    //TODO:
    // Xen returns 1 here which 't violates the iff above...
    // It seems like we should return 0 here
    //
    // return 1;
}

void
evtchn_op::set_pending(chan_t *chan)
{
    expects(m_ctl_blk);

    const auto port = chan->port();
    auto word = this->port_to_word(port);
    if (!word) {

        // The guest hasn't added the corresponding
        // event array, so we set pending for later
        //
        chan->set_pending();
        return;
    }

    const auto was_pending = this->word_is_pending(word);
    if (this->word_is_masked(word) || this->word_is_linked(word)) {
        return;
    }

    if (this->word_test_and_set_linked(word)) {
        //goto done;
        return;
    }

    auto next = &m_queues.at(chan->priority());
    auto prev = &m_queues.at(chan->prev_priority());

    if (prev->tail == port) {
        prev->tail = null_port;
    }

    if (next != prev) {
        chan->set_prev_vcpuid(chan->vcpuid());
        chan->set_prev_priority(chan->priority());
    }

    bool linked = false;
    if (next->tail != null_port) {
        auto tail_word = this->port_to_word(next->tail);
        linked = this->set_link(tail_word, port);
    }

    if (!linked) {
        //TODO: atomic?
        *next->head = port;
    }

    next->tail = port;
    auto bit = 1UL << next->priority;

    //TODO: atomic?
    auto wasnt_ready = (m_ctl_blk->ready & bit) == 0;

    if (!linked && wasnt_ready) {
        auto vcpu_info = &m_xen_op->shared_info()->vcpu_info[0];
        if (vcpu_info->evtchn_upcall_pending) {
            return;
        }

        vcpu_info->evtchn_upcall_pending |= 1;

        auto sel = &vcpu_info->evtchn_pending_sel;
        auto idx0 = port / bits_per_xen_ulong;
        *sel |= set_bit(*sel, idx0);

        auto pen = &m_xen_op->shared_info()->evtchn_pending[idx0];
        auto idx1 = port % bits_per_xen_ulong;
        *pen |= set_bit(*pen, idx1);

        m_vcpu->queue_external_interrupt(m_cb_via);
    }

//done:
//    if (!was_pending) {
//        this->check_pollers(port);
//    }
}

// Ports
//
// A port is an address to two things: a chan_t and a word_t
// Ports use a two-level addressing scheme.
//

evtchn_op::port_t
evtchn_op::make_new_port()
{
    for (port_t p = m_port_end; p < max_channels; p++) {
        if (this->make_port(p) == -EBUSY) {
            continue;
        }

        m_port_end = p + 1U;
        return p;
    }

    return null_port;
}

evtchn_op::chan_t *
evtchn_op::port_to_chan(port_t port) const
{
    const auto size = m_event_chans.size();
    const auto page = (port & chan_page_mask) >> chan_page_shift;

    if (page >= size) {
        return nullptr;
    }

    auto chan = m_event_chans[page].get();
    return &chan[port & chan_mask];
}

// Note:
//
// Word arrays are shared between the guest and host. The guest adds a new
// word array with the EVTCHNOP_expand_array hypercall, so it is possible
// that a given port doesn't map to an existing event word.
//
evtchn_op::word_t *
evtchn_op::port_to_word(port_t port) const
{
    const auto size = m_event_words.size();
    const auto page = (port & word_page_mask) >> word_page_shift;

    if (page >= size) {
        return nullptr;
    }

    auto word = m_event_words[page].get();
    return &word[port & word_mask];
}

int
evtchn_op::make_port(port_t port)
{
    if (port >= max_channels) {
        throw std::invalid_argument("make_port: port out of range" +
                                    std::to_string(port));
    }

    if (const auto chan = this->port_to_chan(port); chan) {
        if (chan->state() != evtchn::state_free) {
            return -EBUSY;
        }

        auto word = this->port_to_word(port);
        if (word && this->word_is_busy(word)) {
            return -EBUSY;
        }
        return 0;
    }

    this->make_chan_page(port);
    return 0;
}

void
evtchn_op::make_chan_page(port_t port)
{
    const auto indx = (port & chan_page_mask) >> chan_page_shift;
    const auto size = m_event_chans.size();
    const auto cpty = m_event_chans.capacity();

    expects(size == indx);
    expects(size < cpty);

    auto page = make_page<chan_t>();

    for (auto i = 0; i < chans_per_page; i++) {
        auto chan = &page.get()[i];

        chan->set_state(evtchn::state_free);
        chan->set_priority(EVTCHN_FIFO_PRIORITY_DEFAULT);
        chan->set_prev_priority(EVTCHN_FIFO_PRIORITY_DEFAULT);

        //TODO: Need to use ID the guest
        // passes in to bind_virq
        chan->set_vcpuid(0);

        chan->set_prev_vcpuid(0);
        chan->set_port(port + i);
        chan->clear_pending();
    }

    m_event_chans.push_back(std::move(page));
    m_allocated_chans += chans_per_page;
}

void
evtchn_op::make_word_page(gsl::not_null<evtchn_expand_array_t *> expand)
{
    expects(m_event_words.size() < m_event_words.capacity());

    auto prev = m_allocated_words;
    auto addr = expand->array_gfn << ::x64::pt::page_shift;
    auto page = m_vcpu->map_gpa_4k<word_t>(addr);

    m_event_words.push_back(std::move(page));
    m_allocated_words += words_per_page;

    for (auto p = prev; p < m_allocated_words; p++) {
        auto chan = this->port_to_chan(p);
        if (!chan || !chan->is_pending()) {
            continue;
        }
        this->set_pending(chan);
    }
}

bool evtchn_op::word_is_pending(word_t *word) const
{
    return is_bit_set(word->load(), EVTCHN_FIFO_PENDING);
}

bool evtchn_op::word_is_masked(word_t *word) const
{
    return is_bit_set(word->load(), EVTCHN_FIFO_MASKED);
}

bool evtchn_op::word_is_linked(word_t *word) const
{
    return is_bit_set(word->load(), EVTCHN_FIFO_LINKED);
}

bool evtchn_op::word_is_busy(word_t *word) const
{
    return is_bit_set(word->load(), EVTCHN_FIFO_BUSY);
}

void evtchn_op::word_set_pending(word_t *word)
{
    word->fetch_or(1U << EVTCHN_FIFO_PENDING);
}

bool evtchn_op::word_test_and_set_pending(word_t *word)
{
    const auto mask = 1U << EVTCHN_FIFO_PENDING;
    const auto prev = word->fetch_or(mask);

    return is_bit_set(prev, EVTCHN_FIFO_PENDING);
}

void evtchn_op::word_set_busy(word_t *word)
{
    word->fetch_or(1U << EVTCHN_FIFO_BUSY);
}

bool evtchn_op::word_test_and_set_busy(word_t *word)
{
    const auto mask = 1U << EVTCHN_FIFO_BUSY;
    const auto prev = word->fetch_or(mask);

    return is_bit_set(prev, EVTCHN_FIFO_BUSY);
}

void evtchn_op::word_set_masked(word_t *word)
{
    word->fetch_or(1U << EVTCHN_FIFO_MASKED);
}

bool evtchn_op::word_test_and_set_masked(word_t *word)
{
    const auto mask = 1U << EVTCHN_FIFO_MASKED;
    const auto prev = word->fetch_or(mask);

    return is_bit_set(prev, EVTCHN_FIFO_MASKED);
}

void evtchn_op::word_set_linked(word_t *word)
{
    word->fetch_or(1U << EVTCHN_FIFO_LINKED);
}

bool evtchn_op::word_test_and_set_linked(word_t *word)
{
    const auto mask = 1U << EVTCHN_FIFO_LINKED;
    const auto prev = word->fetch_or(mask);

    return is_bit_set(prev, EVTCHN_FIFO_LINKED);
}

void evtchn_op::word_clear_pending(word_t *word)
{
    word->fetch_and(~(1U << EVTCHN_FIFO_PENDING));
}

bool evtchn_op::word_test_and_clear_pending(word_t *word)
{
    const auto mask = ~(1U << EVTCHN_FIFO_PENDING);
    const auto prev = word->fetch_and(mask);

    return is_bit_cleared(prev, EVTCHN_FIFO_PENDING);
}

void evtchn_op::word_clear_busy(word_t *word)
{
    word->fetch_and(~(1U << EVTCHN_FIFO_BUSY));
}

bool evtchn_op::word_test_and_clear_busy(word_t *word)
{
    const auto mask = ~(1U << EVTCHN_FIFO_BUSY);
    const auto prev = word->fetch_and(mask);

    return is_bit_cleared(prev, EVTCHN_FIFO_BUSY);
}

void evtchn_op::word_clear_masked(word_t *word)
{
    word->fetch_and(~(1U << EVTCHN_FIFO_MASKED));
}

bool evtchn_op::word_test_and_clear_masked(word_t *word)
{
    const auto mask = ~(1U << EVTCHN_FIFO_MASKED);
    const auto prev = word->fetch_and(mask);

    return is_bit_cleared(prev, EVTCHN_FIFO_MASKED);
}

void evtchn_op::word_clear_linked(word_t *word)
{
    word->fetch_and(~(1U << EVTCHN_FIFO_LINKED));
}

bool evtchn_op::word_test_and_clear_linked(word_t *word)
{
    const auto mask = ~(1U << EVTCHN_FIFO_LINKED);
    const auto prev = word->fetch_and(mask);

    return is_bit_cleared(prev, EVTCHN_FIFO_LINKED);
}

}
