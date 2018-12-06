//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

// -----------------------------------------------------------------------------
// Proof-of-concept VT-d Interrupt Remapping Table
// See VT-d reference sections 5.3.1 and 9.10
// -----------------------------------------------------------------------------

#ifndef VTD_IMAP_H
#define VTD_IMAP_H

#include <bfvmm/memory_manager/memory_manager.h>
#include <stdint.h>
#include <bfgsl.h>
#include <bfbitmanip.h>
#include <bfdebug.h>
#include <eapis/hve/arch/intel_x64/vtd/vtd.h>

namespace intel_x64
{
namespace vtd
{

// The mapping of IOAPIC RTEs to VT-d IRTEs is given
// in section 5.1.5.1 of the VT-d spec

inline uint64_t rte_vector(uint64_t rte)
{ return rte & 0xFF; }

inline uint64_t rte_trig_mode(uint64_t rte)
{ return (rte & (1UL << 15)) >> 15; }

inline uint64_t rte_mask(uint64_t rte)
{ return (rte & (1UL << 16)) >> 16; }

inline uint64_t rte_index(uint64_t rte)
{
    uint64_t idx15 = (rte & (1UL << 11)) << 4;
    uint64_t idx1400 = (rte & 0xFFFE000000000000ULL) >> 49;

    return idx15 | idx1400;
}

// VT-d Interrupt Remapping Map
class imap
{
public:

    using phys_addr_t = uintptr_t;

    using irte_type = intel_x64::vtd::irte::value_type;
    size_t irte_count = 256;
    struct irt_pair {
        gsl::span<irte_type> virt_addr{};
        phys_addr_t phys_addr{};
    };

    imap()
    {
        // bfdebug_info(0, "VT-d imap created");
    }

    void
    init()
    {
        m_irt = allocate_irt();

        for (auto &irte : m_irt.virt_addr) {
            // TODO: What is the equivalent of "identity mapping" for interrupts?
        }

        // TODO: Remap the NIC's MSI to the windows VISR driver
        // auto &irte = m_irt.virt_addr.at(0);

        // Make sure the interrupt remapping table entries make it to memory!
        ::x64::cache::wbinvd();
    }

    ~imap()
    {
        free_irt(m_irt);
    }

    phys_addr_t
    phys_addr()
    { return m_irt.phys_addr; }

    void
    dump()
    {
        bfdebug_info(0, "-------------------------------------------");
        bfdebug_info(0, "      VT-d Interrupt Remapping Table");
        bfdebug_info(0, "-------------------------------------------");

        bfdebug_nhex(0, "Table Base Virtual Address:", m_irt.virt_addr.data());
        bfdebug_nhex(0, "Table Base Physical Address:", m_irt.phys_addr);

        // bfdebug_subnhex(0, "Interupt remapping table base virtual", irt_base_virt);
        // bfdebug_subnhex(0, "Interupt remapping table base physical", irt_base_phys);
        bfdebug_info(0, "Interupt remapping table entries:");
        for (auto &irte : m_irt.virt_addr) {
            if (vtd::irte::p::is_enabled(irte)) {
                bfdebug_info(0, "interupt remapping table entry:");
                vtd::irte::dump(0, irte);
                bfdebug_info(0, "");
            }
        }
    }

private:

    irt_pair
    allocate_irt()
    {
        auto span = gsl::make_span(
            static_cast<intel_x64::vtd::irte::value_type *>(alloc_page()),
            static_cast<long>(irte_count)
        );
        irt_pair ptrs = { span, g_mm->virtptr_to_physint(span.data()) };
        return ptrs;
    }

    void
    free_irt(irt_pair &table)
    { free_page(table.virt_addr.data()); }

    irt_pair m_irt;
};

}
}

#endif
