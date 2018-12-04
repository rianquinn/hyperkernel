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
// Proof-of-concept VTD Root Table
// See VT-d reference sections 3.4.2 and 9.1
// -----------------------------------------------------------------------------

#ifndef VTD_MMAP_H
#define VTD_MMAP_H

#include <bfvmm/memory_manager/memory_manager.h>
#include <bfvmm/memory_manager/arch/x64/cr3/mmap.h>
#include <eapis/hve/arch/intel_x64/ept.h>
#include <stdint.h>
#include <bfgsl.h>
#include <bfbitmanip.h>
#include <bfdebug.h>
#include <eapis/hve/arch/intel_x64/vtd/vtd.h>

namespace intel_x64
{
namespace vtd
{

/// VT-d DMA Remapping Memory Map
///
/// This class constructs all paging structures used by the DMA remapping
/// hardware unit (IOMMU) to map PCI bus/device/functions to hardware domains
/// and physical memory. This implentation:
///     - Does not support extended root tables/extended context tables
///     - Does not support PCI requests-with-PASID
///     - Supports shared page tables with VT-x/EPT
///
/// For more information, please see the Intel Virtualization Technology for
/// Directed I/O SDM. This implementation attempts to map directly
/// to the SDM text.
///
class mmap
{
public:

    using phys_addr_t = uintptr_t;

    // Root table
    using root_entry_type = intel_x64::vtd::rte::value_type;
    size_t root_entry_count = 256;
    struct root_table_pair {
        gsl::span<root_entry_type> virt_addr{};
        phys_addr_t phys_addr{};
    };

    // Context table
    using context_entry_type = intel_x64::vtd::context_entry::value_type;
    size_t context_entry_count = 256;
    struct context_table_pair {
        gsl::span<context_entry_type> virt_addr{};
        phys_addr_t phys_addr{};
    };

    mmap()
    {
        // bfdebug_info(0, "VT-d mmap created");
    }

    void
    init()
    {
        m_root_table = allocate_root_table();

        // Make sure the DMA root table entries make it to memory!
        ::x64::cache::wbinvd();
    }

    void
    map_bus(uint64_t bus, uint64_t dma_domain_id, eapis::intel_x64::ept::mmap &mmap) 
    {
        // Lookup the root entry associated with the given bus
        auto &rte = m_root_table.virt_addr.at(bus);
        if(intel_x64::vtd::rte::present::is_enabled(rte)) {
            // bferror_nhex(0, "Bus already mapped to VT-d DMA domain:", bus);
            return;
        }

        // Allocate a new context table for each bus
        auto ct = allocate_context_table();
        init_context_table(ct, mmap, dma_domain_id);
        intel_x64::vtd::rte::present::enable(rte);
        intel_x64::vtd::rte::context_table_pointer::set(rte, (ct.phys_addr) >> 12);
        // bfdebug_info(0, "Bus mapped for DMA translation");
        // bfdebug_subnhex(0, "bus number", bus);
        // bfdebug_subnhex(0, "domain", dma_domain_id);
        // bfdebug_subnhex(0, "translation table base address", mmap.eptp());

        // Make sure the root table makes it to memory!
        ::x64::cache::wbinvd();
    }

    ~mmap()
    {
        // TODO: walk the root table and free all allocated context tables
        free(m_root_table);
        // free_context_table(m_hdvm_context_table);
        // free_context_table(m_ndvm_context_table);
    }

    phys_addr_t
    phys_addr()
    { return m_root_table.phys_addr; }

    void
    dump()
    {
        bfdebug_info(0, "-------------------------------------------");
        bfdebug_info(0, "             VT-d Root Table");
        bfdebug_info(0, "-------------------------------------------");
        bfdebug_nhex(0, "Table Base Virtual Address:", m_root_table.virt_addr.data());
        bfdebug_nhex(0, "Table Base Physical Address:", m_root_table.phys_addr);

        bfdebug_info(0, "Root table entries for all PCI buses (except the networking bus)");
        auto &rte = m_root_table.virt_addr.at(0);
        intel_x64::vtd::rte::dump(0, rte);

        bfdebug_info(0, "Root table entries for the networking bus");
        rte = m_root_table.virt_addr.at(2);
        intel_x64::vtd::rte::dump(0, rte);
        printf("\n");

        bfdebug_info(0, "-------------------------------------------");
        bfdebug_info(0, "           VT-d Context Tables");
        bfdebug_info(0, "-------------------------------------------");

        bfdebug_nhex(0, "HDVM Context Table Base Virtual Address:", m_hdvm_context_table.virt_addr.data());
        bfdebug_nhex(0, "HDVM Context Table Base Physical Address:", m_hdvm_context_table.phys_addr);
        auto &cte = m_hdvm_context_table.virt_addr.at(0);
        intel_x64::vtd::context_entry::dump(0, cte);

        bfdebug_nhex(0, "NDVM Context Table Base Virtual Address:", m_ndvm_context_table.virt_addr.data());
        bfdebug_nhex(0, "NDVM Context Table Base Physical Address:", m_ndvm_context_table.phys_addr);
        cte = m_ndvm_context_table.virt_addr.at(0);
        intel_x64::vtd::context_entry::dump(0, cte);
        printf("\n");
    }

private:

    root_table_pair
    allocate_root_table()
    {
        auto span = gsl::make_span(
            static_cast<intel_x64::vtd::rte::value_type *>(alloc_page()),
            static_cast<long>(root_entry_count)
        );
        root_table_pair ptrs = { span, g_mm->virtptr_to_physint(span.data()) };
        return ptrs;
    }

    context_table_pair
    allocate_context_table()
    {
        auto span = gsl::make_span(
            static_cast<intel_x64::vtd::context_entry::value_type *>(alloc_page()),
            static_cast<long>(context_entry_count)
        );
        context_table_pair ptrs = { span, g_mm->virtptr_to_physint(span.data()) };
        return ptrs;
    }

    // void
    // init_root_table()
    // {
    //     // Make all root table entries present and mapped to the same context
    //     // table. This effectively maps every PCI bus to the same configuration
    //     for (auto &rte : m_root_table.virt_addr) {
    //         intel_x64::vtd::rte::present::enable(rte);
    //         intel_x64::vtd::rte::context_table_pointer::set(rte, (m_hdvm_context_table.phys_addr) >> 12);
    //     }
    //
    //     // For now, reasign the entire PCI bus that the NIC is attached to a
    //     // seperate DMA remapping context, with different DMA page tables
    //     auto &rte = m_root_table.virt_addr.at(2);
    //     intel_x64::vtd::rte::context_table_pointer::set(rte, (m_ndvm_context_table.phys_addr) >> 12);
    // }

    void
    init_context_table(
        context_table_pair &context_table,
        eapis::intel_x64::ept::mmap &ept_mmap,
        uint64_t dma_domain_id
    )
    {
        // Map all context table entries to the same domain and paging
        // structures. This effectively applies the same DMA paging map to 
        // all PCI devices+functions represented by this table
        for (auto &cte : context_table.virt_addr) {
            // Block "pre-translated" DMA requests (i.e disable device-TLBs)
            intel_x64::vtd::context_entry::t::set(cte, 0x0);
            // Assume 4-level paging
            intel_x64::vtd::context_entry::aw::set(cte, 0x2);
            // Share page tables with EPT
            // TODO: Check Capability Register->SLLPS for 2MB/1GB page support
            intel_x64::vtd::context_entry::slptptr::set(cte, (ept_mmap.eptp() >> 12));
            // Assign all device+functions to the given DMA domain
            intel_x64::vtd::context_entry::did::set(cte, dma_domain_id);
            // Enable this entry for translation
            intel_x64::vtd::context_entry::p::enable(cte);
        }
    }

    void
    free(root_table_pair &table)
    { free_page(table.virt_addr.data()); }

    void
    free_context_table(context_table_pair &table)
    { free_page(table.virt_addr.data()); }

    root_table_pair m_root_table;
    context_table_pair m_hdvm_context_table;
    context_table_pair m_ndvm_context_table;
};

}
}

#endif
