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

#ifndef LAPIC_INTEL_X64_HYPERKERNEL_H
#define LAPIC_INTEL_X64_HYPERKERNEL_H

#include "../../../../../include/gpa_layout.h"
#include <bfvmm/memory_manager/memory_manager.h>
#include <eapis/hve/arch/intel_x64/lapic.h>

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

//------------------------------------------------------------------------------
// Definition
//------------------------------------------------------------------------------

namespace hyperkernel::intel_x64
{

class vcpu;

class EXPORT_HYPERKERNEL_HVE lapic
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu associated with this lapic
    ///
    /// @cond
    ///
    explicit lapic(gsl::not_null<vcpu *> vcpu);

    /// @endcond

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~lapic() = default;

    /// Initialize
    ///
    /// We have to initialize later on during the construction process to give
    /// EPT time to set up, so this function must be called manually after
    /// EPTP has been set. This will initialize the local APIC and get it
    /// ready to access guest reads and writes
    ///
    /// @expects
    /// @ensures
    ///
    void init();

    /// APIC ID
    ///
    /// The APIC ID and the vCPU ID do not need to agree, and on some systems
    /// they don't. This provides that level of flexibility by returning the
    /// APIC's ID
    ///
    /// TODO:
    ///
    /// Note that each domain will have to generate APIC IDs for us so that
    /// the APIC IDs start from 0 on each VM. For now this returns 0 as we
    /// don't support more than on vCPU. Once we attempt to add more than one
    /// vCPU, we will need to implement this. Note also that ACPI and the
    /// MP tables will have to be updated
    ///
    /// @return APIC ID
    ///
    uint32_t id() const
    { return this->read(eapis::intel_x64::lapic::id::indx); }

    /// APIC Base
    ///
    /// This function returns the APIC base for this APIC as a GPA. The HPA is
    /// maintained internally to this class and is not accessible.
    ///
    /// TODO:
    ///
    /// The APIC base is relocatable. For now the guest is not attempting to
    /// relocate the APIC base. If they do, we will have to unmap the GPA and
    /// then remap the GPA to the new APIC base, which means we will also have
    /// to store the APIC base instead of just returning a hardcoded addr.
    ///
    /// @return APIC base GPA
    ///
    uint32_t base() const
    { return LAPIC_GPA; }

    /// Read
    ///
    /// Read the value from a register
    ///
    /// @param idx the index of the register to read
    //
    /// @note the index is a dword offset, not a byte offset
    ///
    uint32_t read(uint32_t idx) const
    { return m_lapic_view[idx]; }

    /// Write
    ///
    /// Write the value to a register
    ///
    /// @param idx the index of the register to write
    /// @param val the value to write
    ///
    /// @note the index is a dword offset, not a byte offset
    ///
    void write(uint32_t idx, uint32_t val)
    { m_lapic_view[idx] = val; }

private:

    vcpu *m_vcpu;

    page_ptr<uint32_t> m_lapic_page;
    gsl::span<uint32_t> m_lapic_view;
};

}

#endif
