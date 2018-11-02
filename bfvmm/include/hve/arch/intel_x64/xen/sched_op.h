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

#ifndef SCHEDOP_INTEL_X64_HYPERKERNEL_H
#define SCHEDOP_INTEL_X64_HYPERKERNEL_H

#include "../base.h"
#include "public/sched.h"

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

class EXPORT_HYPERKERNEL_HVE sched_op
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param freq the frequency of the invariant TSC in kHz
    ///
    sched_op(gsl::not_null<vcpu *> vcpu, uint64_t tsc_freq);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~sched_op() = default;

    /// Handle yield
    ///
    void handle_yield(gsl::not_null<vcpu *> vcpu);

private:

    vcpu *m_vcpu;

    uint64_t m_tsc_freq_kHz{};
    uint64_t m_pet_freq_kHz{};
    uint64_t m_ticks_per_slice{};

public:

    /// @cond

    sched_op(sched_op &&) = default;
    sched_op &operator=(sched_op &&) = default;

    sched_op(const sched_op &) = delete;
    sched_op &operator=(const sched_op &) = delete;

    /// @endcond
};

}

#endif
