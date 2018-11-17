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

#ifndef GNTTABOP_INTEL_X64_HYPERKERNEL_H
#define GNTTABOP_INTEL_X64_HYPERKERNEL_H

#include "../base.h"
#include "public/grant_table.h"
#include "xen_op.h"

#include <eapis/hve/arch/x64/unmapper.h>
#include <bfmath.h>

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

class EXPORT_HYPERKERNEL_HVE gnttab_op
{
public:

    //static_assert(is_power_of_2(

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu of the gnttab_op
    ///
    gnttab_op(
        gsl::not_null<vcpu *> vcpu,
        gsl::not_null<xen_op_handler *> handler
    );

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~gnttab_op() = default;

    /// Query size
    ///
    void query_size(gsl::not_null<gnttab_query_size_t *> arg);

private:

    /// Max number of frames per domain (the Xen default)
    //
    static constexpr auto max_grant_frames = 64;




    vcpu *m_vcpu{};
    xen_op_handler *m_xen_op{};

public:

    /// @cond

    gnttab_op(gnttab_op &&) = default;
    gnttab_op &operator=(gnttab_op &&) = default;

    gnttab_op(const gnttab_op &) = delete;
    gnttab_op &operator=(const gnttab_op &) = delete;

    /// @endcond
};

}

#endif
