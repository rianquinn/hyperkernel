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

#ifndef VMCALL_RUN_INTEL_X64_HYPERKERNEL_H
#define VMCALL_RUN_INTEL_X64_HYPERKERNEL_H

#include "../base.h"

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

class EXPORT_HYPERKERNEL_HVE vmcall_run_op_handler
{
public:

    vmcall_run_op_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vmcall_run_op_handler() = default;

private:

    bool dispatch(gsl::not_null<vcpu *> vcpu);

private:

    vcpu *m_vcpu;
    vcpu *m_child_vcpu;

public:

    /// @cond

    vmcall_run_op_handler(vmcall_run_op_handler &&) = default;
    vmcall_run_op_handler &operator=(vmcall_run_op_handler &&) = default;

    vmcall_run_op_handler(const vmcall_run_op_handler &) = delete;
    vmcall_run_op_handler &operator=(const vmcall_run_op_handler &) = delete;

    /// @endcond
};

}

#endif
