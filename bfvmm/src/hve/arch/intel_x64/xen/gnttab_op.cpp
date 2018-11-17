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

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/xen/gnttab_op.h>

// =============================================================================
// Implementation
// =============================================================================

namespace hyperkernel::intel_x64
{

gnttab_op::gnttab_op(
    gsl::not_null<vcpu *> vcpu,
    gsl::not_null<xen_op_handler *> handler)
:
    m_vcpu{vcpu},
    m_xen_op{handler}
{
    m_gnttab.reserve(max_nr_frames);
    m_gnttab.push_back(make_page<entry_t>());
}

void
gnttab_op::query_size(gsl::not_null<gnttab_query_size_t *> arg)
{
    arg->nr_frames = m_gnttab.size();
    arg->max_nr_frames = max_nr_frames;
    arg->status = GNTST_okay;
}

void
gnttab_op::set_version(gsl::not_null<gnttab_set_version_t *> arg)
{
    expects(arg->version == 2);
}

}
