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

#ifndef XEN_OP_INTEL_X64_HYPERKERNEL_H
#define XEN_OP_INTEL_X64_HYPERKERNEL_H

#define __XEN_INTERFACE_VERSION__ 0x040900

#include "../base.h"

#include "public/xen.h"
#include "public/arch-x86/cpuid.h"
#include "evtchn_fifo.h"

#include <eapis/hve/arch/intel_x64/vmexit/cpuid.h>
#include <eapis/hve/arch/intel_x64/vmexit/wrmsr.h>
#include <eapis/hve/arch/intel_x64/vmexit/rdmsr.h>
#include <eapis/hve/arch/intel_x64/vmexit/io_instruction.h>

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

class EXPORT_HYPERKERNEL_HVE xen_op_handler
{
public:

    xen_op_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~xen_op_handler() = default;

    shared_info_t *shared_info();

private:

    void run_delegate(bfobject *obj);
    bool exit_handler(gsl::not_null<vcpu_t *> vcpu);

    // -------------------------------------------------------------------------
    // MSRS
    // -------------------------------------------------------------------------

    void isolate_msr(uint32_t msr);

    bool rdmsr_zero_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::rdmsr_handler::info_t &info);
    bool wrmsr_ignore_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info);

    bool rdmsr_pass_through_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::rdmsr_handler::info_t &info);
    bool wrmsr_pass_through_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info);

    bool wrmsr_store_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info);

    bool ia32_misc_enable_rdmsr_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::rdmsr_handler::info_t &info);
    bool ia32_misc_enable_wrmsr_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info);

    bool ia32_apic_base_rdmsr_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::rdmsr_handler::info_t &info);
    bool ia32_apic_base_wrmsr_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info);

    bool xen_hypercall_page_wrmsr_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info);
    bool xen_debug_ndec_wrmsr_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info);
    bool xen_debug_nhex_wrmsr_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info);

    // -------------------------------------------------------------------------
    // CPUID
    // -------------------------------------------------------------------------

    bool cpuid_zero_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);
    bool cpuid_pass_through_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);

    bool cpuid_leaf6_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);
    bool cpuid_leaf7_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);
    bool cpuid_leaf80000001_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);
    bool xen_cpuid_leaf1_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);
    bool xen_cpuid_leaf2_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);
    bool xen_cpuid_leaf3_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);
    bool xen_cpuid_leaf5_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);

    // -------------------------------------------------------------------------
    // IO Instructions
    // -------------------------------------------------------------------------

    bool io_zero_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool io_ones_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool io_ignore_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);

    // -------------------------------------------------------------------------
    // VMCalls
    // -------------------------------------------------------------------------

    // TODO: I'm a bit confused about the two vcpu types and why we pass
    // m_vcpu to the subhandlers rather than the HYPERVISOR @param vcpu
    bool HYPERVISOR_memory_op(gsl::not_null<vcpu_t *> vcpu);
    void XENMEM_add_to_physmap_handler(gsl::not_null<vcpu *> vcpu);
    void XENMEM_memory_map_handler(gsl::not_null<vcpu *> vcpu);

    bool HYPERVISOR_xen_version(gsl::not_null<vcpu_t *> vcpu);
    void XENVER_get_features_handler(gsl::not_null<vcpu *> vcpu);

    bool HYPERVISOR_hvm_op(gsl::not_null<vcpu_t *> vcpu);
    void HVMOP_set_param_handler(gsl::not_null<vcpu *> vcpu);
    void HVMOP_get_param_handler(gsl::not_null<vcpu *> vcpu);
    void HVMOP_pagetable_dying_handler(gsl::not_null<vcpu *> vcpu);

    bool HYPERVISOR_event_channel_op(gsl::not_null<vcpu_t *> vcpu);
    void EVTCHNOP_init_control_handler(gsl::not_null<vcpu *> vcpu);
    void EVTCHNOP_send_handler(gsl::not_null<vcpu *> vcpu);

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    void reset_vcpu_time_info();
    void update_vcpu_time_info();

    // -------------------------------------------------------------------------
    // Quirks
    // -------------------------------------------------------------------------

    void register_unplug_quirk();

private:

    uint64_t m_cpu_frequency;
    std::unordered_map<uint32_t, uint64_t> m_msrs;

private:

    vcpu *m_vcpu;

    uint64_t m_hypercall_page_gpa{};
    eapis::x64::unique_map<shared_info_t> m_shared_info;
    eapis::x64::unique_map<uint8_t> m_console;
    std::unique_ptr<hyperkernel::intel_x64::evtchn_fifo> m_evtchn_fifo;

public:

    /// @cond
    xen_op_handler(xen_op_handler &&) = default;
    xen_op_handler &operator=(xen_op_handler &&) = default;

    xen_op_handler(const xen_op_handler &) = delete;
    xen_op_handler &operator=(const xen_op_handler &) = delete;

    /// @endcond
};

}

#endif
