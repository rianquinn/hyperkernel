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

#include <iostream>
#include <hve/arch/intel_x64/vcpu.h>

#include <hve/arch/intel_x64/xen/public/xen.h>
#include <hve/arch/intel_x64/xen/public/memory.h>
#include <hve/arch/intel_x64/xen/public/version.h>
#include <hve/arch/intel_x64/xen/public/hvm/hvm_op.h>
#include <hve/arch/intel_x64/xen/public/arch-x86/cpuid.h>

#include <hve/arch/intel_x64/xen/xen_op.h>
#include "../../../../../../include/gpa_layout.h"

// wrmsr_safe(0xC0000600, dec, 0);
// wrmsr_safe(0xC0000700, hex, 0);

// =============================================================================
// Definitions
// =============================================================================

constexpr auto xen_msr_hypercall_page   = 0xC0000500;
constexpr auto xen_msr_debug_ndec       = 0xC0000600;
constexpr auto xen_msr_debug_nhex       = 0xC0000700;

// =============================================================================
// Macros
// =============================================================================

#define make_delegate(a,b)                                                                          \
    eapis::intel_x64::a::handler_delegate_t::create<xen_op_handler, &xen_op_handler::b>(this)

#define ADD_VMCALL_HANDLER(a)                                                                       \
    m_vcpu->add_vmcall_handler(                                                                     \
        vmcall_handler_delegate(xen_op_handler, a))

#define ADD_CPUID_HANDLER(a,b)                                                                      \
    m_vcpu->add_cpuid_handler(                                                                      \
        a, make_delegate(cpuid_handler, b))

#define EMULATE_CPUID(a,b)                                                                          \
    m_vcpu->emulate_cpuid(                                                                          \
        a, make_delegate(cpuid_handler, b))

#define EMULATE_RDMSR(a,b)                                                                          \
    m_vcpu->emulate_rdmsr(                                                                          \
        a, make_delegate(rdmsr_handler, b))

#define ADD_WRMSR_HANDLER(a,b)                                                                          \
    m_vcpu->add_wrmsr_handler(                                                                          \
        a, make_delegate(wrmsr_handler, b))

#define EMULATE_WRMSR(a,b)                                                                          \
    m_vcpu->emulate_wrmsr(                                                                          \
        a, make_delegate(wrmsr_handler, b))

#define EMULATE_IO_INSTRUCTION(a,b,c)                                                               \
    m_vcpu->emulate_io_instruction(                                                                 \
        a, make_delegate(io_instruction_handler, b), make_delegate(io_instruction_handler, c))

// =============================================================================
// Implementation
// =============================================================================

namespace hyperkernel::intel_x64
{

xen_op_handler::xen_op_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_run_delegate(
        bfvmm::vcpu::run_delegate_t::create<xen_op_handler, &xen_op_handler::run_delegate>(this)
    );

    vcpu->add_exit_handler(
        handler_delegate_t::create<xen_op_handler, &xen_op_handler::exit_handler>(this)
    );

    EMULATE_WRMSR(xen_msr_hypercall_page, xen_hypercall_page_wrmsr_handler);
    EMULATE_WRMSR(xen_msr_debug_ndec, xen_debug_ndec_wrmsr_handler);
    EMULATE_WRMSR(xen_msr_debug_nhex, xen_debug_nhex_wrmsr_handler);

    EMULATE_CPUID(XEN_CPUID_LEAF(0), xen_cpuid_leaf1_handler);
    EMULATE_CPUID(XEN_CPUID_LEAF(1), xen_cpuid_leaf2_handler);
    EMULATE_CPUID(XEN_CPUID_LEAF(2), xen_cpuid_leaf3_handler);
    EMULATE_CPUID(XEN_CPUID_LEAF(4), xen_cpuid_leaf5_handler);

    ADD_VMCALL_HANDLER(HYPERVISOR_memory_op);
    ADD_VMCALL_HANDLER(HYPERVISOR_xen_version);
    ADD_VMCALL_HANDLER(HYPERVISOR_hvm_op);

    if (vcpu->is_domU()) {
        vcpu->trap_on_all_io_instruction_accesses();
        vcpu->trap_on_all_rdmsr_accesses();
        vcpu->trap_on_all_wrmsr_accesses();
    }

    this->isolate_msr(::x64::msrs::ia32_star::addr);
    this->isolate_msr(::x64::msrs::ia32_lstar::addr);
    this->isolate_msr(::x64::msrs::ia32_cstar::addr);
    this->isolate_msr(::x64::msrs::ia32_fmask::addr);
    this->isolate_msr(::x64::msrs::ia32_kernel_gs_base::addr);

    if (vcpu->is_dom0()) {
        return;
    }

    vcpu->pass_through_msr_access(::x64::msrs::ia32_pat::addr);
    vcpu->pass_through_msr_access(::intel_x64::msrs::ia32_efer::addr);
    vcpu->pass_through_msr_access(::intel_x64::msrs::ia32_fs_base::addr);
    vcpu->pass_through_msr_access(::intel_x64::msrs::ia32_gs_base::addr);
    vcpu->pass_through_msr_access(::intel_x64::msrs::ia32_sysenter_cs::addr);
    vcpu->pass_through_msr_access(::intel_x64::msrs::ia32_sysenter_eip::addr);
    vcpu->pass_through_msr_access(::intel_x64::msrs::ia32_sysenter_esp::addr);

    EMULATE_RDMSR(0xFE, rdmsr_zero_handler);                        // MTRRs not supported
    EMULATE_RDMSR(0x2FF, rdmsr_zero_handler);                       // MTRRs not supported
    EMULATE_RDMSR(0x1B, ia32_apic_base_rdmsr_handler);              // TODO: use namespace name
    EMULATE_WRMSR(0x1B, ia32_apic_base_wrmsr_handler);              // TODO: use namespace name
    EMULATE_RDMSR(0x1A0, ia32_misc_enable_rdmsr_handler);           // TODO: use namespace name
    EMULATE_WRMSR(0x1A0, ia32_misc_enable_wrmsr_handler);           // TODO: use namespace name

    ADD_CPUID_HANDLER(0, cpuid_pass_through_handler);
    ADD_CPUID_HANDLER(0x6, cpuid_leaf6_handler);
    ADD_CPUID_HANDLER(0x7, cpuid_leaf7_handler);
    EMULATE_CPUID(0xD, cpuid_zero_handler);
    EMULATE_CPUID(0xF, cpuid_zero_handler);
    EMULATE_CPUID(0x10, cpuid_zero_handler);
    ADD_CPUID_HANDLER(0x16, cpuid_pass_through_handler);            // TODO: 0 reserved bits
    ADD_CPUID_HANDLER(0x80000000, cpuid_pass_through_handler);      // TODO: 0 reserved bits
    ADD_CPUID_HANDLER(0x80000001, cpuid_leaf80000001_handler);      // TODO: 0 reserved bits
    ADD_CPUID_HANDLER(0x80000007, cpuid_pass_through_handler);      // TODO: 0 reserved bits
    ADD_CPUID_HANDLER(0x80000008, cpuid_pass_through_handler);      // TODO: 0 reserved bits

    EMULATE_IO_INSTRUCTION(0xCF8, io_ones_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(0xCFC, io_ones_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(0xCFD, io_ones_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(0xCFE, io_ones_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(0xCFF, io_ones_handler, io_ignore_handler);

    this->register_unplug_quirk();
}

static uint64_t
cpu_frequency(void)
{
    using namespace ::x64::cpuid;
    using namespace ::intel_x64::cpuid;

    // If we are running on VMWare, frequency information is reported through
    // a different CPUID leaf that is hypervisor specific so we should check
    // to see if we are on VMWare first which returns its results in kHz
    // already for us.
    //
    // If we are not on VMWare, we use CPUID 0x15 to report the TSC frequency
    // which is more accurate than 0x16. There is a quirk with some
    // archiectures in that the crystal clock speed is not reported properly,
    // so that information has to be hard coded.
    //
    // Notes:
    // - An invariant TSC is expected and required
    // - The result of this function is in kHz.
    // - The TSC core ratio is used instead of 0x16 as it is more accurate

    if (ebx::get(0x40000000) == 0x61774d56) {
        if (auto freq = eax::get(0x40000010); freq != 0) {
            return freq;
        }

        throw std::runtime_error("unsupported system: missing vmware freq");
    }

    auto [denominator, numerator, freq, ignore] =
        ::x64::cpuid::get(0x15, 0, 0, 0);

    if (denominator == 0 || numerator == 0) {
        throw std::runtime_error("unsupported system: missing TSC ratio");
    }

    if (freq == 0) {
        switch (feature_information::eax::family_id::get()) {
            case 0x4E:  // Skylake Mobile
            case 0x5E:  // Skylake Desktop
            case 0x8E:  // Kabylake Mobile
            case 0x9E:  // Kabylake Desktop
                freq = 24000;
                break;

            case 0x5F:  // Atom Denverton
                freq = 25000;
                break;

            case 0x5C:  // Atom Goldmont
                freq = 19200;
                break;

            default:
                throw std::runtime_error("unsupported system: unknown freq");
        };
    }
    else {
        freq /= 1000;
    }

    return freq * numerator / denominator;
}

void
xen_op_handler::run_delegate(bfobject *obj)
{
    // Note:
    //
    // Note that this function is executed on every entry, so we want to
    // limit what we are doing here. This is an expensive function to
    // execute.

    this->update_vcpu_time_info();

    // Note:
    //
    // We don't use the MSR load/store pages as Intel actually states not to
    // use them so that you can us lazy load/store. To make this work we have
    // three different types of MSRs that we have to deal with:
    // - pass through: these are MSRs that are passed through to the guest so
    //   that the guest can read / write to these MSRs and actually change
    //   the physical hardware. An example of this type of MSR is the LSTAR.
    //   Since this type of MSR is changing the hardware, on each world
    //   switch, we have to write these values from the guest to the hardware
    //   so that these values are the proper value before executing the new
    //   vcpu. Since we need to cache these values, we have to watch writes
    //   to these values. Thankfully, writes to these types of MSRs don't
    //   really happen. Also note that these MSRs cannot be used by the VMM
    //   for this to work, which is one reason why Bareflank only used the MSRs
    //   that are natively saved/loaded by the VMCS already using existing
    //   controls. Note that we use the isolate function to handle the MSRs
    //   that are not already in the VMCS. If the MSR is already in the VMCS
    //   we only use the pass through function, as the VMCS will handle
    //   load/store for us automatically.
    // - emulated: these are MSRs that never touch the real hardware. We fake
    //   the contents of these MSRs and all reads and writes go to our fake
    //   MSR value. There are not many of these, and we use these to
    //   communicate the configuration of hardware to a guest vcpu.
    // - load/store: these are MSRs that have to be saved on every exit, and
    //   then restored on every entry. We want to keep this list to a minimum
    //   and for now, the only register that is in this basket is the SWAPGS
    //   msr, as we have no way of seeing writes to it, so have to save its
    //   value on exit, and restore on every world switch. Note that we
    //   handle these MSRs the same as pass through, with the exception that
    //   they need to be stored on exit.

    if (obj != nullptr) {
        for (const auto &msr : m_msrs) {
            ::x64::msrs::set(msr.first, msr.second);
        }
    }
}

bool
xen_op_handler::exit_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    // Note:
    //
    // Note that this function is executed on every exit, so we want to
    // limit what we are doing here. This is an expensive function to
    // execute.

    using namespace ::x64::msrs;
    m_msrs[ia32_kernel_gs_base::addr] = ia32_kernel_gs_base::get();

    // Ignored
    return false;
}

// -----------------------------------------------------------------------------
// MSRs
// -----------------------------------------------------------------------------

void
xen_op_handler::isolate_msr(uint32_t msr)
{
    m_vcpu->pass_through_rdmsr_access(msr);
    ADD_WRMSR_HANDLER(msr, wrmsr_store_handler);

    if (m_vcpu->is_dom0()) {
        m_msrs[msr] = ::x64::msrs::get(msr);
    }
}

bool
xen_op_handler::rdmsr_zero_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0U;
    return true;
}

bool
xen_op_handler::wrmsr_ignore_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
xen_op_handler::rdmsr_pass_through_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
xen_op_handler::wrmsr_pass_through_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
xen_op_handler::wrmsr_store_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);

    m_msrs[info.msr] = info.val;
    return true;
}

bool
xen_op_handler::ia32_misc_enable_rdmsr_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);
    using namespace ::intel_x64::msrs;

    info.val = 0;
    return true;
}

bool
xen_op_handler::ia32_misc_enable_wrmsr_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return false;
}

bool
xen_op_handler::ia32_apic_base_rdmsr_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_vcpu->lapic_base() | 0x100;
    return true;
}

bool
xen_op_handler::ia32_apic_base_wrmsr_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return false;
}

static void
vmx_init_hypercall_page(uint8_t *hypercall_page)
{
    auto page = gsl::span(hypercall_page, 0x1000);

    for (uint8_t i = 0; i < 55; i++) {
        auto entry = page.subspan(i * 32, 32);

        entry[0] = 0xB8U;
        entry[1] = i;
        entry[2] = 0U;
        entry[3] = 0U;
        entry[4] = 0U;
        entry[5] = 0x0FU;
        entry[6] = 0x01U;
        entry[7] = 0xC1U;
        entry[8] = 0xC3U;
    }
}

bool
xen_op_handler::xen_hypercall_page_wrmsr_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    auto map = vcpu_cast(vcpu)->map_gpa_4k<uint8_t>(info.val);
    vmx_init_hypercall_page(map.get());

    return true;
}

bool
xen_op_handler::xen_debug_ndec_wrmsr_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);

    bfdebug_ndec(0, "debug", info.val);
    return true;
}

bool
xen_op_handler::xen_debug_nhex_wrmsr_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);

    bfdebug_nhex(0, "debug", info.val);
    return true;
}

// -----------------------------------------------------------------------------
// CPUID
// -----------------------------------------------------------------------------

bool
xen_op_handler::cpuid_zero_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rax = 0U;
    info.rbx = 0U;
    info.rcx = 0U;
    info.rdx = 0U;

    return true;
}

bool
xen_op_handler::cpuid_pass_through_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
xen_op_handler::cpuid_leaf6_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    // Diables all power management, minus leaving ARAT turned on. The guest
    // should not attempt to maintain power management as that will be done
    // by the host OS.

    info.rax &= 0x4U;
    info.rbx = 0U;
    info.rcx = 0U;
    info.rdx = 0U;

    return true;
}

bool
xen_op_handler::cpuid_leaf7_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    // Diables the following features:
    //
    // EBX:
    // - SGX                no plans to support
    // - AVX2               need to properly emulate XSAVE/XRESTORE
    // - INVPCID            need to properly emulate PCID
    // - RTM                no plans to support
    // - RDT-M              no plans to support
    // - MPX                no plans to support
    // - RDT-A              no plans to support
    // - AVX512F            need to properly emulate XSAVE/XRESTORE
    // - AVX512DQ           need to properly emulate XSAVE/XRESTORE
    // - AVX512_IFMA        need to properly emulate XSAVE/XRESTORE
    // - Processor Trace    no plans to support
    // - AVX512PF           need to properly emulate XSAVE/XRESTORE
    // - AVX512ER           need to properly emulate XSAVE/XRESTORE
    // - AVX512CD           need to properly emulate XSAVE/XRESTORE
    // - SHA                need to properly emulate XSAVE/XRESTORE
    // - AVX512BW           need to properly emulate XSAVE/XRESTORE
    // - AVX512VL           need to properly emulate XSAVE/XRESTORE
    //
    // ECX:
    // - PREFETCHWT1        no plans to support
    // - AVX512_VBMI        need to properly emulate XSAVE/XRESTORE
    // - UMIP               ??? Might be able to support, not sure
    // - PKU                ??? Might be able to support, not sure
    // - OSPKE              ??? Might be able to support, not sure
    // - MAWAU              no plans to support
    // - SGX_LC             no plans to support

    if (info.rcx != 0) {
        info.rax = 0U;
        info.rbx = 0U;
        info.rcx = 0U;
        info.rdx = 0U;
    }

    info.rax = 1U;
    info.rbx &= 0x19C23DBU;
    info.rcx &= 0x0400000U;
    info.rdx = 0U;

    return true;
}

bool
xen_op_handler::cpuid_leaf80000001_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    // Diables the following features:
    //
    // EDX:
    // - 1-GByte Pages      no plans to support

    info.rbx = 0U;
    info.rcx &= 0x121U;
    info.rdx &= 0x18100800U;

    return true;
}

bool
xen_op_handler::xen_cpuid_leaf1_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rax = XEN_CPUID_LEAF(5);
    info.rbx = XEN_CPUID_SIGNATURE_EBX;
    info.rcx = XEN_CPUID_SIGNATURE_ECX;
    info.rdx = XEN_CPUID_SIGNATURE_EDX;

    return true;
}

bool
xen_op_handler::xen_cpuid_leaf2_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rax = 0x00040B00U; // 4.11
    info.rbx = 0U;
    info.rcx = 0U;
    info.rdx = 0U;

    return true;
}

bool
xen_op_handler::xen_cpuid_leaf3_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rax = 1U;
    info.rbx = xen_msr_hypercall_page;
    info.rcx = 0U;
    info.rdx = 0U;

    return true;
}

bool
xen_op_handler::xen_cpuid_leaf5_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rax = 0U;
    info.rax |= XEN_HVM_CPUID_APIC_ACCESS_VIRT;
    // info.rax |= XEN_HVM_CPUID_X2APIC_VIRT;           // Need to support emulated VT-d first
    // info.rax |= XEN_HVM_CPUID_IOMMU_MAPPINGS;        // Need to support emulated VT-d first
    info.rax |= XEN_HVM_CPUID_VCPU_ID_PRESENT;
    info.rax |= XEN_HVM_CPUID_DOMID_PRESENT;
    info.rbx = m_vcpu->lapicid();
    info.rcx = m_vcpu->domid();
    info.rdx = 0U;

    return true;
}

// -----------------------------------------------------------------------------
// IO Instruction
// -----------------------------------------------------------------------------

bool
xen_op_handler::io_zero_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0;
    return true;
}

bool
xen_op_handler::io_ones_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0xFFFFFFFFFFFFFFFF;
    return true;
}

bool
xen_op_handler::io_ignore_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

// -----------------------------------------------------------------------------
// HYPERVISOR_memory_op
// -----------------------------------------------------------------------------

bool
xen_op_handler::HYPERVISOR_memory_op(
    gsl::not_null<vcpu_t *> vcpu)
{
    if (vcpu->rax() != __HYPERVISOR_memory_op) {
        return false;
    }

    switch(vcpu->rdi()) {
        case XENMEM_add_to_physmap:
            this->XENMEM_add_to_physmap_handler(m_vcpu);
            return true;

        case XENMEM_memory_map:
            this->XENMEM_memory_map_handler(m_vcpu);
            return true;

        default:
            break;
    };

    throw std::runtime_error("unknown HYPERVISOR_memory_op opcode");
}

void
xen_op_handler::XENMEM_add_to_physmap_handler(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto xen_add_to_physmap_arg =
            vcpu->map_arg<xen_add_to_physmap>(
                vcpu->rsi()
            );

        if (xen_add_to_physmap_arg->domid != DOMID_SELF) {
            throw std::runtime_error("unsupported domid");
        }

        switch(xen_add_to_physmap_arg->space) {
            case XENMAPSPACE_shared_info:
                m_shared_info =
                    vcpu->map_gpa_4k<shared_info_t>(
                        xen_add_to_physmap_arg->gpfn << ::x64::pt::page_shift
                    );
                this->reset_vcpu_time_info();
                break;

            default:
                throw std::runtime_error("XENMEM_add_to_physmap: unknown space");
        };

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
xen_op_handler::XENMEM_memory_map_handler(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto map = vcpu->map_arg<xen_memory_map>(vcpu->rsi());

        if (map->nr_entries < vcpu->e820_map().size()) {
            throw std::runtime_error("guest E820 too small");
        }

        auto addr = map->buffer.p;
        auto size = map->nr_entries;

        auto e820 = vcpu->map_gva_4k<e820_entry_t>(addr, size);
        auto e820_view = gsl::span<e820_entry_t>(e820.get(), size);

        map->nr_entries = 0;
        for (const auto &entry : vcpu->e820_map()) {
            e820_view[map->nr_entries].addr = entry.addr;
            e820_view[map->nr_entries].size = entry.size;
            e820_view[map->nr_entries].type = entry.type;
            map->nr_entries++;
        }

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

// -----------------------------------------------------------------------------
// HYPERVISOR_xen_version
// -----------------------------------------------------------------------------

bool
xen_op_handler::HYPERVISOR_xen_version(
    gsl::not_null<vcpu_t *> vcpu)
{
    if (vcpu->rax() != __HYPERVISOR_xen_version) {
        return false;
    }

    switch(vcpu->rdi()) {
        case XENVER_get_features:
            this->XENVER_get_features_handler(m_vcpu);
            return true;

        default:
            break;
    };

    throw std::runtime_error("unknown HYPERVISOR_xen_version opcode");
}

void
xen_op_handler::XENVER_get_features_handler(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto info =
            vcpu->map_arg<xen_feature_info>(
                vcpu->rsi()
            );

        if (info->submap_idx >= XENFEAT_NR_SUBMAPS) {
            throw std::runtime_error("unknown Xen features submap");
        }

        info->submap = 0;
        info->submap |= (1 << XENFEAT_writable_page_tables);
        info->submap |= (1 << XENFEAT_writable_descriptor_tables);
        info->submap |= (1 << XENFEAT_auto_translated_physmap);
        info->submap |= (1 << XENFEAT_supervisor_mode_kernel);
        info->submap |= (1 << XENFEAT_pae_pgdir_above_4gb);
        info->submap |= (1 << XENFEAT_mmu_pt_update_preserve_ad);
        info->submap |= (1 << XENFEAT_highmem_assist);
        info->submap |= (1 << XENFEAT_gnttab_map_avail_bits);
        info->submap |= (1 << XENFEAT_hvm_callback_vector);
        info->submap |= (1 << XENFEAT_hvm_safe_pvclock);
        info->submap |= (1 << XENFEAT_hvm_pirqs);
        info->submap |= (1 << XENFEAT_dom0);
        info->submap |= (1 << XENFEAT_memory_op_vnode_supported);
        // info->submap |= (1 << XENFEAT_ARM_SMCCC_supported);
        info->submap |= (1 << XENFEAT_linux_rsdp_unrestricted);
        info->submap |= (1 << XENFEAT_hvm_pirqs);

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

// -----------------------------------------------------------------------------
// HYPERVISOR_hvm_op
// -----------------------------------------------------------------------------

bool
xen_op_handler::HYPERVISOR_hvm_op(
    gsl::not_null<vcpu_t *> vcpu)
{
    if (vcpu->rax() != __HYPERVISOR_hvm_op) {
        return false;
    }

    switch(vcpu->rdi()) {
        case HVMOP_pagetable_dying:
            this->HVMOP_pagetable_dying_handler(m_vcpu);
            return true;

        default:
            break;
    };

    throw std::runtime_error("unknown HYPERVISOR_hvm_op opcode");
}

void
xen_op_handler::HVMOP_pagetable_dying_handler(
    gsl::not_null<vcpu *> vcpu)
{
    bfignored(vcpu);
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

void
xen_op_handler::reset_vcpu_time_info()
{
    expects(m_shared_info);
    m_cpu_frequency = cpu_frequency();

    /// The equation for tsc_to_system_mul is the following:
    /// - tsc_to_system_mul = (10^9 << 32) / (CPU freq Hz)
    ///
    /// This can be found in xen.h. In the vcpu_info page. tsc_shift and
    /// tsc_to_system_mul are related if you work the formula out. As one
    /// increases, the other must decrease, which is used for handling
    /// drifting in time and preventing resolution issues with the TSC.
    /// Since we require an invarinat TSC, this shift is not needed so it is
    /// set to 0.
    ///

    constexpr const uint64_t GHz = 10^9;
    auto &info = m_shared_info->vcpu_info[0].time;

    info.tsc_shift = 0;
    info.tsc_to_system_mul = (GHz << 32) / (m_cpu_frequency * 1000);
    info.flags = XEN_PVCLOCK_TSC_STABLE_BIT;
}

void
xen_op_handler::update_vcpu_time_info()
{
    if (!m_shared_info) {
        return;
    }

    constexpr const uint64_t us = 10^6;
    auto &info = m_shared_info->vcpu_info[0].time;

    // The xen.h comments suggest that we need to flip the version to prevent
    // races, although its not clear what type of races could occur if this
    // information is vCPU specific (since the vCPU that should be reading
    // this is not active while the VMM is modifying the fields). Either way
    // we do it.
    //
    // Note that we do our calculations using MHz and not kHz. The reason is
    // even with a 64bit number, we run the risk of overflowing with kHz.
    // The issue with using MHz is the CPU frequency is cut off, which could
    // result in a small amount of drift, since the CPU frequency likely
    // granularity extends to the kHz level.
    //

    info.version = 1;
    info.tsc_timestamp = ::x64::read_tsc::get();
    info.system_time = (info.tsc_timestamp * 1000) / (m_cpu_frequency / 1000);
    info.version = 0;
}

// -----------------------------------------------------------------------------
// Quirks
// -----------------------------------------------------------------------------

void
xen_op_handler::register_unplug_quirk()
{
    /// Quirk
    ///
    /// At some point, the Linux kernel might attempt to unplug QEMU by
    /// sending port IO requests to it over the port XEN_IOPORT_BASE which
    /// is defined as port 0x10. The problem is, in PVH QEMU doesn't exist,
    /// so there is nobody to send these port IO requests to. Xen itself also
    /// doesn't define these ports, nor does it really understand what they
    /// are (which raises some security concerns). Here we simply ignore
    /// these requests. For more information, see the following:
    ///
    /// http://lkml.iu.edu/hypermail//linux/kernel/1003.0/01368.html
    ///

    constexpr const auto XEN_IOPORT_BASE = 0x10;
    EMULATE_IO_INSTRUCTION(XEN_IOPORT_BASE, io_zero_handler, io_ignore_handler);
}

}
