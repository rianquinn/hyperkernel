#include <bfvmm/hve/arch/intel_x64/exit_handler.h>
#include <eapis/hve/arch/intel_x64/vcpu.h>
#include <bfvmm/memory_manager/memory_manager.h>
#include <bfvmm/memory_manager/arch/x64/cr3/mmap.h>
#include <bfcallonce.h>

#include "hve/arch/intel_x64/vtd/vtd_sandbox.h"

namespace vtd_sandbox
{
namespace interrupt_remapping
{

intel_x64::vtd::imap g_vtd_imap{};
bfn::once_flag turn_on_remapping_flag{};

using namespace eapis::intel_x64;
namespace vtd = intel_x64::vtd;

// The two interrupt vectors to be remapped to/from each other
static volatile uint64_t g_visr_vector = 0;
static volatile uint64_t g_ndvm_vector = 1;

// The physical bus/device/function the emulated device will occupy
uint64_t g_bus = 0;
uint64_t g_device = 0;
uint64_t g_function = 0;

void
dump_interrupt_remapping()
{
    bfdebug_info(0, "-------------------------------------------");
    bfdebug_info(0, "      VT-d Interrupt Remapping Status");
    bfdebug_info(0, "-------------------------------------------");

    auto irta = vtd::iommu::irta_reg::get();
    vtd::iommu::irta_reg::dump(0, irta);

    intel_x64::vtd::iommu::gsts_reg::dump(0);
    auto irta_size = (2ul << (vtd::iommu::irta_reg::s::get(irta) + 1));
    size_t irt_entry_count = irta_size / sizeof(vtd::irte::value_type);
    bfdebug_subnhex(0, "Interupt remapping table size", irta_size);
    bfdebug_subnhex(0, "Interupt remapping table entry count", irt_entry_count);

    auto irt_base_virt = reinterpret_cast<uintptr_t>(0x104000UL);
    auto irt_base_phys = reinterpret_cast<uintptr_t>(irta & 0xFFFFFFFFFFFFF000UL);
    g_cr3->map_4k(irt_base_virt, irt_base_phys);
    auto irt = gsl::make_span(
        reinterpret_cast<vtd::irte::value_type *>(irt_base_virt),
        static_cast<long>(irt_entry_count)
    );

    uint64_t index = 0;
    bfdebug_info(0, "-------------------------------------------");
    bfdebug_info(0, "      VT-d Interrupt Remapping Table");
    bfdebug_info(0, "-------------------------------------------");
    for (auto &irte : irt) {
        if (vtd::irte::p::is_enabled(irte)) {
            bfdebug_nhex(0, "Interupt Remapping Table Entry At Index:", index);
            vtd::irte::dump(0, irte);
        }
        index++;
    }
}

void
turn_on_interrupt_remapping()
{
    bfn::call_once(turn_on_remapping_flag, [&] {
        // If the VT-d intrinsics aren't set up yet, do it here for now
        // (the intrinsics still need to be re-worked so this isn't necessary)
        if(!intel_x64::vtd::iommu::base_addr) {
            auto iommu_base_virt = reinterpret_cast<uintptr_t>(0x100000UL);
            g_cr3->map_4k(
                iommu_base_virt,
                vtd_sandbox::iommu_base_phys,
                bfvmm::x64::cr3::mmap::attr_type::read_write,
                bfvmm::x64::cr3::mmap::memory_type::uncacheable
            );
            intel_x64::vtd::iommu::base_addr = iommu_base_virt;
            // bfdebug_subnhex(0, "Interrupt remapping unit virtual", iommu_base_virt);
            // bfdebug_subnhex(0, "Interrupt remapping unit physical", vtd_sandbox::iommu_base_phys);
        }

        if (intel_x64::vtd::iommu::gsts_reg::ires::is_enabled()) {
            bfalert_info(0, "WARNING: Interrupt remapping is already enabled.");
            bfalert_info(0, "Dumping remapping tables and configuration without enabling");
        }
        else {
            bfdebug_info(0, "Enabling VT-d interrupt remapping:");
            bfdebug_subnhex(0, "Interrupts destined for NDVM IDT vector...", g_ndvm_vector);
            bfdebug_subnhex(0, "will be redirected to VISR at vector:", g_visr_vector);
            // -------------------------------------------------------------------------
            // Set up interrupt remapping table
            // -------------------------------------------------------------------------
            bfdebug_info(0, "Setting up interrupt remapping table");
            g_vtd_imap.init();
            // TODO: Lookup the NIC's programed IRT index, or figure out how to program it
            // TODO: Figure out the correct destination xAPIC id
            g_vtd_imap.remap_interrupt(7, g_visr_vector, 1);
            bfdebug_info(0, "done");

            auto gsts_reg_val = ::intel_x64::vtd::iommu::gsts_reg::get();

            // -------------------------------------------------------------------------
            // Set the interrupt remapping table pointer
            // -------------------------------------------------------------------------
            bfdebug_info(0, "Setting interrupt remapping table pointer...");
            auto irta_value = g_vtd_imap.phys_addr();
            intel_x64::vtd::iommu::irta_reg::eime::disable(irta_value);
            intel_x64::vtd::iommu::irta_reg::s::set(irta_value, 0x9);
            intel_x64::vtd::iommu::irta_reg::set(irta_value);
            // intel_x64::vtd::iommu::irta_reg::dump(0, irta_value);

            gsts_reg_val = ::intel_x64::vtd::iommu::gsts_reg::get();
            gsts_reg_val = gsts_reg_val & 0x96FFFFFF;
            intel_x64::vtd::iommu::gcmd_reg::sirtp::enable();
            intel_x64::vtd::iommu::gcmd_reg::set(gsts_reg_val);
            while(1) {
                volatile auto keep_waiting = intel_x64::vtd::iommu::gsts_reg::irtps::is_disabled();
                if (!keep_waiting) break;
                bfdebug_info(0, "... waiting on interrupt remapping table pointer status bit ...");
            }
            bfdebug_info(0, "done");

            // -------------------------------------------------------------------------
            // Enable Interrupt compatibility mode
            // -------------------------------------------------------------------------
            bfdebug_info(0, "Enabling interrupt compatibility mode...");
            gsts_reg_val = ::intel_x64::vtd::iommu::gsts_reg::get();
            gsts_reg_val = gsts_reg_val & 0x96FFFFFF;
            intel_x64::vtd::iommu::gcmd_reg::cfi::enable(gsts_reg_val);
            intel_x64::vtd::iommu::gcmd_reg::set(gsts_reg_val);
            while(1) {
                volatile auto keep_waiting = intel_x64::vtd::iommu::gsts_reg::cfis::is_disabled();
                if (!keep_waiting) break;
                bfdebug_info(0, "... waiting on interrupt compatibility enable status bit ...");
            }
            bfdebug_info(0, "done");

            // -------------------------------------------------------------------------
            // Enable Interrupt remapping
            // -------------------------------------------------------------------------
            bfdebug_info(0, "Enabling interrupt remapping...");
            gsts_reg_val = ::intel_x64::vtd::iommu::gsts_reg::get();
            gsts_reg_val = gsts_reg_val & 0x96FFFFFF;
            intel_x64::vtd::iommu::gcmd_reg::ire::enable(gsts_reg_val);
            intel_x64::vtd::iommu::gcmd_reg::set(gsts_reg_val);
            while(1) {
                volatile auto keep_waiting = intel_x64::vtd::iommu::gsts_reg::ires::is_disabled();
                if (!keep_waiting) break;
                bfdebug_info(0, "... waiting on interrupt remapping enable status bit ...");
            }
            bfdebug_info(0, "done");

            // -------------------------------------------------------------------------
            // Check fault recording to see if we messed anything up
            // -------------------------------------------------------------------------
            for (auto i = 0; i < 1000000; i++) {
                if(intel_x64::vtd::iommu::fsts_reg::ppf::is_enabled()) {
                    printf("\n");
                    bferror_info(0, "Fault occurred during interrupt remapping initialization:");
                    intel_x64::vtd::iommu::frr::dump(0);
                    return;
                }
            }
        }

        dump_interrupt_remapping();
    });
}

bool
receive_vector_from_ndvm(
    gsl::not_null<vcpu_t *> vcpu,
    cpuid_handler::info_t &info
)
{
    bfignored(vcpu);
    bfignored(info);

    g_ndvm_vector = vcpu->rcx();
    bfdebug_nhex(0, "Recieved vector from NDVM:", g_ndvm_vector);
    
    if(g_visr_vector != 0 && g_ndvm_vector != 0) {
        turn_on_interrupt_remapping();
    }

    return true;
}

bool
receive_vector_from_windows(
    gsl::not_null<vcpu_t *> vcpu,
    cpuid_handler::info_t &info
)
{
    bfignored(vcpu);
    bfignored(info);

    g_visr_vector = vcpu->rcx();
    bfdebug_nhex(0, "Recieved vector from VISR driver:", g_visr_vector);
    
    if(g_visr_vector != 0 && g_ndvm_vector != 0) {
        turn_on_interrupt_remapping();
    }

    return true;
}

bool
windows_test_interrupt_inject(
    gsl::not_null<vcpu_t *> vcpu,
    cpuid_handler::info_t &info
)
{
    bfignored(vcpu);
    bfignored(info);

    auto my_vcpu = vcpu_cast(vcpu);
    my_vcpu->queue_external_interrupt(g_visr_vector);
    bfdebug_info(0, "VISR requested an interrupt test, injecting to hardware domain now");

    return true;
}

bool
windows_isr_ack(
    gsl::not_null<vcpu_t *> vcpu,
    cpuid_handler::info_t &info
)
{
    bfignored(vcpu);
    bfignored(info);

    bfdebug_info(0, "The VISR interrupt service routine ran!");
    bfdebug_info(0, "TODO: \"un-remap\" the interrupt by injecting it into the NDVM");

    // TODO: "Un-remap" the interrupt by injecting it into the NDVM
    // auto ndvm_vcpu = ?;
    // ndvm_vcpu->queue_external_interrupt(g_ndvm_vector);

    return true;
}

bool
handle_cfc_in(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return false;
}

bool
handle_cfc_out(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    auto cf8 = ::x64::portio::ind(0xCF8);
    auto reg_number = (cf8 & 0x000000FC) >> 2U;
    auto emulate_addr = 0x80000000U | (g_bus << 16U) | (g_device << 11U) | (g_function << 8U);
    auto next_addr = 0x80000000U | (g_bus << 16U) | (g_device << 11U) | ((g_function + 1) << 8U);

    if ((emulate_addr <= cf8) && (cf8 < next_addr)) {
        if(reg_number == 0x08) {
            // bfdebug_nhex(0, "Windows-assigned MSI-X BAR for Realtek NIC:", info.val);
        }
    }

    return false;
}

bfn::once_flag init_flag{};

void
enable(
    gsl::not_null<eapis::intel_x64::vcpu *> vcpu,
    uint64_t bus,
    uint64_t device,
    uint64_t function
)
{
    g_bus = bus;
    g_device = device;
    g_function = function;

    vcpu->emulate_cpuid(
        0xd00dfeed,
        cpuid_handler::handler_delegate_t::create<receive_vector_from_ndvm>()
    );

    vcpu->emulate_cpuid(
        0xf00dbeef,
        cpuid_handler::handler_delegate_t::create<receive_vector_from_windows>()
    );

    vcpu->emulate_cpuid(
        0xdeadbeef,
        cpuid_handler::handler_delegate_t::create<windows_test_interrupt_inject>()
    );

    vcpu->emulate_cpuid(
        0xcafebabe,
        cpuid_handler::handler_delegate_t::create<windows_isr_ack>()
    );

    vcpu->add_io_instruction_handler(
        0xCFC,
        io_instruction_handler::handler_delegate_t::create <handle_cfc_in>(),
        io_instruction_handler::handler_delegate_t::create <handle_cfc_out>()
    );
}

}
}
