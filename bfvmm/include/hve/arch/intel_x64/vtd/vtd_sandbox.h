#ifndef VTD_SANDBOX_H
#define VTD_SANDBOX_H

#include "mmap.h"
#include "imap.h"

namespace vtd_sandbox
{

inline uintptr_t iommu_base_phys = 0xfed91000;     // Gigabyte and Surface Pro
// inline uintptr_t iommu_base_phys = 0xfec10000;     // VMware Fusion

namespace hidden_nic
{
    // Realtek Semiconductor RTL8111/8168/8411 PCI Express Gigabit Ethernet Controller
    inline uint32_t vendor_device = 0x816810EC;

    void enable(gsl::not_null<eapis::intel_x64::vcpu *> vcpu);
}

namespace visr_device
{
    void enable(gsl::not_null<eapis::intel_x64::vcpu *> vcpu);
}

namespace dma_remapping
{
    void init(
        gsl::not_null<eapis::intel_x64::vcpu *> vcpu,
        eapis::intel_x64::ept::mmap &hdvm_ept_mmap,
        eapis::intel_x64::ept::mmap &ndvm_ept_mmap
    );
}

namespace interrupt_remapping
{
    void enable(gsl::not_null<eapis::intel_x64::vcpu *> vcpu);
}

}

#endif
