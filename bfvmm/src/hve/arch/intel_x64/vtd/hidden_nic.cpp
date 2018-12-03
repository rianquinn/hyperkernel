#include <bfvmm/hve/arch/intel_x64/exit_handler.h>
#include <eapis/hve/arch/intel_x64/vcpu.h>

#include "hve/arch/intel_x64/vtd/vtd_sandbox.h"

namespace vtd_sandbox
{
namespace hidden_nic
{

using namespace eapis::intel_x64;

bool
handle_cfc_in(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    info.val = ::x64::portio::ind(0xCFC);
    if (info.val == vendor_device) {
        info.val = 0xffffffffffffffff;
        return true;
    }

    return false;
}

bool
handle_cfc_out(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);
    // ::x64::portio::outd(0xCFC, gsl::narrow_cast<uint32_t>(info.val));
    return false;
}

void
enable(gsl::not_null<eapis::intel_x64::vcpu *> vcpu)
{
    vcpu->add_io_instruction_handler(
        0xCFC,
        io_instruction_handler::handler_delegate_t::create <handle_cfc_in>(),
        io_instruction_handler::handler_delegate_t::create <handle_cfc_out>()
    );

    // bfdebug_info(0, "Hidden NIC initialized");

}

}
}
