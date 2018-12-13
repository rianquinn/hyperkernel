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

#ifndef UART_INTEL_X64_HYPERKERNEL_H
#define UART_INTEL_X64_HYPERKERNEL_H

#include <bfgsl.h>
#include <bftypes.h>

#include <deque>

#include <eapis/hve/arch/intel_x64/vcpu.h>
#include <eapis/hve/arch/intel_x64/vmexit/io_instruction.h>

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

class EXPORT_HYPERKERNEL_HVE uart
{
public:

    using port_type = uint16_t;
    using data_type = uint8_t;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu associated with this uart
    ///
    /// @cond
    ///
    explicit uart(
        gsl::not_null<vcpu *> vcpu, port_type port);

    /// @endcond

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~uart() = default;

    /// Enable
    ///
    /// Enables the emulation of the UART. When this is enabled, the UART
    /// becomes active, presenting itself as present and capable of recording
    /// string data.
    ///
    /// @expects
    /// @ensures
    ///
    void enable();

    /// Pass-Through
    ///
    /// Instead of emulating the UART, this will cause the UART to be passed
    /// through to the guest, physically giving the guest the device. Special
    /// care should be used when enabling this feature as the guest will own
    /// the device and be externally accessible.
    ///
    /// @expects
    /// @ensures
    ///
    void pass_through();

private:

    bool io_zero_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool io_ignore_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);

    bool reg0_in_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg1_in_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg2_in_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg3_in_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg4_in_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg5_in_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);

    bool reg0_out_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg1_out_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg2_out_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg3_out_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg4_out_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg5_out_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);

    bool dlab() const
    { return m_line_control_register & 0x80; }

private:

    vcpu *m_vcpu;
    port_type m_port;

    bool m_enabled{};
    std::deque<data_type> m_buffer;

    data_type m_baud_rate_l{};
    data_type m_baud_rate_h{};
    data_type m_line_control_register{};

};

}

#endif
