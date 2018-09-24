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

#include <intrinsics.h>

#include <hve/arch/intel_x64/lapic.h>
#include <hve/arch/intel_x64/fault.h>

//--------------------------------------------------------------------------
// Registers
//--------------------------------------------------------------------------

namespace lapic_id
{
    constexpr const auto indx = (0x020U >> 4);
    constexpr const auto name = "lapic_id";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace lapic_version
{
    constexpr const auto indx = (0x030U >> 4);
    constexpr const auto name = "lapic_version";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace tpr
{
    constexpr const auto indx = (0x080U >> 4);
    constexpr const auto name = "tpr";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace apr
{
    constexpr const auto indx = (0x090U >> 4);
    constexpr const auto name = "apr";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace ppr
{
    constexpr const auto indx = (0x0A0U >> 4);
    constexpr const auto name = "ppr";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace eoi
{
    constexpr const auto indx = (0x0B0U >> 4);
    constexpr const auto name = "eoi";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace rrd
{
    constexpr const auto indx = (0x0C0U >> 4);
    constexpr const auto name = "rrd";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace ldr
{
    constexpr const auto indx = (0x0D0U >> 4);
    constexpr const auto name = "ldr";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace dfr
{
    constexpr const auto indx = (0x0E0U >> 4);
    constexpr const auto name = "dfr";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace siv
{
    constexpr const auto indx = (0x0F0U >> 4);
    constexpr const auto name = "siv";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace isr3100
{
    constexpr const auto indx = (0x100U >> 4);
    constexpr const auto name = "isr3100";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace isr6332
{
    constexpr const auto indx = (0x110U >> 4);
    constexpr const auto name = "isr6332";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace isr9564
{
    constexpr const auto indx = (0x120U >> 4);
    constexpr const auto name = "isr9564";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace isr12796
{
    constexpr const auto indx = (0x130U >> 4);
    constexpr const auto name = "isr12796";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace isr159128
{
    constexpr const auto indx = (0x140U >> 4);
    constexpr const auto name = "isr159128";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace isr191160
{
    constexpr const auto indx = (0x150U >> 4);
    constexpr const auto name = "isr191160";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace isr223192
{
    constexpr const auto indx = (0x160U >> 4);
    constexpr const auto name = "isr223192";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace isr255224
{
    constexpr const auto indx = (0x170U >> 4);
    constexpr const auto name = "isr255224";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace tmr3100
{
    constexpr const auto indx = (0x180U >> 4);
    constexpr const auto name = "tmr3100";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace tmr6332
{
    constexpr const auto indx = (0x190U >> 4);
    constexpr const auto name = "tmr6332";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace tmr9564
{
    constexpr const auto indx = (0x1A0U >> 4);
    constexpr const auto name = "tmr9564";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace tmr12796
{
    constexpr const auto indx = (0x1B0U >> 4);
    constexpr const auto name = "tmr12796";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace tmr159128
{
    constexpr const auto indx = (0x1C0U >> 4);
    constexpr const auto name = "tmr159128";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace tmr191160
{
    constexpr const auto indx = (0x1D0U >> 4);
    constexpr const auto name = "tmr191160";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace tmr223192
{
    constexpr const auto indx = (0x1E0U >> 4);
    constexpr const auto name = "tmr223192";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace tmr255224
{
    constexpr const auto indx = (0x1F0U >> 4);
    constexpr const auto name = "tmr255224";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace irr3100
{
    constexpr const auto indx = (0x200U >> 4);
    constexpr const auto name = "irr3100";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace irr6332
{
    constexpr const auto indx = (0x210U >> 4);
    constexpr const auto name = "irr6332";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace irr9564
{
    constexpr const auto indx = (0x220U >> 4);
    constexpr const auto name = "irr9564";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace irr12796
{
    constexpr const auto indx = (0x230U >> 4);
    constexpr const auto name = "irr12796";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace irr159128
{
    constexpr const auto indx = (0x240U >> 4);
    constexpr const auto name = "irr159128";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace irr191160
{
    constexpr const auto indx = (0x250U >> 4);
    constexpr const auto name = "irr191160";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace irr223192
{
    constexpr const auto indx = (0x260U >> 4);
    constexpr const auto name = "irr223192";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace irr255224
{
    constexpr const auto indx = (0x270U >> 4);
    constexpr const auto name = "irr255224";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace esr
{
    constexpr const auto indx = (0x280U >> 4);
    constexpr const auto name = "esr";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace cmci
{
    constexpr const auto indx = (0x2F0U >> 4);
    constexpr const auto name = "cmci";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace icr3100
{
    constexpr const auto indx = (0x300U >> 4);
    constexpr const auto name = "icr3100";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace icr6332
{
    constexpr const auto indx = (0x310U >> 4);
    constexpr const auto name = "icr6332";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace lvt_timer
{
    constexpr const auto indx = (0x320U >> 4);
    constexpr const auto name = "lvt_timer";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace lvt_thermal_sensor
{
    constexpr const auto indx = (0x330U >> 4);
    constexpr const auto name = "lvt_thermal_sensor";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace lvt_pmc
{
    constexpr const auto indx = (0x340U >> 4);
    constexpr const auto name = "lvt_pmc";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace lvt_lint0
{
    constexpr const auto indx = (0x350U >> 4);
    constexpr const auto name = "lvt_lint0";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace lvt_lint1
{
    constexpr const auto indx = (0x360U >> 4);
    constexpr const auto name = "lvt_lint1";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace lvt_error
{
    constexpr const auto indx = (0x370U >> 4);
    constexpr const auto name = "lvt_error";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace initial_count
{
    constexpr const auto indx = (0x380U >> 4);
    constexpr const auto name = "initial_count";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace current_count
{
    constexpr const auto indx = (0x390U >> 4);
    constexpr const auto name = "current_count";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

namespace divide_config
{
    constexpr const auto indx = (0x3E0U >> 4);
    constexpr const auto name = "divide_config";

    inline auto get(const gsl::span<uint64_t> &view) noexcept
    { return view[indx]; }

    inline void set(gsl::span<uint64_t> &view, uint64_t val) noexcept
    { view[indx] = val; }

    inline void dump(
        int lev, const gsl::span<uint64_t> &view, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(view), msg); }
}

//--------------------------------------------------------------------------
// Implementation
//--------------------------------------------------------------------------

namespace hyperkernel::intel_x64
{

lapic::lapic(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu},
    m_lapic_page{make_page<uint64_t>()},
    m_lapic_view{m_lapic_page.get(), 0x1000}
{ }

void
lapic::init()
{
    auto hpa = g_mm->virtptr_to_physint(m_lapic_page.get());
    m_vcpu->map_4k_ro(this->base(), hpa);

    // Note:
    //
    // The initial state of the APIC is defined in the Intel SDM. It should
    // be noted that we only provide an LVT with 5 entries, as we do not
    // support the PMC or thermal sensor LVT entries.
    //

    lapic_id::set(m_lapic_view, this->id());
    lapic_version::set(m_lapic_view, 0x40010U);
    dfr::set(m_lapic_view, 0xFFFFFFFFU);
    cmci::set(m_lapic_view, 0x10000U);
    lvt_lint0::set(m_lapic_view, 0x10000U);
    lvt_lint1::set(m_lapic_view, 0x10000U);
    lvt_error::set(m_lapic_view, 0x10000U);
    siv::set(m_lapic_view, 0x000000FFU);
}

}