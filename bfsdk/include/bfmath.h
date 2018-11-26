/*
 * Bareflank Hyperkernel
 * Copyright (C) 2018 Assured Information Security, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef HYPERKERNEL_BFMATH_H
#define HYPERKERNEL_BFMATH_H

#include <bftypes.h>

constexpr auto is_power_of_2(size_t n)
{ return (n > 0) && ((n & (n - 1)) == 0); }

constexpr auto next_power_of_2(size_t n)
{
    while (!is_power_of_2(n)) {
        n++;
    }
    return n;
}

constexpr auto log2(const size_t n)
{
    for (auto i = 0; i < 64; i++) {
        if (((1ULL << i) & n) == n) {
            return i;
        }
    }
}

#endif
