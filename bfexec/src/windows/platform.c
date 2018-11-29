/**
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

#include <bfdebug.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>

extern uint64_t g_ram_size;

/* -------------------------------------------------------------------------- */
/* Internal helpers                                                           */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/* API implementation                                                         */
/* -------------------------------------------------------------------------- */

int64_t platform_init(void)
{
    BOOL ret =
        SetProcessWorkingSetSize(
            GetCurrentProcess(),
            g_ram_size + 0x50000,
            g_ram_size + 0x100000
        );

    assert(ret);
    return 0;
}

void *
platform_alloc_rw(uint64_t len)
{
    void *addr;

    addr = aligned_alloc(0x1000, len);
    if (addr == 0) {
        BFALERT("platform_alloc_rw failed\n");
        return 0;
    }

    // if (!VirtualLock(addr, len)) {
    //     free(addr);

    //     BFALERT("VirtualLock failed\n");
    //     return 0;
    // }

    return addr;
}

void *
platform_alloc_rwe(uint64_t len)
{
    /**
     * bfexec doesn't actually execute any code, so we can safely ignore
     * the "e" bit here and just return "rw"
     */
    return platform_alloc_rw(len);
}

void
platform_free_rw(void *addr, uint64_t len)
{
    bfignored(len);
    free(addr);
}

void
platform_free_rwe(void *addr, uint64_t len)
{
    bfignored(len);
    free(addr);
}

void *
platform_memset(void *ptr, char value, uint64_t num)
{ return memset(ptr, value, num); }

void *
platform_memcpy(void *dst, const void *src, uint64_t num)
{ return memcpy(dst, src, num); }
