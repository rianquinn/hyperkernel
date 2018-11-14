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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <bfdriverinterface.h>

int g_hkd;

int64_t
platform_init(void)
{
    g_hkd = open("/dev/hkd", O_RDWR);

    if (g_hkd == -1) {
        printf("failed to open /dev/hkd:", strerror(errno));
        return -ENODEV;
    }

    return BF_SUCCESS;
}

void *
platform_alloc_rw(uint64_t len)
{
    return aligned_alloc(0x1000, len);
}

void *
platform_alloc_rwe(uint64_t len)
{
    return aligned_alloc(0x1000, len);
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
