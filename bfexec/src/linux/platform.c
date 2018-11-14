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

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <bfdriverinterface.h>

#ifndef MMAP_CAPACITY
#define MMAP_CAPACITY 16
#endif

/* -------------------------------------------------------------------------- */
/* Global data                                                                */
/* -------------------------------------------------------------------------- */

int g_hkd;
int g_mmap_size;
struct hkd_mmap *g_mmap[MMAP_CAPACITY];

/* -------------------------------------------------------------------------- */
/* Internal helpers                                                           */
/* -------------------------------------------------------------------------- */

static struct hkd_mmap *mmap_init(uint64_t len, int prot)
{
    struct hkd_mmap *mm = malloc(sizeof(struct hkd_mmap));

    if (!mm) {
        return NULL;
    }

    mm->size = len;
    mm->prot = prot;
    mm->flags = 0;

    return mm;
}

static struct hkd_mmap *mmap_init_rw(uint64_t len)
{
    return mmap_init(len, PROT_READ | PROT_WRITE);
}

static struct hkd_mmap *mmap_init_rwe(uint64_t len)
{
    return mmap_init(len, PROT_READ | PROT_WRITE | PROT_EXEC);
}

/* -------------------------------------------------------------------------- */
/* API implementation                                                         */
/* -------------------------------------------------------------------------- */

int64_t platform_init(void)
{
    g_hkd = open("/dev/hkd", O_RDWR);
    if (g_hkd == -1) {
        printf("failed to open /dev/hkd:", strerror(errno));
        return -ENODEV;
    }

    g_mmap_size = 0;
    return BF_SUCCESS;
}

void *
platform_alloc_rw(uint64_t len)
{
    if (g_mmap_size >= MMAP_CAPACITY) {
        return NULL;
    }

    struct hkd_mmap *mm = mmap_init_rw(len);
    if (!mm) {
        return NULL;
    }

    g_mmap[g_mmap_size++] = mm;

    int ret = ioctl(g_hkd, IOCTL_MMAP, mm);
    if (ret < 0) {
        free(mm);
        return NULL;
    }

    return mm;
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
