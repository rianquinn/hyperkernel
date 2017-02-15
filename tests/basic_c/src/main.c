/*
 * Bareflank Hyperkernel
 *
 * Copyright (C) 2015 Assured Information Security, Inc.
 * Author: Rian Quinn        <quinnr@ainfosec.com>
 * Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#include <stdio.h>
#include <stdlib.h>

uint64_t __read_tsc(void);
uint64_t __read_tscp(void);

int
main(int argc, const char *argv[])
{
    (void) argc;
    (void) argv;

    int i, l;
    char *page = (char *)0x0000000100004000UL;

    uint64_t stsc;
    uint64_t etsc;

    stsc = __read_tsc();

    for (l = 0; l < 100000; l++)
        for (i = 0; i < 4096; i++)
            page[i]++;

    etsc = __read_tscp();

    printf("time: %ld\n", etsc - stsc);
    return 0;
}
