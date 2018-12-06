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

#include <bfelf_loader.h>

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/mman.h>

#include <hypercall.h>
#include <gpa_layout.h>

#include <hve/arch/intel_x64/xen/public/xen.h>
#include <hve/arch/intel_x64/xen/public/elfnote.h>

#include "xen/start_info.h"
#include "xen/elf_note.h"

extern int is_xen_elf_note(const char *buf);
extern void print_xen_elf_note(const struct xen_elf_note *note);

// Notes:
//
// - Currently on one vCPU is supported. This code is written using threading
//   so adding support for more than one vCPU should be simple once the
//   hyperkernel supports this. Just create more vCPU threads
//
// - Currently this code doesn't handle when the VM wishes to go to sleep
//   by calling "hlt". Once the hyperkernel supports this, we will need to
//   add support for this application to wait on a kernel event. The only
//   way to wake up from "hlt" is to interrupt the CPU. Such and interrupt
//   will either have to come from an external interrupt, or it will have to
//   come from a timer interrupt. Either way, execution doesn't need to
//   continue until an event occurs, which we will have to add support for.
//
// - Currently, we do not support VMCS migration, which means we have to
//   set the affinity of bfexec. At some point, we need to implement
//   VMCS migration so that we can support executing from any core, at any
//   time.
//

#define alloc_page() platform_memset(platform_alloc_rwe(0x1000), 0, 0x1000);
#define alloc_buffer(sz) platform_memset(platform_alloc_rwe((sz)), 0, (sz));

/* -------------------------------------------------------------------------- */
/* VM                                                                         */
/* -------------------------------------------------------------------------- */


/* -------------------------------------------------------------------------- */
/* Ack                                                                        */
/* -------------------------------------------------------------------------- */

uint32_t _cpuid_eax(uint32_t val) NOEXCEPT;

/* -------------------------------------------------------------------------- */
/* Signal Handling                                                            */
/* -------------------------------------------------------------------------- */

#include <signal.h>

void
kill_signal_handler(void)
{
    status_t ret;

    BFINFO("\n");
    BFINFO("\n");
    BFINFO("killing VM: %" PRId64 "\n", g_vm.domainid);

    ret = __vcpu_op__hlt_vcpu(g_vm.vcpuid);
    if (ret != SUCCESS) {
        BFALERT("__vcpu_op__hlt_vcpu failed\n");
        return;
    }

    return;
}

void
sig_handler(int sig)
{
    bfignored(sig);
    kill_signal_handler();
    return;
}

void
setup_kill_signal_handler(void)
{
    signal(SIGINT, sig_handler);
    signal(SIGQUIT, sig_handler);
    signal(SIGTERM, sig_handler);
}

/* -------------------------------------------------------------------------- */
/* Domain Functions                                                           */
/* -------------------------------------------------------------------------- */

status_t
vcpu_op__create_vcpu(void)
{
    status_t ret;

    g_vm.vcpuid = __vcpu_op__create_vcpu(g_vm.domainid);
    if (g_vm.vcpuid == INVALID_VCPUID) {
        BFALERT("__vcpu_op__create_vcpu failed\n");
        return FAILURE;
    }


    ret = __vcpu_op__set_rip(g_vm.vcpuid, (uint64_t)g_vm.entry);
    if (ret != SUCCESS) {
        BFALERT("__vcpu_op__set_rip failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

void *
vcpu_op__run_vcpu(void *arg)
{
    status_t ret;
    bfignored(arg);

    while (1) {
        ret = __vcpu_op__run_vcpu(g_vm.vcpuid);
        switch(vcpu_run_code(ret)) {
            case SUCCESS:
                return 0;

            case FAILURE:
                BFALERT("__vcpu_op__run_vcpu failed\n");
                exit(-1);
                return 0;

            case VCPU_OP__RUN_CONTINUE:
                continue;

            case VCPU_OP__RUN_SLEEP:
                usleep(vcpu_sleep_usec(ret));
                continue;

            default:
                BFALERT("unknown run_vcpu return code: %d\n", ret);
                return 0;
        }
    }
}

status_t
vcpu_op__destroy_vcpu(void)
{
    status_t ret;

    ret = __vcpu_op__destroy_vcpu(g_vm.vcpuid);
    if (ret != SUCCESS) {
        BFALERT("__vcpu_op__destroy_vcpu failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* Threading                                                                  */
/* -------------------------------------------------------------------------- */

#include <pthread.h>

void
start_run_thread()
{ pthread_create(&g_vm.run_thread, 0, vcpu_op__run_vcpu, 0); }

/* -------------------------------------------------------------------------- */
/* Memory Layout                                                              */
/* -------------------------------------------------------------------------- */


typedef union {
    hvm_start_info start_info;
    char pad[0x1000];
} reserved_4000_t;

typedef struct {
    char cmdline[0x1000];
} reserved_5000_t;

typedef struct {
    char shared_info_page[0x1000];
} reserved_6000_t;

typedef struct {
    char console[0x1000];
} reserved_7000_t;

typedef struct {
    char store[0x1000];
} reserved_8000_t;

#ifndef REAL_MODE_SIZE
#define REAL_MODE_SIZE (6 * 0x1000)
#endif

typedef struct {
    char rm_trampoline[REAL_MODE_SIZE];
} reserved_A000_t;

reserved_4000_t *g_reserved_4000 = 0;   /* Xen start info */
reserved_5000_t *g_reserved_5000 = 0;   /* Xen cmdline */
reserved_6000_t *g_reserved_6000 = 0;   /* Xen shared info page */
reserved_7000_t *g_reserved_7000 = 0;   /* Xen console */
reserved_8000_t *g_reserved_8000 = 0;   /* Xen store */
reserved_A000_t *g_reserved_A000 = 0;   /* Real-mode trampoline */

// TODO: this should be a setting that is filled in from the command line.

void *g_zero_page;



/* -------------------------------------------------------------------------- */
/* Main                                                                       */
/* -------------------------------------------------------------------------- */

int
main(int argc, const char *argv[])
{


    /**
     * Note that affinity *must* be set before any VM-bound resources are
     * allocated. Failure to do so can (and will) result in the kernel mapping
     * in memory on a core that is different from the one bareflank maps on. In
     * this case, bareflank's mmap will walk an invalid CR3, resulting in (at
     * best) an EPT violation when the guest starts to run.
     */

    setup_kill_signal_handler();
    platform_init();

    ret = domain_op__create_domain();
    if (ret != SUCCESS) {
        BFALERT("create_domain failed\n");
        return EXIT_FAILURE;
    }

    ret = setup_e820_map();
    if (ret != SUCCESS) {
        BFALERT("setup_e820_map failed\n");
        goto CLEANUP_VCPU;
    }

    ret = binary_read(argv[1]);
    if (ret != SUCCESS) {
        BFALERT("read_binary failed\n");
        goto CLEANUP_DOMAIN;
    }

    ret = binary_load();
    if (ret != SUCCESS) {
        BFALERT("load_binary failed\n");
        goto CLEANUP_DOMAIN;
    }

    ret = set_vm_entry(&g_vm.bfelf_binary, (uintptr_t *)&g_vm.entry);
    if (ret != SUCCESS) {
        BFALERT("set_vm_entry failed\n");
        return EXIT_FAILURE;
    }

    ret = vcpu_op__create_vcpu();
    if (ret != SUCCESS) {
        BFALERT("create_vcpu failed\n");
        goto CLEANUP_DOMAIN;
    }

    ret = setup_xen_start_info();
    if (ret != SUCCESS) {
        BFALERT("setup_xen_start_info failed\n");
        goto CLEANUP_VCPU;
    }

    ret = setup_xen_cmdline();
    if (ret != SUCCESS) {
        BFALERT("setup_xen_cmdline failed\n");
        goto CLEANUP_VCPU;
    }

    ret = setup_xen_shared_info_page();
    if (ret != SUCCESS) {
        BFALERT("setup_xen_shared_info_page failed\n");
        goto CLEANUP_VCPU;
    }

    ret = setup_xen_console();
    if (ret != SUCCESS) {
        BFALERT("setup_xen_console failed\n");
        goto CLEANUP_VCPU;
    }

    ret = setup_xen_store();
    if (ret != SUCCESS) {
        BFALERT("setup_xen_store failed\n");
        goto CLEANUP_VCPU;
    }

    ret = setup_rm_trampoline();
    if (ret != SUCCESS) {
        BFALERT("setup_rm_trampoline failed\n");
        goto CLEANUP_VCPU;
    }

    ret = setup_xen_disabled();
    if (ret != SUCCESS) {
        BFALERT("setup_xen_disabled failed\n");
        goto CLEANUP_VCPU;
    }

    start_run_thread();
    pthread_join(g_vm.run_thread, 0);

CLEANUP_VCPU:

    ret = vcpu_op__destroy_vcpu();
    if (ret != SUCCESS) {
        BFALERT("destroy_vcpu failed\n");
    }

CLEANUP_DOMAIN:

    ret = domain_op__destroy_domain();
    if (ret != SUCCESS) {
        BFALERT("destroy_domain failed\n");
    }

    return EXIT_SUCCESS;
}
