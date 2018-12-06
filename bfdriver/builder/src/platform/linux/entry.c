/*
 * Bareflank Hypervisor
 * Copyright (C) 2015 Assured Information Security, Inc.
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

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>

#include <common.h>
#include <bfbuilderinterface.h>

#include <bfdebug.h>
#include <bftypes.h>
#include <bfconstants.h>
#include <bfplatform.h>

#define MAX_VMS 0x1000
struct vm_t g_vms[MAX_VMS] = {0};

/* -------------------------------------------------------------------------- */
/* Misc Device                                                                */
/* -------------------------------------------------------------------------- */

static int
dev_open(struct inode *inode, struct file *file)
{
    BFDEBUG("dev_open succeeded\n");
    return 0;
}

static int
dev_release(struct inode *inode, struct file *file)
{
    BFDEBUG("dev_release succeeded\n");
    return 0;
}

static long
ioctl_create_from_elf(const struct create_from_elf_args *args)
{
    int64_t i;
    int64_t ret;
    struct vm_t *vm;
    struct create_from_elf_args user_ioctl_args;
    struct create_from_elf_args kern_ioctl_args;

    for (i = 0; i < MAX_VMS; i++) {
        vm = &g_vms[i];
        if (vm->used == 0) {
            break;
        }
    }

    if (i == MAX_VMS) {
        BFALERT("MAX_VMS reached. No more VMs can be created\n");
        return BF_IOCTL_FAILURE;
    }

    ret = copy_from_user(
        &user_ioctl_args, args, sizeof(struct create_from_elf_args));
    if (ret != 0) {
        BFALERT("IOCTL_CREATE_FROM_ELF: failed to copy args from userspace\n");
        return BF_IOCTL_FAILURE;
    }

    ret = copy_from_user(
        &kern_ioctl_args, args, sizeof(struct create_from_elf_args));
    if (ret != 0) {
        BFALERT("IOCTL_CREATE_FROM_ELF: failed to copy args from userspace\n");
        return BF_IOCTL_FAILURE;
    }

    kern_ioctl_args.file = platform_alloc_rw(user_ioctl_args.file_size);
    if (kern_ioctl_args.file == NULL) {
        BFALERT("IOCTL_CREATE_FROM_ELF: failed to allocate memory for file\n");
        goto failed;
    }

    kern_ioctl_args.cmdl = platform_alloc_rw(user_ioctl_args.cmdl_size);
    if (kern_ioctl_args.cmdl == NULL) {
        BFALERT("IOCTL_CREATE_FROM_ELF: failed to allocate memory for file\n");
        goto failed;
    }

    ret = copy_from_user(
        (void *)kern_ioctl_args.file, user_ioctl_args.file, user_ioctl_args.file_size);
    if (ret != 0) {
        BFALERT("IOCTL_CREATE_FROM_ELF: failed to copy file from userspace\n");
        goto failed;
    }

    ret = copy_from_user(
        (void *)kern_ioctl_args.cmdl, user_ioctl_args.cmdl, user_ioctl_args.cmdl_size);
    if (ret != 0) {
        BFALERT("IOCTL_CREATE_FROM_ELF: failed to copy cmdl from userspace\n");
        goto failed;
    }

    ret = common_create_from_elf(vm, &kern_ioctl_args);
    if (ret != BF_SUCCESS) {
        BFDEBUG("common_create_from_elf failed: %llx\n", ret);
        goto failed;
    }

    platform_free_rw((void *)kern_ioctl_args.file, kern_ioctl_args.file_size);
    platform_free_rw((void *)kern_ioctl_args.cmdl, kern_ioctl_args.cmdl_size);

    BFDEBUG("IOCTL_CREATE_FROM_ELF: succeeded\n");
    return BF_IOCTL_SUCCESS;

failed:

    platform_free_rw((void *)kern_ioctl_args.file, kern_ioctl_args.file_size);
    platform_free_rw((void *)kern_ioctl_args.cmdl, kern_ioctl_args.cmdl_size);

    BFALERT("IOCTL_CREATE_FROM_ELF: failed\n");
    return BF_IOCTL_FAILURE;
}

static long
ioctl_destroy(const domainid_t *args)
{
    int64_t i;
    int64_t ret;
    struct vm_t *vm;
    domainid_t domainid;

    ret = copy_from_user(&domainid, args, sizeof(domainid_t));
    if (ret != 0) {
        BFALERT("IOCTL_DESTROY: failed to copy args from userspace\n");
        return BF_IOCTL_FAILURE;
    }

    for (i = 0; i < MAX_VMS; i++) {
        vm = &g_vms[i];
        if (vm->used == 1 && vm->domainid == domainid) {
            break;
        }
    }

    if (i == MAX_VMS) {
        BFALERT("MAX_VMS reached. Unable to locate VM\n");
        return BF_IOCTL_FAILURE;
    }

    ret = common_destroy(vm);
    if (ret != BF_SUCCESS) {
        BFDEBUG("common_destroy failed: %llx\n", ret);
        return BF_IOCTL_FAILURE;
    }

    BFDEBUG("IOCTL_DESTROY: succeeded\n");
    return BF_IOCTL_SUCCESS;
}

static long
dev_unlocked_ioctl(
    struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
        case IOCTL_CREATE_FROM_ELF_CMD:
            return ioctl_create_from_elf((struct create_from_elf_args *)arg);

        case IOCTL_DESTROY_CMD:
            return ioctl_destroy((domainid_t *)arg);

        default:
            return -EINVAL;
    }
}

static struct file_operations fops = {
    .open = dev_open,
    .release = dev_release,
    .unlocked_ioctl = dev_unlocked_ioctl
};

static struct miscdevice builder_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = BUILDER_NAME,
    .fops = &fops,
    .mode = 0666
};

/* -------------------------------------------------------------------------- */
/* Entry / Exit                                                               */
/* -------------------------------------------------------------------------- */

int
dev_init(void)
{
    if (misc_register(&builder_dev) != 0) {
        BFALERT("misc_register failed\n");
        return -EPERM;
    }

    BFDEBUG("dev_init succeeded\n");
    return 0;
}

void
dev_exit(void)
{
    misc_deregister(&builder_dev);

    BFDEBUG("dev_exit succeeded\n");
    return;
}

module_init(dev_init);
module_exit(dev_exit);

MODULE_LICENSE("GPL");
