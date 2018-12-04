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
#include <builderinterface.h>

#include <bfdebug.h>
#include <bftypes.h>
#include <bfconstants.h>
#include <bfplatform.h>

/* -------------------------------------------------------------------------- */
/* Misc Device                                                                */
/* -------------------------------------------------------------------------- */

static int
dev_open(struct inode *inode, struct file *file)
{
    (void) inode;
    (void) file;

    BFDEBUG("dev_open succeeded\n");
    return 0;
}

static int
dev_release(struct inode *inode, struct file *file)
{
    (void) inode;
    (void) file;

    BFDEBUG("dev_release succeeded\n");
    return 0;
}

static long
ioctl_load_elf(const struct load_elf_args *args)
{
    // int64_t ret;

    // buf = platform_alloc_rw(g_elf_size);
    // if (buf == NULL) {
    //     BFALERT("IOCTL_ADD_MODULE: failed to allocate memory for the module\n");
    //     return BF_IOCTL_FAILURE;
    // }

    // ret = copy_from_user(buf, file, g_elf_size);
    // if (ret != 0) {
    //     BFALERT("IOCTL_ADD_MODULE: failed to copy memory from userspace\n");
    //     goto failed;
    // }

/**
    ret = common_add_module(buf, g_elf_size);
    if (ret != BF_SUCCESS) {
        BFALERT("IOCTL_ADD_MODULE: common_add_module failed: %p - %s\n", \
                (void *)ret, ec_to_str(ret));
        goto failed;
    }
*/

//     BFDEBUG("IOCTL_ADD_MODULE: succeeded\n");
//     return BF_IOCTL_SUCCESS;

// failed:

//     platform_free_rw(buf, g_elf_size);

    BFALERT("IOCTL_ADD_MODULE: failed\n");
    return BF_IOCTL_FAILURE;
}

static long
dev_unlocked_ioctl(
    struct file *file, unsigned int cmd, unsigned long arg)
{
    (void) file;

    switch (cmd) {
        case IOCTL_LOAD_ELF:
            return ioctl_load_elf((struct load_elf_args *)arg);

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
