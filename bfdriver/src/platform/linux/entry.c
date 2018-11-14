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

#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#include <bfdriverinterface.h>

/* -------------------------------------------------------------------------- */
/* Global                                                                     */
/* -------------------------------------------------------------------------- */

#define MMAP_FLAGS \
    (MAP_POPULATE  | /* pre-fault associated page table entries */ \
     MAP_LOCKED    | /* don't page out to disk */ \
     MAP_PRIVATE   | /* keep changes private */ \
     MAP_ANONYMOUS   /* don't use a file */ )

/* -------------------------------------------------------------------------- */
/* Misc Device                                                                */
/* -------------------------------------------------------------------------- */

static int
dev_open(struct inode *inode, struct file *file)
{
    (void) inode;
    (void) file;

    BFDEBUG("hkd: dev_open succeeded\n");
    return 0;
}

static int
dev_release(struct inode *inode, struct file *file)
{
    (void) inode;
    (void) file;

    BFDEBUG("hkd: dev_release succeeded\n");
    return 0;
}

static long
ioctl_map_memory(struct hkd_mmap *user_mmap)
{
    int32_t err;
    uint64_t addr;
    struct hkd_mmap mmap;

    if (!user_mmap) {
        BFALERT("hkd: IOCTL_MAP_MEMORY: failed with user_mmap == NULL\n");
        return BF_IOCTL_FAILURE;
    }

    err = copy_from_user(&mmap, user_mmap, sizeof(struct hkd_mmap));
    if (err != 0) {
        BFALERT("hkd: IOCTL_MAP_MEMORY: failed to copy memory from userspace\n");
        return BF_IOCTL_FAILURE;
    }

    if (!mmap.size) {
        BFALERT("hkd: IOCTL_MAP_MEMORY: size must be > 0\n");
        return BF_IOCTL_FAILURE;
    }

    addr = vm_mmap(NULL, 0, mmap.size, mmap.prot, mmap.flags | MMAP_FLAGS, 0);
    if (!addr) {
        BFALERT("hkd: IOCTL_MAP_MEMORY: vm_mmap failed\n");
        return BF_IOCTL_FAILURE;
    }

    err = put_user((void __user *)addr, &user_mmap->addr);
    if (err) {
        BFALERT("hkd: IOCTL_MAP_MEMORY: put_user faulted\n");
        return BF_IOCTL_FAILURE;
    }

    return BF_IOCTL_SUCCESS;
}

static long
dev_unlocked_ioctl(struct file *file,
                   unsigned int cmd,
                   unsigned long arg)
{
    (void) file;

    switch (cmd) {
        case IOCTL_MAP_MEMORY:
            return ioctl_map_memory((struct hkd_mmap *)arg);

        default:
            return BF_IOCTL_FAILURE;
    }
}

static struct file_operations fops = {
    .open = dev_open,
    .release = dev_release,
    .unlocked_ioctl = dev_unlocked_ioctl
};

static struct miscdevice hkd_dev = {
    MISC_DYNAMIC_MINOR,
    "hkd",
    &fops
};

/* -------------------------------------------------------------------------- */
/* Entry / Exit                                                               */
/* -------------------------------------------------------------------------- */

int
dev_init(void)
{
    if (misc_register(&hkd_dev) != 0) {
        BFALERT("hkd: misc_register failed\n");
        return -EPERM;
    }

    BFDEBUG("hkd: dev_init succeeded\n");
    return 0;
}

void
dev_exit(void)
{
    misc_deregister(&hkd_dev);

    BFDEBUG("hkd: dev_exit succeeded\n");
    return;
}

module_init(dev_init);
module_exit(dev_exit);

MODULE_LICENSE("GPL");
