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
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include <bfdriverinterface.h>

/* -------------------------------------------------------------------------- */
/* Global                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Flags for mapping memory suitable for hypervisor use:
 *
 * MAP_LOCKED - lock the page in RAM
 * MAP_PRIVATE - keep changes private
 * MAP_ANONYMOUS - don't use a file
 * MAP_POPULATE - populate (i.e. pre-fault) associated page table entries
 *
 * Note:
 *
 * There are other attributes we should consider using, either from the
 * driver or in userspace. Specifically madvise(2) allows us to control
 * what happens to memory at certain times e.g., does a child inherit the
 * mapping on fork()? Should memory contents be included in core dumps?
 *
 * On the other hand, if the hypervisor remaps the pages from the kernel,
 * madvise may not be needed.
 */

#define MMAP_FLAGS (MAP_LOCKED | MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE)


struct hkd_mmap_node {
    struct list_head list;
    struct hkd_mmap mm;
};

/**
 * struct hkd
 *
 * @list the list of mmap nodes
 * @lock the lock protecting updates to @list
 * @fops the address to the file_operations
 * @misc the address to the miscdevice
 */
struct hkd {
    struct list_head list;
    struct mutex lock;
    struct file_operations *fops;
    struct miscdevice *misc;
} g_hkd;

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
ioctl_mmap(struct hkd_mmap *user_mm)
{
    int32_t err;
    uint64_t addr;
    struct hkd_mmap mm;
    struct hkd_mmap_node *node;

    if (!user_mm) {
        BFALERT("hkd: IOCTL_MMAP: failed with user_mm == NULL\n");
        return BF_IOCTL_FAILURE;
    }

    err = copy_from_user(&mm, user_mm, sizeof(struct hkd_mmap));
    if (err != 0) {
        BFALERT("hkd: IOCTL_MMAP: failed to copy memory from userspace\n");
        return BF_IOCTL_FAILURE;
    }

    if (!mm.size) {
        BFALERT("hkd: IOCTL_MMAP: size must be > 0\n");
        return BF_IOCTL_FAILURE;
    }

    addr = vm_mmap(NULL, 0, mm.size, mm.prot, mm.flags | MMAP_FLAGS, 0);
    if (!addr) {
        BFALERT("hkd: IOCTL_MMAP: vm_mmap failed\n");
        return BF_IOCTL_FAILURE;
    }

    mm.addr = (void *)addr;
    node = kmalloc(sizeof(*node), GFP_KERNEL);
    if (!node) {
        BFALERT("hkd: IOCTL_MMAP: kmalloc failed\n");
        goto out_unmap;
    }

    err = put_user((void *)addr, &user_mm->addr);
    if (err) {
        BFALERT("hkd: IOCTL_MMAP: put_user faulted\n");
        goto out_node;
    }

    memcpy(&node->mm, &mm, sizeof(struct hkd_mmap));

    node->list.next = &node->list;
    node->list.prev = &node->list;

    mutex_lock(&g_hkd.lock);
    list_add(&node->list, &g_hkd.list);
    mutex_unlock(&g_hkd.lock);

    return BF_IOCTL_SUCCESS;

out_node:
    kfree(node);

out_unmap:
    vm_munmap(addr, mm.size);
    return BF_IOCTL_FAILURE;
}

static long
ioctl_munmap(struct hkd_mmap *user_mm)
{
    int err;
    struct hkd_mmap mm;
    struct hkd_mmap_node *node = NULL, *tmp;

    if (!user_mm) {
        BFALERT("hkd: IOCTL_MUNMAP: failed with user_mm == NULL\n");
        return BF_IOCTL_FAILURE;
    }

    err = copy_from_user(&mm, user_mm, sizeof(struct hkd_mmap));
    if (err != 0) {
        BFALERT("hkd: IOCTL_MUNMAP: failed to copy memory from userspace\n");
        return BF_IOCTL_FAILURE;
    }

    mutex_lock(&g_hkd.lock);
    list_for_each_entry_safe(node, tmp, &g_hkd.list, list) {
        if (node->mm.addr == mm.addr) {
            list_del(&node->list);
            vm_munmap((uint64_t)node->mm.addr, node->mm.size);
            kfree(node);

            break;
        }
    }
    mutex_unlock(&g_hkd.lock);

    return BF_IOCTL_SUCCESS;
}

static long
dev_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    (void) file;

    switch (cmd) {
        case IOCTL_MMAP:
            return ioctl_mmap((struct hkd_mmap *)arg);
        case IOCTL_MUNMAP:
            return ioctl_munmap((struct hkd_mmap *)arg);

        default:
            return BF_IOCTL_FAILURE;
    }
}

static struct file_operations hkd_fops = {
    .open = dev_open,
    .release = dev_release,
    .unlocked_ioctl = dev_unlocked_ioctl
};

static struct miscdevice hkd_misc = {
    MISC_DYNAMIC_MINOR,
    "hkd",
    &hkd_fops
};

/* -------------------------------------------------------------------------- */
/* Entry / Exit                                                               */
/* -------------------------------------------------------------------------- */

int
dev_init(void)
{
    INIT_LIST_HEAD(&g_hkd.list);
    mutex_init(&g_hkd.lock);

    g_hkd.misc = &hkd_misc;
    g_hkd.fops = &hkd_fops;

    if (misc_register(g_hkd.misc) != 0) {
        BFALERT("hkd: misc_register failed\n");
        return -EPERM;
    }

    BFDEBUG("hkd: dev_init succeeded\n");
    return 0;
}

void
dev_exit(void)
{
    struct hkd_mmap_node *node, *tmp;

    list_for_each_entry_safe(node, tmp, &g_hkd.list, list) {
        list_del(&node->list);
        vm_munmap((unsigned long)node->mm.addr, node->mm.size);
        kfree(node);
    }

    misc_deregister(g_hkd.misc);
    BFDEBUG("hkd: dev_exit succeeded\n");

    return;
}

module_init(dev_init);
module_exit(dev_exit);

MODULE_LICENSE("GPL");
