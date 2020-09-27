// SPDX-License-Identifier: GPL-2.0-only
/*
 * X86 Accelerated Processing Core support.
 * (C) Xingyan Wang, September 2020
 */
#include <linux/list.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/sysctl.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/numa.h>
#include <linux/proc_fs.h>
#include <linux/miscdevice.h>
#include <linux/anon_inodes.h>
#include <linux/tsp.h>

#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/tlb.h>
#include <asm/apc.h>

#define APC_MINOR 251

static int apc_ioctl_create_tsp(struct apc_create_tsp *c)
{
	int error, fd;
	struct file *file = NULL;
        struct tsp *tsp = NULL; 

        tsp = tsp_alloc(c->code_size, c->heap_size, c->mmap_size, c->stack_size);
	if (IS_ERR(tsp)) {
		fd = PTR_ERR(tsp);
		goto out;
	}

	error = get_unused_fd_flags(O_RDWR);
	if (error < 0) {
		fd = error;
		goto out;
	}
	fd = error;

	file = anon_inode_getfile("tsp", &tsp_fops, tsp, O_RDWR);
	if (IS_ERR(file)) {
		error = PTR_ERR(file);
		put_unused_fd(fd);
		fd = error;
		goto out;
	}
	get_tsp(tsp);
	fd_install(fd, file);
out:
        return fd;
}

static int apc_dev_release(struct inode *inode, struct file *filp)
{
        return 0;
}

static long apc_dev_ioctl(struct file *filp, unsigned int ioctl,
			    unsigned long arg)
{
	long r = -EINVAL;
	void __user *argp = (void __user *)arg;
        
	switch (ioctl) {
                case APC_CREATE_TSP: {
                        struct apc_create_tsp c;
                        r = -EFAULT;
		        if (copy_from_user(&c, argp, sizeof c))
		        	goto out;
                        r =  apc_ioctl_create_tsp(&c);
                        break;
                }
        	default:
		        r = -EOPNOTSUPP;
		        return r;
	}
out:
	return r;
}

static struct file_operations apc_chardev_ops = {
	.release = apc_dev_release,
	.unlocked_ioctl = apc_dev_ioctl,
	.compat_ioctl = apc_dev_ioctl,
	.llseek = noop_llseek,
};


static struct miscdevice apc_dev = {
	APC_MINOR, "apc", &apc_chardev_ops,
};


int __init apc_device_init(void)
{
        return misc_register(&apc_dev);
}
device_initcall(apc_device_init);
