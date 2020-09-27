/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_APC_H
#define _UAPI_LINUX_APC_H

#include <linux/types.h>

#define APC 0xAA

struct apc_create_tsp {
        /* Input Arguments */
        unsigned long code_size;  /* binary */
        unsigned long heap_size;  /* brk */
        unsigned long mmap_size;  /* mmap */
        unsigned long stack_size; /* stack */
};

#define APC_CREATE_TSP                     _IOW(APC,   0x01, struct apc_create_tsp)

#endif /* _UAPI_LINUX_APC_H */
