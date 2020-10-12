/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_TSP_H
#define _UAPI_LINUX_TSP_H

#include <linux/types.h>

#define TSP 0xAB

#define TSP_SWAP                     _IOW(TSP,   0x01, unsigned long)

#endif /* _UAPI_LINUX_TSP_H */
