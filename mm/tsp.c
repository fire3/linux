// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generic Transparent Segment Page support.
 * (C) Xingyan Wang, September 2020
 */
#include <linux/list.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/sysctl.h>
#include <linux/highmem.h>
#include <linux/mmu_notifier.h>
#include <linux/nodemask.h>
#include <linux/pagemap.h>
#include <linux/mempolicy.h>
#include <linux/compiler.h>
#include <linux/cpuset.h>
#include <linux/mutex.h>
#include <linux/memblock.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/mmdebug.h>
#include <linux/sched/signal.h>
#include <linux/rmap.h>
#include <linux/string_helpers.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/jhash.h>
#include <linux/numa.h>
#include <linux/llist.h>
#include <linux/cma.h>

#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/tlb.h>

static unsigned long tsp_reserve_size __initdata;
static bool tsp_reserve_called __initdata;

static int __init cmdline_parse_tsp_reserve(char *p)
{
	tsp_reserve_size = memparse(p, &p);
	return 0;
}

early_param("tsp_reserve", cmdline_parse_tsp_reserve);

void __init tsp_reserve(int order)
{
	unsigned long size, reserved, per_node;
	int nid;
	phys_addr_t memblock_start = memblock_start_of_DRAM();
	phys_addr_t memblock_end = memblock_end_of_DRAM();

	tsp_reserve_called = true;

	if (!tsp_reserve_size)
		return;

	if (tsp_reserve_size < (PAGE_SIZE << order)) {
		pr_warn("tsp: reserved area should be at least %lu MiB\n",
			(PAGE_SIZE << order) / SZ_1M);
		return;
	}

	/*
	 * If 3 GB area is requested on a machine with 4 numa nodes,
	 * let's allocate 1 GB on first three nodes and ignore the last one.
	 */
	per_node = DIV_ROUND_UP(tsp_reserve_size, nr_online_nodes);
	pr_info("tsp: reserve %lu MiB, up to %lu MiB per node\n",
		tsp_reserve_size / SZ_1M, per_node / SZ_1M);

	reserved = 0;
	for_each_node_state(nid, N_ONLINE) {
		phys_addr_t addr = 0;

		size = min(per_node, tsp_reserve_size - reserved);
		size = round_up(size, PAGE_SIZE << order);

                pr_info("memblock_start: %llu memblock_end: %llu\n",
                                memblock_start, memblock_end);
                addr = memblock_alloc_range_nid(size, PAGE_SIZE << order,
                                memblock_start, memblock_end, nid, false);

		if (!addr) {
			pr_warn("tsp: reservation failed: node %d",
				nid);
			continue;
		}

		reserved += size;
		pr_info("tsp: reserved %lu MiB on node %d\n",
			size / SZ_1M, nid);

		if (reserved >= tsp_reserve_size)
			break;
	}
}
