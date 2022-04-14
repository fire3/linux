// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generic Transparent Segment Page support.
 * (C) Xingyan Wang, September 2020
 */
#include <linux/list.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/oom.h>
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
#include <linux/timekeeping.h>

#include <asm/io.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <linux/uaccess.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>

#include <linux/proc_fs.h>
#include <linux/miscdevice.h>
#include <linux/smm.h>
#include <linux/huge_mm.h>
#include <linux/hugetlb.h>
#include <linux/anon_inodes.h>

#include "internal.h"
#include "cma.h"

static unsigned long smm_reserve_size __initdata;
static bool smm_reserve_called __initdata;

static int __init cmdline_parse_smm_reserve(char *p)
{
	smm_reserve_size = memparse(p, &p);
	return 0;
}

early_param("smm_reserve", cmdline_parse_smm_reserve);

static struct cma *smm_cma;
void __init smm_reserve(int order)
{
	unsigned long size;
	int res;

	smm_reserve_called = true;

	if (!smm_reserve_size)
		return;

	if (smm_reserve_size < (PAGE_SIZE << order)) {
		pr_warn("smm: reserved area should be at least %lu MiB\n",
			(PAGE_SIZE << order) / SZ_1M);
		return;
	}

	size = round_up(smm_reserve_size, PAGE_SIZE << order);
	res = cma_declare_contiguous_nid(0, size, 0, PAGE_SIZE << order, 0,
					 false, "smm", &smm_cma, NUMA_NO_NODE);

	if (res) {
		pr_warn("smm: reservation failed.\n");
	}
	pr_info("smm: reserved %lu MiB\n", size / SZ_1M);
}

/**
 * smm_cma_reserve() reserve pages from smm_cma area
 * @count: Requested number of pages.
 * @align: Requested alignment of pages (in PAGE_SIZE order).
 *
 */
unsigned long smm_cma_reserve(unsigned long count, unsigned long align)
{
	unsigned long pfn;
	pfn = cma_reserve(smm_cma, count, align);
	return pfn;
}

bool smm_cma_cancel(unsigned long pfn, unsigned int count)
{
	return cma_cancel(smm_cma, pfn, count);
}

void smm_cma_reserve_stack(unsigned long size, struct mm_struct *mm)
{
	unsigned long pfn;

	size = round_up(size, PAGE_SIZE);
	pfn = smm_cma_reserve(size / PAGE_SIZE, 0);

	if (pfn != 0) {
		mm->smm_stack_base_pfn = pfn;
		mm->smm_stack_page_count = size / PAGE_SIZE;
		printk("[%s %d] mm: %#lx SMM CMA stack reserved to pfn %#lx, count: %ld\n",
		       current->comm, current->pid, (unsigned long)mm, pfn,
		       mm->smm_stack_page_count);
	} else {
		mm->smm_stack_base_pfn = 0;
		mm->smm_stack_page_count = 0;
		printk("[%s %d] SMM CMA stack reserve failed\n", current->comm,
		       current->pid);
	}
}

void exit_smm(struct mm_struct *mm)
{
	if (mm->smm_stack_base_pfn && mm->smm_stack_page_count) {
		printk("[%s %d] mm: %#lx SMM CMA cancel reservation from pfn %#lx, count %d\n",
		       current->comm, current->pid, (unsigned long) mm, mm->smm_stack_base_pfn,
		       mm->smm_stack_page_count);
		smm_cma_cancel(mm->smm_stack_base_pfn,
			       mm->smm_stack_page_count);
	}
}

void mm_init_smm(struct mm_struct *mm)
{
	mm->smm_stack_base_va = 0;
	mm->smm_stack_end_va = 0;
	mm->smm_stack_base_pfn = 0;

	mm->smm_heap_base_va = 0;
	mm->smm_heap_end_va = 0;
	mm->smm_heap_base_pfn = 0;

	mm->smm_code_base_va = 0;
	mm->smm_code_base_pfn = 0;

	mm->smm_mmap_base_va = 0;
	mm->smm_mmap_base_pfn = 0;

	mm->smm_stack_page_count = 0;
	mm->smm_code_page_count = 0;
	mm->smm_heap_page_count = 0;
	mm->smm_mmap_page_count = 0;
}

unsigned long smm_stack_va_to_pa(struct mm_struct *mm, unsigned long va)
{
	unsigned long pa = 0;
	if (mm->smm_stack_base_pfn && mm->smm_stack_base_va &&
	    mm->smm_stack_page_count) {
		pa = ((mm->smm_stack_base_pfn + mm->smm_stack_page_count)
		      << PAGE_SHIFT) -
		     (mm->smm_stack_end_va - va);
		return pa;
	}

	return pa;
}
