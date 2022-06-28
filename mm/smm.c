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
static DEFINE_MUTEX(smm_mutex);

unsigned long smm_cpfile_flags __read_mostly = 0;

#define smm_dbg(fmt, ...)                                                      \
	do {                                                                   \
		if (smm_debug)                                                 \
			printk(fmt, ##__VA_ARGS__);                            \
	} while (0)

static int smm_debug = 1;

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
	res = cma_declare_contiguous_nid(0x100000000UL, size, 0,
					 PAGE_SIZE << order, 0, true, "smm",
					 &smm_cma, NUMA_NO_NODE);

	if (res) {
		pr_warn("smm: reservation failed.\n");
		return;
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

/*
void smm_shuffle_freelist(unsigned long pfn_start, unsigned long pfn_end)
{
	struct zone *zone;
	int current_order;
	struct free_area *area;
	struct page *page, *next;
	unsigned long pfn;
	unsigned long flags;
	struct list_head *freelist;
	LIST_HEAD(pages_to_move);

	zone = page_zone(pfn_to_page(pfn_start));

	spin_lock_irqsave(&zone->lock, flags);
	for (current_order = (MAX_ORDER-1); current_order >= 0; --current_order) {
		area = &(zone->free_area[current_order]);
		freelist = &area->free_list[MIGRATE_CMA];
		list_for_each_entry_safe(page, next, freelist, lru) {
			pfn = page_to_pfn(page);
			if (pfn >= pfn_start && pfn < pfn_end) {
				list_del(&page->lru);
				list_add(&page->lru, &pages_to_move);
			}
		}
	}

	list_for_each_entry_safe(page, next, &pages_to_move, lru) {
		area = &(zone->free_area[buddy_order(page)]);
		freelist = &area->free_list[MIGRATE_CMA];
		list_add_tail(&page->lru, freelist);
	}

	spin_unlock_irqrestore(&zone->lock, flags);
}
*/

void smm_cma_reserve_code(unsigned long size, struct mm_struct *mm)
{
	unsigned long pfn;

	if (mm->smm_code_page_count)
		return;

	size = round_up(size, PAGE_SIZE);
	pfn = smm_cma_reserve(size / PAGE_SIZE, 0);

	smm_dbg("[%s %d] SMM code reserved to pfn [%#lx - %#lx)\n",
		current->comm, current->pid, pfn, pfn + size / PAGE_SIZE);

	if (pfn != 0) {
		mm->smm_code_base_pfn = pfn;
		mm->smm_code_page_count = size / PAGE_SIZE;

	} else {
		mm->smm_code_base_pfn = 0;
		mm->smm_code_page_count = 0;
	}

}

void smm_cma_reserve_stack(unsigned long size, struct mm_struct *mm)
{
	unsigned long pfn;

	if (mm->smm_stack_page_count)
		return;

	size = round_up(size, PAGE_SIZE);
	pfn = smm_cma_reserve(size / PAGE_SIZE, 0);

	if (pfn != 0) {
		mm->smm_stack_base_pfn = pfn;
		mm->smm_stack_page_count = size / PAGE_SIZE;
		smm_dbg("[%s %d] SMM stack reserved to pfn: [%#lx- %#lx)\n",
			current->comm, current->pid, pfn,
			pfn + size / PAGE_SIZE);
	} else {
		mm->smm_stack_base_pfn = 0;
		mm->smm_stack_page_count = 0;
		pr_warn("[%s %d] SMM CMA stack reserve size %ld failed\n",
			current->comm, current->pid, size);
	}
}

void smm_cma_reserve_mem(unsigned long size, struct mm_struct *mm)
{
	unsigned long pfn;

	if (mm->smm_mem_page_count)
		return;

	size = round_up(size, PAGE_SIZE);
	pfn = smm_cma_reserve(size / PAGE_SIZE, HUGETLB_PAGE_ORDER);

	if (pfn != 0) {
		mm->smm_mem_base_pfn = pfn;
		mm->smm_mem_page_count = size / PAGE_SIZE;

		smm_dbg("[%s %d] SMM heap and mmap reserved to pfn [%#lx - %#lx)\n",
			current->comm, current->pid, pfn,
			pfn + size / PAGE_SIZE);
	} else {
		mm->smm_mem_base_pfn = 0;
		mm->smm_mem_page_count = 0;
		pr_warn("[%s %d] SMM CMA mem reserve size %ld failed\n",
			current->comm, current->pid, size);
	}
}

void exit_smm(struct mm_struct *mm)
{
	if (mm->smm_stack_base_pfn && mm->smm_stack_page_count) {
		smm_cma_cancel(mm->smm_stack_base_pfn,
			       mm->smm_stack_page_count);
		smm_dbg("[%s %d] SMM cancel stack cma pfn [%#lx - %#lx).\n",
			current->comm, current->pid, mm->smm_stack_base_pfn,
			mm->smm_stack_base_pfn + mm->smm_stack_page_count);
	}

	if (mm->smm_mem_base_pfn && mm->smm_mem_page_count) {
		smm_cma_cancel(mm->smm_mem_base_pfn, mm->smm_mem_page_count);
		smm_dbg("[%s %d] SMM cancel heap and mmap cma pfn [%#lx - %#lx).\n",
			current->comm, current->pid, mm->smm_mem_base_pfn,
			mm->smm_mem_base_pfn + mm->smm_mem_page_count);

		smm_dbg("[%s %d] SMM migrate page count: %ld\n",current->comm, current->pid, mm->smm_migrate_page_count);
	}

	if (mm->smm_code_base_pfn && mm->smm_code_page_count) {
		smm_cma_cancel(mm->smm_code_base_pfn, mm->smm_code_page_count);
		smm_dbg("[%s %d] SMM cancel code cma pfn [%#lx - %#lx).\n",
			current->comm, current->pid, mm->smm_code_base_pfn,
			mm->smm_code_base_pfn + mm->smm_code_page_count);
	}

}

void mm_init_smm(struct mm_struct *mm)
{
	mm->smm_activate = 0;

	mm->smm_code_base_va = 0;
	mm->smm_code_end_va = 0;
	mm->smm_stack_base_va = 0;
	mm->smm_stack_end_va = 0;
	mm->smm_heap_base_va = 0;
	mm->smm_heap_end_va = 0;
	mm->smm_mmap_base_va = 0;
	mm->smm_mmap_end_va = 0;

	mm->smm_code_base_pfn = 0;
	mm->smm_stack_base_pfn = 0;
	mm->smm_mem_base_pfn = 0;

	mm->smm_code_page_count = 0;
	mm->smm_stack_page_count = 0;
	mm->smm_mem_page_count = 0;

	mm->smm_code_size = 0;
	mm->smm_stack_size = 0;
	mm->smm_mem_size = 0;
	mm->smm_migrate_page_count = 0;
}

unsigned long smm_code_va_to_pa(struct mm_struct *mm, unsigned long va)
{
	unsigned long pa = 0;

	if (!mm)
		return 0;
	if (!mm->smm_activate)
		return 0;

	if (mm->smm_code_base_va && mm->smm_code_end_va &&
	    mm->smm_code_base_pfn && mm->smm_code_page_count) {
		if (va < mm->smm_code_base_va || va >= mm->smm_code_end_va)
			return 0;

		pa = va - mm->smm_code_base_va +
		     (mm->smm_code_base_pfn << PAGE_SHIFT);

		return pa;
	}

	return 0;
}

unsigned long smm_stack_va_to_pa(struct mm_struct *mm, unsigned long va)
{
	unsigned long pa = 0;

	if (!mm)
		return 0;
	if (!mm->smm_activate)
		return 0;

	if (mm->smm_stack_base_pfn && mm->smm_stack_base_va &&
	    mm->smm_stack_page_count && mm->smm_stack_end_va) {
		if ((mm->smm_stack_end_va - round_down(va, PAGE_SIZE)) >
		    SMM_STACK_SIZE_LIMIT)
			return 0;
		pa = ((mm->smm_stack_base_pfn + mm->smm_stack_page_count)
		      << PAGE_SHIFT) -
		     (mm->smm_stack_end_va - va);
		return pa;
	}

	return 0;
}

unsigned long smm_heap_va_to_pa(struct mm_struct *mm, unsigned long va)
{
	unsigned long pa = 0;
	unsigned long hugepage_offset = (~HPAGE_MASK & mm->smm_heap_base_va);

	if (!mm)
		return 0;
	if (!mm->smm_activate)
		return 0;

	if (mm->smm_heap_base_va && mm->smm_heap_end_va &&
	    mm->smm_mem_base_pfn && mm->smm_mem_page_count) {
		if (va < mm->smm_heap_base_va || va >= mm->smm_heap_end_va)
			return 0;

		if (va >= mm->smm_mmap_base_va)
			return 0;

		pa = va - mm->smm_heap_base_va +
		     (mm->smm_mem_base_pfn << PAGE_SHIFT) + hugepage_offset;

		return pa;
	}

	return 0;
}

unsigned long smm_mmap_va_to_pa(struct mm_struct *mm, unsigned long va)
{
	unsigned long pa = 0;
	unsigned long hugepage_offset =
		HPAGE_SIZE - (~HPAGE_MASK & mm->smm_mmap_end_va);

	if (!mm)
		return 0;
	if (!mm->smm_activate)
		return 0;

	if (mm->smm_mem_base_pfn && mm->smm_mmap_base_va &&
	    mm->smm_mem_page_count && mm->smm_stack_end_va) {

		if (va < mm->smm_heap_end_va)
			return 0;

		pa = ((mm->smm_mem_base_pfn + mm->smm_mem_page_count)
		      << PAGE_SHIFT) -
		     hugepage_offset - (mm->smm_mmap_end_va - va);
		return pa;
	}
	return 0;
}

unsigned long smm_va_to_pa(struct vm_area_struct *vma, unsigned long va)
{
	if (!vma)
		return 0;

	if (!vma->vm_mm->smm_activate)
		return 0;

	if ((va < vma->vm_start) || (va >= vma->vm_end))
		return 0;

	if (vma->vm_flags & VM_SMM_CODE)
		return smm_code_va_to_pa(vma->vm_mm, va);

	if (vma->vm_flags & VM_SMM_HEAP)
		return smm_heap_va_to_pa(vma->vm_mm, va);

	if (vma->vm_flags & VM_SMM_MMAP)
		return smm_mmap_va_to_pa(vma->vm_mm, va);

	if (vma->vm_flags & VM_SMM_STACK)
		return smm_stack_va_to_pa(vma->vm_mm, va);

	return 0;
}

void smm_lock(void)
{
	mutex_lock(&smm_mutex);
}

void smm_unlock(void)
{
	mutex_unlock(&smm_mutex);
}

int is_smm_reserved(unsigned long pfn)
{
	return is_cma_reserved(smm_cma, pfn);
}

#ifdef CONFIG_SYSFS

static ssize_t cpfile_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	if (test_bit(0, &smm_cpfile_flags))
		return sprintf(buf, "[always] never\n");
	else
		return sprintf(buf, "always [never]\n");
}

static ssize_t cpfile_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	ssize_t ret = count;

	if (sysfs_streq(buf, "always")) {
		set_bit(0, &smm_cpfile_flags);
	} else if (sysfs_streq(buf, "never")) {
		clear_bit(0, &smm_cpfile_flags);
	} else
		ret = -EINVAL;

	return ret;
}
static struct kobj_attribute cpfile_attr =
	__ATTR(cpfile, 0644, cpfile_show, cpfile_store);

static struct attribute *smm_attr[] = {
	&cpfile_attr.attr,
	NULL,
};

static const struct attribute_group smm_attr_group = {
	.attrs = smm_attr,
};

static int __init smm_init_sysfs(struct kobject **smm_kobj)
{
	int err;

	*smm_kobj = kobject_create_and_add("smm", mm_kobj);
	if (unlikely(!*smm_kobj)) {
		pr_err("failed to create smm kobject\n");
		return -ENOMEM;
	}

	err = sysfs_create_group(*smm_kobj, &smm_attr_group);
	if (err) {
		pr_err("failed to register smm group\n");
		goto delete_obj;
	}

	return 0;

delete_obj:
	kobject_put(*smm_kobj);
	return err;
}
#else
static inline int smm_init_sysfs(struct kobject **smm_kobj)
{
	return 0;
}

#endif /* CONFIG_SYSFS */


static int __init smm_init(void)
{
	int err;
	struct kobject *smm_kobj;
	err = smm_init_sysfs(&smm_kobj);
	if (err)
		goto err_sysfs;
err_sysfs:
	return err;
}
subsys_initcall(smm_init);
