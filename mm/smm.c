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
#include <uapi/linux/smm.h>
#include <linux/huge_mm.h>
#include <linux/hugetlb.h>
#include <linux/anon_inodes.h>

#include "internal.h"

#define TSP_DEBUG 1

#define mk_huge_pmd(page, prot) pmd_mkhuge(mk_pmd(page, prot))
#define mk_pud(page, pgprot) pfn_pud(page_to_pfn(page), (pgprot))
#define mk_huge_pud(page, prot) pud_mkhuge(mk_pud(page, prot))
pmd_t smm_maybe_pmd_mkwrite(pmd_t pmd, struct vm_area_struct *vma);

pmd_t smm_pmdp_invalidate(struct vm_area_struct *vma, unsigned long address,
			  pmd_t *pmdp);
static unsigned long smm_reserve_size __initdata;
static bool smm_reserve_called __initdata;

bool smm_pmd_huge_vma_suitable(struct vm_area_struct *vma, unsigned long haddr);
static int prep_new_smm_page(struct page *page);

static int __init cmdline_parse_smm_reserve(char *p)
{
	smm_reserve_size = memparse(p, &p);
	return 0;
}

early_param("smm_reserve", cmdline_parse_smm_reserve);

void __init smm_reserve(int order)
{
	unsigned long size, reserved, per_node;
	int nid;
	phys_addr_t memblock_start = memblock_start_of_DRAM();
	phys_addr_t memblock_end = memblock_end_of_DRAM();

	smm_reserve_called = true;

	if (!smm_reserve_size)
		return;

	if (smm_reserve_size < (PAGE_SIZE << order)) {
		pr_warn("smm: reserved area should be at least %lu MiB\n",
			(PAGE_SIZE << order) / SZ_1M);
		return;
	}

	/*
	 * If 3 GB area is requested on a machine with 4 numa nodes,
	 * let's allocate 1 GB on first three nodes and ignore the last one.
	 */
	per_node = DIV_ROUND_UP(smm_reserve_size, nr_online_nodes);
	pr_info("smm: reserve %lu MiB, up to %lu MiB per node\n",
		smm_reserve_size / SZ_1M, per_node / SZ_1M);

	reserved = 0;
	for_each_node_state (nid, N_ONLINE) {
		phys_addr_t addr = 0;

		size = min(per_node, smm_reserve_size - reserved);
		size = round_up(size, PAGE_SIZE << order);

		pr_info("memblock_start: %llu memblock_end: %llu\n",
			memblock_start, memblock_end);
		addr = memblock_alloc_range_nid(size, PAGE_SIZE << order,
						memblock_start, memblock_end,
						nid, false);

		if (!addr) {
			pr_warn("smm: reservation failed: node %d", nid);
			continue;
		}

		smmblock_add_node(addr, size, nid);

		reserved += size;
		pr_info("smm: reserved %lu MiB on node %d\n", size / SZ_1M,
			nid);
		if (reserved >= smm_reserve_size)
			break;
	}
	__smmblock_dump_all();
}

/*
 * smmblock_lock protects all slob allocator structures.
 */
static DEFINE_SPINLOCK(smmblock_lock);

static struct smmblock_region
	smmblock_memory_init_regions[INIT_TSPBLOCK_REGIONS];
static struct smmblock_region
	smmblock_reserved_init_regions[INIT_TSPBLOCK_REGIONS];

struct smmblock smmblock = {
	.memory.regions = smmblock_memory_init_regions,
	.memory.cnt = 1, /* empty dummy entry */
	.memory.max = INIT_TSPBLOCK_REGIONS,

	.reserved.regions = smmblock_reserved_init_regions,
	.reserved.cnt = 1, /* empty dummy entry */
	.reserved.max = INIT_TSPBLOCK_REGIONS,

	.current_limit = TSPBLOCK_ALLOC_ANYWHERE,
};

int smmblock_debug = 0;
static int smmblock_can_resize = 1;
static int smmblock_memory_in_slab = 0;
static int smmblock_reserved_in_slab = 0;
/* inline so we don't get a warning when pr_debug is compiled out */
static const char *smmblock_type_name(struct smmblock_type *type)
{
	if (type == &smmblock.memory)
		return "memory";
	else if (type == &smmblock.reserved)
		return "reserved";
	else
		return "unknown";
}

/* adjust *@size so that (@base + *@size) doesn't overflow, return new size */
static inline phys_addr_t smmblock_cap_size(phys_addr_t base, phys_addr_t *size)
{
	return *size = min(*size, (phys_addr_t)ULLONG_MAX - base);
}

/*
 * Address comparison utilities
 */
static unsigned long smmblock_addrs_overlap(phys_addr_t base1,
					    phys_addr_t size1,
					    phys_addr_t base2,
					    phys_addr_t size2)
{
	return ((base1 < (base2 + size2)) && (base2 < (base1 + size1)));
}

static long smmblock_overlaps_region(struct smmblock_type *type,
				     phys_addr_t base, phys_addr_t size)
{
	unsigned long i;

	for (i = 0; i < type->cnt; i++) {
		phys_addr_t rgnbase = type->regions[i].base;
		phys_addr_t rgnsize = type->regions[i].size;
		if (smmblock_addrs_overlap(base, size, rgnbase, rgnsize))
			break;
	}

	return (i < type->cnt) ? i : -1;
}

/**
 * smmblock_find_in_range_node_reverse - find free area in given range and node reverse
 * @start: start of candidate range
 * @end: end of candidate range, can be %smmblock_ALLOC_{ANYWHERE|ACCESSIBLE}
 * @size: size of free area to find
 * @align: alignment of free area to find
 * @nid: nid of the free area to find, %MCK_MAX_NUMNODES for any node
 *
 * Find @size free area aligned to @align in the specified range and node.
 *
 * RETURNS:
 * Found address on success, %0 on failure.
 */
phys_addr_t smmblock_find_in_range_node_reverse(phys_addr_t start,
						phys_addr_t end,
						phys_addr_t size,
						phys_addr_t align, int nid)
{
	phys_addr_t this_start, this_end, cand;
	u64 i;

	/* pump up @end */
	if (end == TSPBLOCK_ALLOC_ACCESSIBLE)
		end = smmblock.current_limit;

	/* avoid allocating the first page */
	start = max_t(phys_addr_t, start, PAGE_SIZE);
	end = max(start, end);

	for_each_freemem_range_reverse(i, nid, &this_start, &this_end, NULL)
	{
		this_start = clamp(this_start, start, end);
		this_end = clamp(this_end, start, end);

		if (this_end < size)
			continue;

		cand = round_down(this_end - size, align);
		if (cand >= this_start)
			return cand;
	}
	return 0;
}

/**
 * smmblock_find_in_range_node - find free area in given range and node
 * @start: start of candidate range
 * @end: end of candidate range, can be %TSPBLOCK_ALLOC_{ANYWHERE|ACCESSIBLE}
 * @size: size of free area to find
 * @align: alignment of free area to find
 * @nid: nid of the free area to find, %MCK_MAX_NUMNODES for any node
 *
 * Find @size free area aligned to @align in the specified range and node.
 *
 * RETURNS:
 * Found address on success, %0 on failure.
 */
phys_addr_t smmblock_find_in_range_node(phys_addr_t start, phys_addr_t end,
					phys_addr_t size, phys_addr_t align,
					int nid)
{
	phys_addr_t this_start, this_end, cand;
	u64 i;

	/* pump up @end */
	if (end == TSPBLOCK_ALLOC_ACCESSIBLE)
		end = smmblock.current_limit;

	/* avoid allocating the first page */
	start = max_t(phys_addr_t, start, PAGE_SIZE);
	end = max(start, end);

	for_each_freemem_range(i, nid, &this_start, &this_end, NULL)
	{
		this_start = clamp(this_start, start, end);
		this_end = clamp(this_end, start, end);

		if (this_end < size)
			continue;
		//cand = round_down(this_end - size, align);
		//Get cand from beginning
		cand = round_up(this_start, align);
		if ((cand + size) <= this_end)
			return cand;
	}
	return 0;
}

/**
 * smmblock_find_in_range_reverse - find free area in given range reverse
 * @start: start of candidate range
 * @end: end of candidate range, can be %smmblock_ALLOC_{ANYWHERE|ACCESSIBLE}
 * @size: size of free area to find
 * @align: alignment of free area to find
 *
 * Find @size free area aligned to @align in the specified range.
 *
 * RETURNS:
 * Found address on success, %0 on failure.
 */
phys_addr_t smmblock_find_in_range_reverse(phys_addr_t start, phys_addr_t end,
					   phys_addr_t size, phys_addr_t align)
{
	return smmblock_find_in_range_node_reverse(start, end, size, align,
						   MCK_MAX_NUMNODES);
}

/**
 * smmblock_find_in_range - find free area in given range
 * @start: start of candidate range
 * @end: end of candidate range, can be %smmblock_ALLOC_{ANYWHERE|ACCESSIBLE}
 * @size: size of free area to find
 * @align: alignment of free area to find
 *
 * Find @size free area aligned to @align in the specified range.
 *
 * RETURNS:
 * Found address on success, %0 on failure.
 */
phys_addr_t smmblock_find_in_range(phys_addr_t start, phys_addr_t end,
				   phys_addr_t size, phys_addr_t align)
{
	return smmblock_find_in_range_node(start, end, size, align,
					   MCK_MAX_NUMNODES);
}

static void smmblock_remove_region(struct smmblock_type *type, unsigned long r)
{
	type->total_size -= type->regions[r].size;
	memmove(&type->regions[r], &type->regions[r + 1],
		(type->cnt - (r + 1)) * sizeof(type->regions[r]));
	type->cnt--;

	/* Special case for empty arrays */
	if (type->cnt == 0) {
		WARN_ON(type->total_size != 0);
		type->cnt = 1;
		type->regions[0].base = 0;
		type->regions[0].size = 0;
		smmblock_set_region_node(&type->regions[0], MCK_MAX_NUMNODES);
	}
}

phys_addr_t get_allocated_smmblock_reserved_regions_info(phys_addr_t *addr)
{
	if (smmblock.reserved.regions == smmblock_reserved_init_regions)
		return 0;

	*addr = __pa(smmblock.reserved.regions);

	return PAGE_ALIGN(sizeof(struct smmblock_region) *
			  smmblock.reserved.max);
}

/**
 * smmblock_double_array - double the size of the smmblock regions array
 * @type: smmblock type of the regions array being doubled
 * @new_area_start: starting address of memory range to avoid overlap with
 * @new_area_size: size of memory range to avoid overlap with
 *
 * Double the size of the @type regions array. If smmblock is being used to
 * allocate memory for a new reserved regions array and there is a previously
 * allocated memory range [@new_area_start,@new_area_start+@new_area_size]
 * waiting to be reserved, ensure the memory used by the new array does
 * not overlap.
 *
 * RETURNS:
 * 0 on success, -1 on failure.
 */
static int smmblock_double_array(struct smmblock_type *type,
				 phys_addr_t new_area_start,
				 phys_addr_t new_area_size)
{
	struct smmblock_region *new_array, *old_array;
	phys_addr_t old_alloc_size, new_alloc_size;
	phys_addr_t old_size, new_size, addr;
	int use_slab = slab_is_available();
	int *in_slab;
	/* We don't allow resizing until we know about the reserved regions
	 * of memory that aren't suitable for allocation
	 */
	if (!smmblock_can_resize)
		return -1;

	/* Calculate new doubled size */
	old_size = type->max * sizeof(struct smmblock_region);
	new_size = old_size << 1;
	/*
	 * We need to allocated new one align to PAGE_SIZE,
	 *   so we can free them completely later.
	 */
	old_alloc_size = PAGE_ALIGN(old_size);
	new_alloc_size = PAGE_ALIGN(new_size);

	/* Retrieve the slab flag */
	if (type == &smmblock.memory)
		in_slab = &smmblock_memory_in_slab;
	else
		in_slab = &smmblock_reserved_in_slab;

	/* Try to find some space for it.
	 *
	 * WARNING: We assume that either slab_is_available() and we use it or
	 * we use smmblock for allocations. That means that this is unsafe to
	 * use when bootmem is currently active (unless bootmem itself is
	 * implemented on top of smmblock which isn't the case yet)
	 *
	 * This should however not be an issue for now, as we currently only
	 * call into smmblock while it's still active, or much later when slab
	 * is active for memory hotplug operations
	 */
	new_array = kmalloc(new_size, GFP_KERNEL);
	addr = new_array ? __pa(new_array) : 0;
	if (!addr) {
		pr_err("smmblock: Failed to double %s array from %ld to %ld "
		       "entries !\n",
		       smmblock_type_name(type), type->max, type->max * 2);
		return -1;
	}

	smmblock_dbg("smmblock: %s is doubled to %ld at [%#010llx-%#010llx]",
		     smmblock_type_name(type), type->max * 2, (u64)addr,
		     (u64)addr + new_size - 1);

	/*
	 * Found space, we now need to move the array over before we add the
	 * reserved region since it may be our reserved array itself that is
	 * full.
	 */
	memcpy(new_array, type->regions, old_size);
	memset(new_array + type->max, 0, old_size);
	old_array = type->regions;
	type->regions = new_array;
	type->max <<= 1;

	/* Free old array. We needn't free it if the array is the static one */
	if (*in_slab)
		kfree(old_array);

	/* Update slab flag */
	*in_slab = use_slab;
	return 0;
}

/**
 * smmblock_merge_regions - merge neighboring compatible regions
 * @type: smmblock type to scan
 *
 * Scan @type and merge neighboring compatible regions.
 */
static void smmblock_merge_regions(struct smmblock_type *type)
{
	int i = 0;

	/* cnt never goes below 1 */
	while (i < type->cnt - 1) {
		struct smmblock_region *this = &type->regions[i];
		struct smmblock_region *next = &type->regions[i + 1];

		if (this->base + this->size != next->base ||
		    smmblock_get_region_node(this) !=
			    smmblock_get_region_node(next)) {
			BUG_ON(this->base + this->size > next->base);
			i++;
			continue;
		}

		this->size += next->size;
		/* move forward from next + 1, index of which is i + 2 */
		memmove(next, next + 1, (type->cnt - (i + 2)) * sizeof(*next));
		type->cnt--;
	}
}

/**
 * smmblock_insert_region - insert new smmblock region
 * @type: smmblock type to insert into
 * @idx: index for the insertion point
 * @base: base address of the new region
 * @size: size of the new region
 *
 * Insert new smmblock region [@base,@base+@size) into @type at @idx.
 * @type must already have extra room to accomodate the new region.
 */
static void smmblock_insert_region(struct smmblock_type *type, int idx,
				   phys_addr_t base, phys_addr_t size, int nid)
{
	struct smmblock_region *rgn = &type->regions[idx];

	BUG_ON(type->cnt >= type->max);
	memmove(rgn + 1, rgn, (type->cnt - idx) * sizeof(*rgn));
	rgn->base = base;
	rgn->size = size;
	smmblock_set_region_node(rgn, nid);
	type->cnt++;
	type->total_size += size;
}

/**
 * smmblock_add_region - add new smmblock region
 * @type: smmblock type to add new region into
 * @base: base address of the new region
 * @size: size of the new region
 * @nid: nid of the new region
 *
 * Add new smmblock region [@base,@base+@size) into @type.  The new region
 * is allowed to overlap with existing ones - overlaps don't affect already
 * existing regions.  @type is guaranteed to be minimal (all neighbouring
 * compatible regions are merged) after the addition.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
static int smmblock_add_region(struct smmblock_type *type, phys_addr_t base,
			       phys_addr_t size, int nid)
{
	bool insert = false;
	phys_addr_t obase = base;
	phys_addr_t end = base + smmblock_cap_size(base, &size);
	int i, nr_new;

	if (!size)
		return 0;

	/* special case for empty array */
	if (type->regions[0].size == 0) {
		WARN_ON(type->cnt != 1 || type->total_size);
		type->regions[0].base = base;
		type->regions[0].size = size;
		smmblock_set_region_node(&type->regions[0], nid);
		type->total_size = size;
		return 0;
	}
repeat:
	/*
	 * The following is executed twice.  Once with %false @insert and
	 * then with %true.  The first counts the number of regions needed
	 * to accomodate the new area.  The second actually inserts them.
	 */
	base = obase;
	nr_new = 0;

	for (i = 0; i < type->cnt; i++) {
		struct smmblock_region *rgn = &type->regions[i];
		phys_addr_t rbase = rgn->base;
		phys_addr_t rend = rbase + rgn->size;

		if (rbase >= end)
			break;
		if (rend <= base)
			continue;
		/*
		 * @rgn overlaps.  If it separates the lower part of new
		 * area, insert that portion.
		 */
		if (rbase > base) {
			nr_new++;
			if (insert)
				smmblock_insert_region(type, i++, base,
						       rbase - base, nid);
		}
		/* area below @rend is dealt with, forget about it */
		base = min(rend, end);
	}

	/* insert the remaining portion */
	if (base < end) {
		nr_new++;
		if (insert)
			smmblock_insert_region(type, i, base, end - base, nid);
	}

	/*
	 * If this was the first round, resize array and repeat for actual
	 * insertions; otherwise, merge and return.
	 */
	if (!insert) {
		while (type->cnt + nr_new > type->max)
			if (smmblock_double_array(type, obase, size) < 0)
				return -ENOMEM;
		insert = true;
		goto repeat;
	} else {
		smmblock_merge_regions(type);
		return 0;
	}
}

int smmblock_add_node(phys_addr_t base, phys_addr_t size, int nid)
{
	return smmblock_add_region(&smmblock.memory, base, size, nid);
}

int smmblock_add(phys_addr_t base, phys_addr_t size)
{
	return smmblock_add_region(&smmblock.memory, base, size,
				   MCK_MAX_NUMNODES);
}

/**
 * smmblock_isolate_range - isolate given range into disjoint smmblocks
 * @type: smmblock type to isolate range for
 * @base: base of range to isolate
 * @size: size of range to isolate
 * @start_rgn: out parameter for the start of isolated region
 * @end_rgn: out parameter for the end of isolated region
 *
 * Walk @type and ensure that regions don't cross the boundaries defined by
 * [@base,@base+@size).  Crossing regions are split at the boundaries,
 * which may create at most two more regions.  The index of the first
 * region inside the range is returned in *@start_rgn and end in *@end_rgn.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
static int smmblock_isolate_range(struct smmblock_type *type, phys_addr_t base,
				  phys_addr_t size, int *start_rgn,
				  int *end_rgn)
{
	phys_addr_t end = base + smmblock_cap_size(base, &size);
	int i;

	*start_rgn = *end_rgn = 0;

	if (!size)
		return 0;

	/* we'll create at most two more regions */
	while (type->cnt + 2 > type->max)
		if (smmblock_double_array(type, base, size) < 0)
			return -ENOMEM;

	for (i = 0; i < type->cnt; i++) {
		struct smmblock_region *rgn = &type->regions[i];
		phys_addr_t rbase = rgn->base;
		phys_addr_t rend = rbase + rgn->size;

		if (rbase >= end)
			break;
		if (rend <= base)
			continue;

		if (rbase < base) {
			/*
			 * @rgn intersects from below.  Split and continue
			 * to process the next region - the new top half.
			 */
			rgn->base = base;
			rgn->size -= base - rbase;
			type->total_size -= base - rbase;
			smmblock_insert_region(type, i, rbase, base - rbase,
					       smmblock_get_region_node(rgn));
		} else if (rend > end) {
			/*
			 * @rgn intersects from above.  Split and redo the
			 * current region - the new bottom half.
			 */
			rgn->base = end;
			rgn->size -= end - rbase;
			type->total_size -= end - rbase;
			smmblock_insert_region(type, i--, rbase, end - rbase,
					       smmblock_get_region_node(rgn));
		} else {
			/* @rgn is fully contained, record it */
			if (!*end_rgn)
				*start_rgn = i;
			*end_rgn = i + 1;
		}
	}

	return 0;
}

static int __smmblock_remove(struct smmblock_type *type, phys_addr_t base,
			     phys_addr_t size)
{
	int start_rgn, end_rgn;
	int i, ret;
	unsigned long flags;

	spin_lock_irqsave(&smmblock_lock, flags);
	ret = smmblock_isolate_range(type, base, size, &start_rgn, &end_rgn);
	if (ret) {
		spin_unlock_irqrestore(&smmblock_lock, flags);
		return ret;
	}

	for (i = end_rgn - 1; i >= start_rgn; i--)
		smmblock_remove_region(type, i);
	spin_unlock_irqrestore(&smmblock_lock, flags);
	return 0;
}

int smmblock_remove(phys_addr_t base, phys_addr_t size)
{
	return __smmblock_remove(&smmblock.memory, base, size);
}

int smmblock_free(phys_addr_t base, phys_addr_t size)
{
	smmblock_dbg("   smmblock_free: [%#016llx-%#016llx] %pF\n",
		     (unsigned long long)base, (unsigned long long)base + size,
		     (void *)_RET_IP_);

	return __smmblock_remove(&smmblock.reserved, base, size);
}

int smmblock_reserve(phys_addr_t base, phys_addr_t size)
{
	struct smmblock_type *_rgn = &smmblock.reserved;

	smmblock_dbg("smmblock_reserve: [%#016llx-%#016llx] %pF\n",
		     (unsigned long long)base, (unsigned long long)base + size,
		     (void *)_RET_IP_);

	return smmblock_add_region(_rgn, base, size, MCK_MAX_NUMNODES);
}

/**
 * __next_free_mckmem_range - next function for for_each_freemem_range()
 * @idx: pointer to u64 loop variable
 * @nid: nid: node selector, %MCK_MAX_NUMNODES for all nodes
 * @out_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @out_end: ptr to phys_addr_t for end address of the range, can be %NULL
 * @out_nid: ptr to int for nid of the range, can be %NULL
 *
 * Find the first free area from *@idx which matches @nid, fill the out
 * parameters, and update *@idx for the next iteration.  The lower 32bit of
 * *@idx contains index into memory region and the upper 32bit indexes the
 * areas before each reserved region.  For example, if reserved regions
 * look like the following,
 *
 *	0:[0-16), 1:[32-48), 2:[128-130)
 *
 * The upper 32bit indexes the following regions.
 *
 *	0:[0-0), 1:[16-32), 2:[48-128), 3:[130-MAX)
 *
 * As both region arrays are sorted, the function advances the two indices
 * in lockstep and returns each intersection.
 */
void __next_free_mckmem_range(u64 *idx, int nid, phys_addr_t *out_start,
			      phys_addr_t *out_end, int *out_nid)
{
	struct smmblock_type *mem = &smmblock.memory;
	struct smmblock_type *rsv = &smmblock.reserved;
	int mi = *idx & 0xffffffff;
	int ri = *idx >> 32;

	for (; mi < mem->cnt; mi++) {
		struct smmblock_region *m = &mem->regions[mi];
		phys_addr_t m_start = m->base;
		phys_addr_t m_end = m->base + m->size;

		/* only memory regions are associated with nodes, check it */
		if (nid != MCK_MAX_NUMNODES &&
		    nid != smmblock_get_region_node(m))
			continue;

		/* scan areas before each reservation for intersection */
		for (; ri < rsv->cnt + 1; ri++) {
			struct smmblock_region *r = &rsv->regions[ri];
			phys_addr_t r_start = ri ? r[-1].base + r[-1].size : 0;
			phys_addr_t r_end =
				ri < rsv->cnt ? r->base : ULLONG_MAX;

			/* if ri advanced past mi, break out to advance mi */
			if (r_start >= m_end)
				break;
			/* if the two regions intersect, we're done */
			if (m_start < r_end) {
				if (out_start)
					*out_start = max(m_start, r_start);
				if (out_end)
					*out_end = min(m_end, r_end);
				if (out_nid)
					*out_nid = smmblock_get_region_node(m);
				/*
				 * The region which ends first is advanced
				 * for the next iteration.
				 */
				if (m_end <= r_end)
					mi++;
				else
					ri++;
				*idx = (u32)mi | (u64)ri << 32;
				return;
			}
		}
	}

	/* signal end of iteration */
	*idx = ULLONG_MAX;
}

/**
 * __next_free_mckmem_range_rev - next function for for_each_freemem_range_reverse()
 * @idx: pointer to u64 loop variable
 * @nid: nid: node selector, %MCK_MAX_NUMNODES for all nodes
 * @out_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @out_end: ptr to phys_addr_t for end address of the range, can be %NULL
 * @out_nid: ptr to int for nid of the range, can be %NULL
 *
 * Reverse of __next_free_mckmem_range().
 */
void __next_free_mckmem_range_rev(u64 *idx, int nid, phys_addr_t *out_start,
				  phys_addr_t *out_end, int *out_nid)
{
	struct smmblock_type *mem = &smmblock.memory;
	struct smmblock_type *rsv = &smmblock.reserved;
	int mi = *idx & 0xffffffff;
	int ri = *idx >> 32;

	if (*idx == (u64)ULLONG_MAX) {
		mi = mem->cnt - 1;
		ri = rsv->cnt;
	}

	for (; mi >= 0; mi--) {
		struct smmblock_region *m = &mem->regions[mi];
		phys_addr_t m_start = m->base;
		phys_addr_t m_end = m->base + m->size;

		/* only memory regions are associated with nodes, check it */
		if (nid != MCK_MAX_NUMNODES &&
		    nid != smmblock_get_region_node(m))
			continue;

		/* scan areas before each reservation for intersection */
		for (; ri >= 0; ri--) {
			struct smmblock_region *r = &rsv->regions[ri];
			phys_addr_t r_start = ri ? r[-1].base + r[-1].size : 0;
			phys_addr_t r_end =
				ri < rsv->cnt ? r->base : ULLONG_MAX;

			/* if ri advanced past mi, break out to advance mi */
			if (r_end <= m_start)
				break;
			/* if the two regions intersect, we're done */
			if (m_end > r_start) {
				if (out_start)
					*out_start = max(m_start, r_start);
				if (out_end)
					*out_end = min(m_end, r_end);
				if (out_nid)
					*out_nid = smmblock_get_region_node(m);

				if (m_start >= r_start)
					mi--;
				else
					ri--;
				*idx = (u32)mi | (u64)ri << 32;
				return;
			}
		}
	}

	*idx = ULLONG_MAX;
}

/*
 * Common iterator interface used to define for_each_mem_range().
 */
void __next_mckmem_pfn_range(int *idx, int nid, unsigned long *out_start_pfn,
			     unsigned long *out_end_pfn, int *out_nid)
{
	struct smmblock_type *type = &smmblock.memory;
	struct smmblock_region *r;

	while (++*idx < type->cnt) {
		r = &type->regions[*idx];

		if (PFN_UP(r->base) >= PFN_DOWN(r->base + r->size))
			continue;
		if (nid == MCK_MAX_NUMNODES || nid == r->nid)
			break;
	}
	if (*idx >= type->cnt) {
		*idx = -1;
		return;
	}

	if (out_start_pfn)
		*out_start_pfn = PFN_UP(r->base);
	if (out_end_pfn)
		*out_end_pfn = PFN_DOWN(r->base + r->size);
	if (out_nid)
		*out_nid = r->nid;
}

/**
 * smmblock_set_node - set node ID on smmblock regions
 * @base: base of area to set node ID for
 * @size: size of area to set node ID for
 * @nid: node ID to set
 *
 * Set the nid of smmblock memory regions in [@base,@base+@size) to @nid.
 * Regions which cross the area boundaries are split as necessary.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
int smmblock_set_node(phys_addr_t base, phys_addr_t size, int nid)
{
	struct smmblock_type *type = &smmblock.memory;
	int start_rgn, end_rgn;
	int i, ret;

	ret = smmblock_isolate_range(type, base, size, &start_rgn, &end_rgn);
	if (ret)
		return ret;

	for (i = start_rgn; i < end_rgn; i++)
		smmblock_set_region_node(&type->regions[i], nid);

	smmblock_merge_regions(type);
	return 0;
}

static phys_addr_t smmblock_alloc_base_nid(phys_addr_t size, phys_addr_t align,
					   phys_addr_t max_addr, int nid)
{
	phys_addr_t found;
	unsigned long flags;

	BUG_ON(align == 0);
	/* align @size to avoid excessive fragmentation on reserved array */
	size = round_up(size, align);

	spin_lock_irqsave(&smmblock_lock, flags);
	found = smmblock_find_in_range_node(0, max_addr, size, align, nid);
	if (found && !smmblock_reserve(found, size)) {
		spin_unlock_irqrestore(&smmblock_lock, flags);
		return found;
	}

	spin_unlock_irqrestore(&smmblock_lock, flags);
	return 0;
}

static phys_addr_t smmblock_alloc_base_nid_bottom_up(phys_addr_t size,
						     phys_addr_t align,
						     phys_addr_t max_addr,
						     int nid)
{
	phys_addr_t found;
	unsigned long flags;

	BUG_ON(align == 0);
	/* align @size to avoid excessive fragmentation on reserved array */
	size = round_up(size, align);

	spin_lock_irqsave(&smmblock_lock, flags);
	found = smmblock_find_in_range_node_reverse(0, max_addr, size, align,
						    nid);
	if (found && !smmblock_reserve(found, size)) {
		spin_unlock_irqrestore(&smmblock_lock, flags);
		return found;
	}

	spin_unlock_irqrestore(&smmblock_lock, flags);
	return 0;
}

phys_addr_t smmblock_alloc_nid_bottom_up(phys_addr_t size, phys_addr_t align,
					 int nid)
{
	return smmblock_alloc_base_nid_bottom_up(
		size, align, TSPBLOCK_ALLOC_ACCESSIBLE, nid);
}

phys_addr_t smmblock_alloc_nid(phys_addr_t size, phys_addr_t align, int nid)
{
	return smmblock_alloc_base_nid(size, align, TSPBLOCK_ALLOC_ACCESSIBLE,
				       nid);
}

phys_addr_t __smmblock_alloc_base(phys_addr_t size, phys_addr_t align,
				  phys_addr_t max_addr)
{
	return smmblock_alloc_base_nid(size, align, max_addr, MCK_MAX_NUMNODES);
}

phys_addr_t __smmblock_alloc_base_bottom_up(phys_addr_t size, phys_addr_t align,
					    phys_addr_t max_addr)
{
	return smmblock_alloc_base_nid_bottom_up(size, align, max_addr,
						 MCK_MAX_NUMNODES);
}

phys_addr_t smmblock_alloc_base_bottom_up(phys_addr_t size, phys_addr_t align,
					  phys_addr_t max_addr)
{
	phys_addr_t alloc;

	alloc = __smmblock_alloc_base_bottom_up(size, align, max_addr);

	if (alloc == 0)
		printk("TSP ERROR: Failed to allocate 0x%llx bytes below "
		       "0x%llx.\n",
		       (unsigned long long)size, (unsigned long long)max_addr);

	return alloc;
}

phys_addr_t smmblock_alloc_base(phys_addr_t size, phys_addr_t align,
				phys_addr_t max_addr)
{
	phys_addr_t alloc;

	alloc = __smmblock_alloc_base(size, align, max_addr);

	if (alloc == 0)
		printk("TSP ERROR: Failed to allocate 0x%llx bytes below "
		       "0x%llx.\n",
		       (unsigned long long)size, (unsigned long long)max_addr);

	return alloc;
}

/* align should not be 0 */
phys_addr_t smmblock_alloc(phys_addr_t size, phys_addr_t align)
{
	BUG_ON(align == 0);
	return smmblock_alloc_base(size, align, TSPBLOCK_ALLOC_ACCESSIBLE);
}

/* align should not be 0 */
phys_addr_t smmblock_alloc_bottom_up(phys_addr_t size, phys_addr_t align)
{
	BUG_ON(align == 0);
	return smmblock_alloc_base_bottom_up(size, align,
					     TSPBLOCK_ALLOC_ACCESSIBLE);
}

phys_addr_t smmblock_alloc_try_nid_bottom_up(phys_addr_t size,
					     phys_addr_t align, int nid)
{
	phys_addr_t res;
	BUG_ON(align == 0);
	res = smmblock_alloc_nid_bottom_up(size, align, nid);

	if (res)
		return res;
	return smmblock_alloc_base_bottom_up(size, align,
					     TSPBLOCK_ALLOC_ACCESSIBLE);
}

phys_addr_t smmblock_alloc_try_nid(phys_addr_t size, phys_addr_t align, int nid)
{
	phys_addr_t res;
	BUG_ON(align == 0);
	res = smmblock_alloc_nid(size, align, nid);

	if (res)
		return res;
	return smmblock_alloc_base(size, align, TSPBLOCK_ALLOC_ACCESSIBLE);
}

/*
 * Remaining API functions
 */

phys_addr_t smmblock_phys_mem_size(void)
{
	return smmblock.memory.total_size;
}

/* lowest address */
phys_addr_t smmblock_start_of_DRAM(void)
{
	return smmblock.memory.regions[0].base;
}

phys_addr_t smmblock_end_of_DRAM(void)
{
	int idx = smmblock.memory.cnt - 1;

	return (smmblock.memory.regions[idx].base +
		smmblock.memory.regions[idx].size);
}

void smmblock_enforce_memory_limit(phys_addr_t limit)
{
	unsigned long i;
	phys_addr_t max_addr = (phys_addr_t)ULLONG_MAX;

	if (!limit)
		return;

	/* find out max address */
	for (i = 0; i < smmblock.memory.cnt; i++) {
		struct smmblock_region *r = &smmblock.memory.regions[i];

		if (limit <= r->size) {
			max_addr = r->base + limit;
			break;
		}
		limit -= r->size;
	}

	/* truncate both memory and reserved regions */
	__smmblock_remove(&smmblock.memory, max_addr, (phys_addr_t)ULLONG_MAX);
	__smmblock_remove(&smmblock.reserved, max_addr,
			  (phys_addr_t)ULLONG_MAX);
}

static int smmblock_search(struct smmblock_type *type, phys_addr_t addr)
{
	unsigned int left = 0, right = type->cnt;

	do {
		unsigned int mid = (right + left) / 2;

		if (addr < type->regions[mid].base)
			right = mid;
		else if (addr >=
			 (type->regions[mid].base + type->regions[mid].size))
			left = mid + 1;
		else
			return mid;
	} while (left < right);
	return -1;
}

int smmblock_is_reserved(phys_addr_t addr)
{
	return smmblock_search(&smmblock.reserved, addr) != -1;
}

int smmblock_is_memory(phys_addr_t addr)
{
	return smmblock_search(&smmblock.memory, addr) != -1;
}

/**
 * smmblock_is_region_memory - check if a region is a subset of memory
 * @base: base of region to check
 * @size: size of region to check
 *
 * Check if the region [@base, @base+@size) is a subset of a memory block.
 *
 * RETURNS:
 * 0 if false, non-zero if true
 */
int smmblock_is_region_memory(phys_addr_t base, phys_addr_t size)
{
	int idx = smmblock_search(&smmblock.memory, base);
	phys_addr_t end = base + smmblock_cap_size(base, &size);

	if (idx == -1)
		return 0;
	return smmblock.memory.regions[idx].base <= base &&
	       (smmblock.memory.regions[idx].base +
		smmblock.memory.regions[idx].size) >= end;
}

/**
 * smmblock_is_region_reserved - check if a region intersects reserved memory
 * @base: base of region to check
 * @size: size of region to check
 *
 * Check if the region [@base, @base+@size) intersects a reserved memory block.
 *
 * RETURNS:
 * 0 if false, non-zero if true
 */
int smmblock_is_region_reserved(phys_addr_t base, phys_addr_t size)
{
	smmblock_cap_size(base, &size);
	return smmblock_overlaps_region(&smmblock.reserved, base, size) >= 0;
}

void smmblock_trim_memory(phys_addr_t align)
{
	int i;
	phys_addr_t start, end, orig_start, orig_end;
	struct smmblock_type *mem = &smmblock.memory;

	for (i = 0; i < mem->cnt; i++) {
		orig_start = mem->regions[i].base;
		orig_end = mem->regions[i].base + mem->regions[i].size;
		start = round_up(orig_start, align);
		end = round_down(orig_end, align);

		if (start == orig_start && end == orig_end)
			continue;

		if (start < end) {
			mem->regions[i].base = start;
			mem->regions[i].size = end - start;
		} else {
			smmblock_remove_region(mem, i);
			i--;
		}
	}
}

void smmblock_set_current_limit(phys_addr_t limit)
{
	smmblock.current_limit = limit;
}

static void smmblock_dump(struct smmblock_type *type, char *name)
{
	unsigned long long base, size;
	int i;

	pr_info(" %s.cnt  = 0x%lx\n", name, type->cnt);

	for (i = 0; i < type->cnt; i++) {
		struct smmblock_region *rgn = &type->regions[i];
		char nid_buf[32] = "";

		base = rgn->base;
		size = rgn->size;
		if (smmblock_get_region_node(rgn) != MCK_MAX_NUMNODES)
			snprintf(nid_buf, sizeof(nid_buf), " on node %d",
				 smmblock_get_region_node(rgn));
		pr_info(" %s[%#x]\t[%#016llx-%#016llx], %#llx bytes%s\n", name,
			i, base, base + size - 1, size, nid_buf);
	}
}

void __smmblock_dump_all(void)
{
	pr_info("smmblock configuration:\n");
	pr_info(" memory size = %#llx reserved size = %#llx\n",
		(unsigned long long)smmblock.memory.total_size,
		(unsigned long long)smmblock.reserved.total_size);

	smmblock_dump(&smmblock.memory, "memory");
	smmblock_dump(&smmblock.reserved, "reserved");
}

/* Allow smmblock use kmalloc to store mblock info */
void smmblock_allow_resize(void)
{
	smmblock_can_resize = 1;
}

static void smmblock_dump_show(struct seq_file *m, struct smmblock_type *type,
			       char *name)
{
	unsigned long long base, size;
	int i;

	for (i = 0; i < type->cnt; i++) {
		struct smmblock_region *rgn = &type->regions[i];
		char nid_buf[32] = "";

		base = rgn->base;
		size = rgn->size;
		if (smmblock_get_region_node(rgn) != MCK_MAX_NUMNODES)
			snprintf(nid_buf, sizeof(nid_buf), " on node %d",
				 smmblock_get_region_node(rgn));
		seq_printf(m, " %s[%#x]\t[%#016llx-%#016llx], %#llx bytes%s\n",
			   name, i, base, base + size - 1, size, nid_buf);
	}
}

static int smmblock_proc_show(struct seq_file *m, void *v)
{
	if (smmblock.memory.total_size > 0) {
		seq_printf(m, " Memory total_size = %#llx bytes\n",
			   (unsigned long long)smmblock.memory.total_size);
		smmblock_dump_show(m, &smmblock.memory, "memory");
	}
	if (smmblock.reserved.total_size > 0) {
		seq_printf(m, " Reserved total_size = %#llx bytes\n",
			   (unsigned long long)smmblock.reserved.total_size);
		smmblock_dump_show(m, &smmblock.reserved, "reserved");
	}
	return 0;
}

static int smmblock_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, smmblock_proc_show, NULL);
}

static const struct proc_ops smmblock_proc_fops = {
	.proc_open = smmblock_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = seq_release_private,
};

static int __init proc_smmblock_init(void)
{
	proc_create("smmblock", 0444, NULL, &smmblock_proc_fops);
	return 0;
}
fs_initcall(proc_smmblock_init);

void smm_destroy(struct smm *smm)
{
	if (!smm)
		return;

	if (smm->code_segment_paddr && smm->code_segment_size)
		smmblock_free(smm->code_segment_paddr, smm->code_segment_size);

	if (smm->heap_segment_paddr && smm->heap_segment_size)
		smmblock_free(smm->heap_segment_paddr, smm->heap_segment_size);

	if (smm->mmap_segment_paddr && smm->mmap_segment_size)
		smmblock_free(smm->mmap_segment_paddr, smm->mmap_segment_size);

	if (smm->stack_segment_paddr && smm->stack_segment_size)
		smmblock_free(smm->stack_segment_paddr,
			      smm->stack_segment_size);

#if 0
	printk("TSP FREE: [%s %d] CODE:%#lx HEAP:%#lx MMAP:%#lx STACK:%#lx\n",
	       current->comm, current->pid,
	       smm->code_segment_size, smm->heap_segment_size,
	       smm->mmap_segment_size, smm->stack_segment_size);
#endif
	kfree(smm);
}

struct smm *smm_alloc(unsigned long code_size, unsigned long heap_size,
		      unsigned long mmap_size, unsigned long stack_size)
{
	struct smm *smm = NULL;
	unsigned long addr;
	struct page *page;

	smm = kzalloc(sizeof(struct smm), GFP_KERNEL);
	if (!smm)
		return ERR_PTR(-ENOMEM);

	if (current->mm->smm_pud)
		smm->mmap_segment_paddr = smmblock_alloc(mmap_size, PUD_SIZE);
	else if (current->mm->smm_pmd)
		smm->mmap_segment_paddr = smmblock_alloc(mmap_size, PMD_SIZE);
	else 
		smm->mmap_segment_paddr = smmblock_alloc(mmap_size, PMD_SIZE);

	if (!smm->mmap_segment_paddr) {
		smm_destroy(smm);
		return ERR_PTR(-ENOMEM);
	}
	smm->mmap_segment_size = mmap_size;

	smm->code_segment_paddr = smmblock_alloc(code_size, PMD_SIZE);
	if (!smm->code_segment_paddr) {
		smm_destroy(smm);
		return ERR_PTR(-ENOMEM);
	}
	smm->code_segment_size = code_size;

	if (current->mm->smm_pud)
		smm->heap_segment_paddr = smmblock_alloc(heap_size, PUD_SIZE);
	else if (current->mm->smm_pmd)
		smm->heap_segment_paddr = smmblock_alloc(heap_size, PMD_SIZE);
	else
		smm->heap_segment_paddr = smmblock_alloc(heap_size, PMD_SIZE);

	if (!smm->heap_segment_paddr) {
		smm_destroy(smm);
		return ERR_PTR(-ENOMEM);
	}
	smm->heap_segment_size = heap_size;

	smm->stack_segment_paddr = smmblock_alloc(stack_size, PMD_SIZE);
	if (!smm->stack_segment_paddr) {
		smm_destroy(smm);
		return ERR_PTR(-ENOMEM);
	}
	smm->stack_segment_size = stack_size;

	smm->mm = current->mm;
	smm->task = current;
	atomic_set(&smm->users_count, 0);

	for (addr = smm->code_segment_paddr;
	     addr < (smm->code_segment_paddr + code_size); addr += PAGE_SIZE) {
		page = pfn_to_page(addr >> PAGE_SHIFT);
		prep_new_smm_page(page);
		//memset(__va(addr), 0, PAGE_SIZE);
	}
	for (addr = smm->mmap_segment_paddr;
	     addr < (smm->mmap_segment_paddr + mmap_size); addr += PAGE_SIZE) {
		page = pfn_to_page(addr >> PAGE_SHIFT);
		prep_new_smm_page(page);
		//memset(__va(addr), 0, PAGE_SIZE);
	}

	for (addr = smm->heap_segment_paddr;
	     addr < (smm->heap_segment_paddr + heap_size); addr += PAGE_SIZE) {
		page = pfn_to_page(addr >> PAGE_SHIFT);
		prep_new_smm_page(page);
		//memset(__va(addr), 0, PAGE_SIZE);
	}

	for (addr = smm->stack_segment_paddr;
	     addr < (smm->stack_segment_paddr + stack_size);
	     addr += PAGE_SIZE) {
		page = pfn_to_page(addr >> PAGE_SHIFT);
		prep_new_smm_page(page);
		//memset(__va(addr), 0, PAGE_SIZE);
	}

#if 0
	printk("TSP ALLOC: [%s %d] CODE:%#lx HEAP:%#lx MMAP:%#lx STACK:%#lx\n",
	       current->comm, current->pid,
	       smm->code_segment_size, smm->heap_segment_size,
	       smm->mmap_segment_size, smm->stack_segment_size);
#endif
	return smm;
}

void get_smm(struct smm *smm)
{
	atomic_inc(&smm->users_count);
}

void put_smm(struct smm *smm)
{
	if (atomic_dec_and_test(&smm->users_count)) {
		smm_destroy(smm);
	}
}

static int smm_release(struct inode *inode, struct file *filp)
{
	struct smm *smm = filp->private_data;

	put_smm(smm);

	return 0;
}

static long smm_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	int r;
	switch (ioctl) {
	case TSP_SWAP: {
		r = smm_swap_current();
		break;
	}
	default:
		r = -EOPNOTSUPP;
		break;
	}
	return r;
}

struct file_operations smm_fops = {
	.release = smm_release,
	.unlocked_ioctl = smm_ioctl,
	.compat_ioctl = smm_ioctl,
	.llseek = noop_llseek,
};

void dup_smm_page(struct page *old_page, struct page *smm_page)
{
	unsigned long flags;
	smm_page->flags = smm_page->flags & (~((1UL << NR_PAGEFLAGS) - 1));
	flags = (old_page->flags) & ((1UL << NR_PAGEFLAGS) - 1);
	smm_page->flags =
		(smm_page->flags & (~(1UL << NR_PAGEFLAGS) - 1)) | flags;
	SetPageSmm(smm_page);
	ClearPageLRU(smm_page);

	smm_page->smm_buddy_page = old_page;
	smm_page->mapping = old_page->mapping;
	smm_page->_refcount.counter = old_page->_refcount.counter;
	smm_page->_mapcount.counter = old_page->_mapcount.counter;
	smm_page->index = old_page->index;
#ifdef CONFIG_MEMCG
	smm_page->mem_cgroup = old_page->mem_cgroup;
#endif
#if 0
	printk("[%s %d],dup_smm_page:%#lx old flag: %#lx PageSmm:%d PageDirty:%d PageLoced:%d\n",
					current->comm, current->pid,
					(unsigned long)smm_page,
					flags,
					PageSmm(smm_page), PageDirty(smm_page), PageLocked(smm_page));
#endif

#if 0
	if (!PageAnon(old_page)) {
		__SetPageLocked(smm_page);
		SetPageDirty(smm_page);
		SetPagePrivate(smm_page);
	}
#endif
}

unsigned long smm_vaddr_to_paddr(struct smm *smm, unsigned long vaddr)
{
	unsigned long offset;
	BUG_ON(smm == NULL);

	if (smm_vaddr_is_code(vaddr)) {
		offset = vaddr - TSP_SEGMENT_BASE_CODE;
		if (offset > smm->code_segment_size)
			return 0;
		return (smm->code_segment_paddr + offset);
	} else if (smm_vaddr_is_heap(vaddr)) {
		offset = vaddr - TSP_SEGMENT_BASE_HEAP;
		if (offset > smm->heap_segment_size)
			return 0;
		return (smm->heap_segment_paddr + offset);
	} else if (smm_vaddr_is_mmap(vaddr)) {
		offset = vaddr - TSP_SEGMENT_BASE_MMAP;
		if (offset > smm->mmap_segment_size)
			return 0;
		return (smm->mmap_segment_paddr + offset);
	} else if (smm_vaddr_is_stack(vaddr)) {
		offset = TSP_SEGMENT_TOP_STACK + 1 - vaddr;
		if (offset > smm->stack_segment_size)
			return 0;
		return (smm->stack_segment_paddr + smm->stack_segment_size -
			offset);
	} else {
		return 0;
	}
}

static int check_smm_pte_range(struct vm_area_struct *vma, pmd_t *pmd,
			       unsigned long addr, unsigned long end,
			       pgprot_t prot)
{
	pte_t *pte;
	int err = 0;
	struct smm *smm = vma->vm_mm->smm;
	unsigned long pte_paddr, smm_paddr;

	if (smm == NULL)
		return -EFAULT;

	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
		return 0;

	pte = pte_offset_map(pmd, addr);
	arch_enter_lazy_mmu_mode();
	do {
		if (!pte_present(*pte) || (pte_none(*pte)) ||
		    !(pte_accessible(vma->vm_mm, *pte)))
			continue;
		WARN_ON_ONCE(is_zero_pfn(pte_pfn(*pte)));
		pte_paddr = (pte_pfn(*pte)) << PAGE_SHIFT;
		smm_paddr = smm_vaddr_to_paddr(smm, addr);
		if (smm_paddr != pte_paddr) {
			printk("[%s %d] addr %#lx check failed, "
			       "pte_paddr = %#lx, smm_paddr = %#lx\n",
			       current->comm, current->pid, addr, pte_paddr,
			       smm_paddr);
			return -EINVAL;
		}
	} while (pte++, addr += PAGE_SIZE, addr != end);
	arch_leave_lazy_mmu_mode();
	return err;
}

int swap_pte_range(struct vm_area_struct *vma, pmd_t *pmd, unsigned long addr,
		   unsigned long end)
{
	pte_t *pte;
	pte_t *start_pte;
	spinlock_t *ptl;
	int err = 0;
	unsigned long smm_paddr, pte_paddr;
	struct page *old_page, *new_page;
	pgprot_t old_prot;
	struct mm_struct *mm = vma->vm_mm;
	struct smm *smm = vma->vm_mm->smm;

#if 0
	printk("SWAP_PTE_RANGE: [%#lx - %#lx] addr %#lx end %#lx pmd:%#lx\n",
			vma->vm_start, vma->vm_end, addr, end, (unsigned long)(pmd));
#endif
	BUG_ON(end <= addr);

	if (smm == NULL)
		return -ENOMEM;

	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
		return 0;

	if (pmd_smm_huge(*pmd)) {
		return 0;
	}

	start_pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
	pte = start_pte;
	do {
		pte_t ptent = *pte;
		pte_t entry;

		if (pte_none(ptent))
			continue;
		if (pte_present(ptent)) {
			struct page *page = pte_page(ptent);

			if (PageSmm(page)) {
#if 0
				printk("swap_pte[%s %d] %#lx [%#lx - %#lx]\n", 
						current->comm, current->pid,
						addr, 
						vma->vm_start, vma->vm_end);
#endif
				continue;
			}

			pte_paddr = (pte_pfn(*pte)) << PAGE_SHIFT;
			smm_paddr = smm_vaddr_to_paddr(smm, addr);

			if (smm_paddr == 0)
				continue;

			if (smm_vaddr_is_mmap(addr))
				mm->smm->mmap_segment_swapped += PAGE_SIZE;
			if (smm_vaddr_is_code(addr))
				mm->smm->code_segment_swapped += PAGE_SIZE;
			if (smm_vaddr_is_heap(addr))
				mm->smm->heap_segment_swapped += PAGE_SIZE;
			if (smm_vaddr_is_stack(addr))
				mm->smm->stack_segment_swapped += PAGE_SIZE;

			copy_page((void *)__va(smm_paddr),
				  (void *)__va(pte_paddr));
			old_prot = pte_pgprot(*pte);
			entry = pfn_pte(smm_paddr >> PAGE_SHIFT, old_prot);
// Avoid copy-on-write for some file page
#if 0
			if (!pte_write(*pte))
				*pte = pte_mkwrite(*pte);
#endif
			old_page = pfn_to_page(pte_paddr >> PAGE_SHIFT);
			new_page = pfn_to_page(smm_paddr >> PAGE_SHIFT);

			dup_smm_page(old_page, new_page);

			flush_tlb_page(vma, addr);
			set_pte_at(vma->vm_mm, addr, pte, entry);
#if 0
			if (PageAnon(old_page)) {
				new_page->smm_buddy_page = NULL;
				page_remove_rmap(old_page, false);
				put_page(old_page);
			}
#endif
		}
	} while (pte++, addr += PAGE_SIZE, addr != end);
	pte_unmap_unlock(start_pte, ptl);
	return err;
}

static inline int check_smm_pmd_range(struct vm_area_struct *vma, pud_t *pud,
				      unsigned long addr, unsigned long end,
				      pgprot_t prot)
{
	pmd_t *pmd;
	unsigned long next;
	int err;

	pmd = pmd_offset(pud, addr);
	VM_BUG_ON(pmd_trans_huge(*pmd));
	do {
		next = pmd_addr_end(addr, end);
		err = check_smm_pte_range(vma, pmd, addr, next, prot);
		if (err)
			return err;
	} while (pmd++, addr = next, addr != end);
	return 0;
}

int swap_pmd_range(struct vm_area_struct *vma, pud_t *pud, unsigned long addr,
		   unsigned long end)
{
	pmd_t *pmd;
	unsigned long next;
	int err;

	pmd = pmd_offset(pud, addr);
	if (!pmd)
		return -ENOMEM;
	VM_BUG_ON(pmd_trans_huge(*pmd));
	do {
		next = pmd_addr_end(addr, end);
		err = swap_pte_range(vma, pmd, addr, next);
		if (err)
			return err;
	} while (pmd++, addr = next, addr != end);
	return 0;
}

static inline int check_smm_pud_range(struct vm_area_struct *vma, p4d_t *p4d,
				      unsigned long addr, unsigned long end,
				      pgprot_t prot)
{
	pud_t *pud;
	unsigned long next;
	int err;

	pud = pud_offset(p4d, addr);
	do {
		next = pud_addr_end(addr, end);
		err = check_smm_pmd_range(vma, pud, addr, next, prot);
		if (err)
			return err;
	} while (pud++, addr = next, addr != end);
	return 0;
}

int swap_pud_range(struct vm_area_struct *vma, p4d_t *p4d, unsigned long addr,
		   unsigned long end)
{
	pud_t *pud;
	unsigned long next;
	int err;

	pud = pud_offset(p4d, addr);
	if (!pud)
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		err = swap_pmd_range(vma, pud, addr, next);
		if (err)
			return err;
	} while (pud++, addr = next, addr != end);
	return 0;
}

static inline int check_smm_p4d_range(struct vm_area_struct *vma, pgd_t *pgd,
				      unsigned long addr, unsigned long end,
				      pgprot_t prot)
{
	p4d_t *p4d;
	unsigned long next;
	int err;

	p4d = p4d_offset(pgd, addr);
	if (!p4d)
		return -ENOMEM;
	do {
		next = p4d_addr_end(addr, end);
		err = check_smm_pud_range(vma, p4d, addr, next, prot);
		if (err)
			return err;
	} while (p4d++, addr = next, addr != end);
	return 0;
}

int swap_p4d_range(struct vm_area_struct *vma, pgd_t *pgd, unsigned long addr,
		   unsigned long end)
{
	p4d_t *p4d;
	unsigned long next;
	int err;

	p4d = p4d_offset(pgd, addr);
	if (!p4d)
		return -ENOMEM;
	do {
		next = p4d_addr_end(addr, end);
		err = swap_pud_range(vma, p4d, addr, next);
		if (err)
			return err;
	} while (p4d++, addr = next, addr != end);
	return 0;
}

int check_smm_range(struct vm_area_struct *vma, unsigned long addr,
		    unsigned long size, pgprot_t prot)
{
	pgd_t *pgd;
	unsigned long next;
	unsigned long end = addr + PAGE_ALIGN(size);
	struct mm_struct *mm = vma->vm_mm;
	int err = 0;

#if 0
	printk("TSP CHECK [%lx - %lx] vm_flags %lx, vm_page_prot %lx, "
	       "vm_pgoff: %lx , err = %d\n",
	       addr, end, vma->vm_flags, vma->vm_page_prot.pgprot,
	       vma->vm_pgoff, err);
#endif
	BUG_ON(addr >= end);
	pgd = pgd_offset(mm, addr);
	flush_cache_range(vma, addr, end);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		err = check_smm_p4d_range(vma, pgd, addr, next, prot);
		if (err)
			break;
	} while (pgd++, addr = next, addr != end);

	return err;
}

static int __coalesce_pud_check(struct vm_area_struct *vma,
				unsigned long address, pmd_t *pmd)
{
	pmd_t *_pmd;

	for (_pmd = pmd; _pmd < pmd + TSP_HPAGE_PMD_NR;
	     _pmd++, address += PMD_SIZE) {
		pmd_t pmdval = *_pmd;
		unsigned long pfn =
			smm_vaddr_to_paddr(vma->vm_mm->smm, address) >>
			PAGE_SHIFT;
		if (pmd_none(pmdval))
			goto out;
		if (!pmd_present(pmdval))
			goto out;
		if (pfn != pmd_pfn(pmdval))
			goto out;
	}
	return 1;

out:
	return 0;
}

static int __coalesce_pmd_check(struct vm_area_struct *vma,
				unsigned long address, pte_t *pte)
{
	pte_t *_pte;

	for (_pte = pte; _pte < pte + TSP_HPAGE_PMD_NR;
	     _pte++, address += PAGE_SIZE) {
		pte_t pteval = *_pte;
		unsigned long pfn =
			smm_vaddr_to_paddr(vma->vm_mm->smm, address) >>
			PAGE_SHIFT;
		if (pte_none(pteval))
			goto out;
		if (!pte_present(pteval))
			goto out;
		if (pfn != pte_pfn(pteval))
			goto out;
	}
	return 1;

out:
	return 0;
}

pud_t *mm_find_pud(struct mm_struct *mm, unsigned long address)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud = NULL;

	pgd = pgd_offset(mm, address);
	if (!pgd_present(*pgd))
		goto out;

	p4d = p4d_offset(pgd, address);
	if (!p4d_present(*p4d))
		goto out;

	pud = pud_offset(p4d, address);
	if (!pud_present(*pud) || pud_smm_huge(*pud)) 
		pud = NULL;
out:
	return pud;
}


int coalesce_smm_pud(struct vm_area_struct *vma, unsigned long address)
{
	pud_t *pud, _pud;
	pmd_t *pmd;
	struct page *page;
	int ok;
	struct mm_struct *mm = vma->vm_mm;
	struct mmu_notifier_range range;
	spinlock_t *pud_ptl, *pmd_ptl;
	pgtable_t token;

	if (!is_vma_smm_swapped(vma))
		return 0;

	if (!vma_is_anonymous(vma))
		return 0;

	VM_BUG_ON(address & ~TSP_HPAGE_PUD_MASK);

	down_write(&mm->mmap_sem);

	pud = mm_find_pud(mm, address);
	if (!pud) {
		goto out;
	}
	pud_ptl = pud_lockptr(mm, pud);
	pmd = pmd_offset(pud, address);

	spin_lock(pud_ptl);
	ok = __coalesce_pud_check(vma, address, pmd);
	spin_unlock(pud_ptl);

	if (ok)
		printk("[%s %d] pud %#lx ok\n",current->comm, current->pid, address);

out:
	up_write(&mm->mmap_sem);
	return 0;
}

int coalesce_smm_pmd(struct vm_area_struct *vma, unsigned long address)
{
	pmd_t *pmd, _pmd;
	pte_t *pte;
	struct page *page;
	int ok;
	struct mm_struct *mm = vma->vm_mm;
	struct mmu_notifier_range range;
	spinlock_t *pmd_ptl, *pte_ptl;
	pgtable_t token;

	if (!is_vma_smm_swapped(vma))
		return 0;

	if (!vma_is_anonymous(vma))
		return 0;

	VM_BUG_ON(address & ~TSP_HPAGE_PMD_MASK);

	down_write(&mm->mmap_sem);

	pmd = mm_find_pmd(mm, address);
	if (!pmd) {
		goto out;
	}

	anon_vma_lock_write(vma->anon_vma);

	mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, NULL, mm, address,
				address + TSP_HPAGE_PMD_SIZE);
	mmu_notifier_invalidate_range_start(&range);

	pte = pte_offset_map(pmd, address);
	pte_ptl = pte_lockptr(mm, pmd);

	pmd_ptl = pmd_lock(mm, pmd); /* probably unnecessary */

	_pmd = pmdp_huge_get_and_clear(vma->vm_mm, address, pmd);

	/* collapse entails shooting down ptes not pmd */
	flush_tlb_range(vma, address, address + TSP_HPAGE_PMD_SIZE);

	spin_unlock(pmd_ptl);
	mmu_notifier_invalidate_range_end(&range);

	spin_lock(pte_ptl);
	ok = __coalesce_pmd_check(vma, address, pte);
	spin_unlock(pte_ptl);

	if (unlikely(!ok)) {
		pte_unmap(pte);
		spin_lock(pmd_ptl);
		BUG_ON(!pmd_none(*pmd));
		/*
		 * We can only use set_pmd_at when establishing
		 * hugepmds and never for establishing regular pmds that
		 * points to regular pagetables. Use pmd_populate for that
		 */
		pmd_populate(mm, pmd, pmd_pgtable(_pmd));
		spin_unlock(pmd_ptl);
		anon_vma_unlock_write(vma->anon_vma);
		goto out;
	}

	anon_vma_unlock_write(vma->anon_vma);
	pte_unmap(pte);

	token = pmd_pgtable(*pmd);
	page = pfn_to_page(smm_vaddr_to_paddr(vma->vm_mm->smm, address) >>
			   PAGE_SHIFT);

	prep_new_smm_page(page);
	__SetPageUptodate(page);

	_pmd = mk_huge_pmd(page, vma->vm_page_prot);
	_pmd = smm_maybe_pmd_mkwrite(pmd_mkdirty(_pmd), vma);

	smp_wmb();
	spin_lock(pmd_ptl);
	BUG_ON(!pmd_none(*pmd));
	page_add_new_anon_rmap(page, vma, address, false);
	pgtable_pte_page_dtor(token);
	set_pmd_at(vma->vm_mm, address, pmd, _pmd);
	update_mmu_cache_pmd(vma, address, pmd);
	spin_unlock(pmd_ptl);
	pte_free(vma->vm_mm, token);
	vma->vm_mm->smm_coalesce_pmd_count++;
	mm_dec_nr_ptes(vma->vm_mm);
#if 0
	printk("[%s %d] coalesce_smm_pmd %#lx vma [%#lx - %#lx] pmd:%#lx\n",
			current->comm, current->pid,
			address,  vma->vm_start, vma->vm_end, pmd_val(_pmd));
#endif
out:
	up_write(&mm->mmap_sem);
	return 0;
}

int coalesce_smm_vma(struct vm_area_struct *vma)
{
	int err = 0;
	unsigned long hstart =
		(vma->vm_start + ~TSP_HPAGE_PMD_MASK) & TSP_HPAGE_PMD_MASK;
	unsigned long hend = vma->vm_end & TSP_HPAGE_PMD_MASK;
	unsigned long addr;

	if (!is_vma_smm_swapped(vma))
		return 0;

	if (!vma_is_anonymous(vma))
		return 0;

	if (addr < hstart)
		addr = hstart;

	while (addr < hend) {
		if ((addr + TSP_HPAGE_PMD_SIZE) <= hend)
			err = coalesce_smm_pmd(vma, addr);
		addr += TSP_HPAGE_PMD_SIZE;
	}
	return err;
}

/**
 * swap_smm_range - swap paged memory to segmented space
 * @vma: user vma to swap to
 * @addr: target user address to start at
 * @size: size of mapping area
 * @prot: page protection flags for this mapping
 *
 * Note: this is only safe if the mm semaphore is held when called.
 *
 * Return: %0 on success, negative error code otherwise.
 */
int swap_smm_vma_range(struct vm_area_struct *vma, unsigned long addr,
		       unsigned long size)
{
	pgd_t *pgd;
	unsigned long next;
	unsigned long end = addr + PAGE_ALIGN(size);
	struct mm_struct *mm = vma->vm_mm;
	int err = 0;

	BUG_ON(addr >= end);
	pgd = pgd_offset(mm, addr);
	flush_cache_range(vma, addr, end);
	do {
		next = pgd_addr_end(addr, end);
		err = swap_p4d_range(vma, pgd, addr, next);
		if (err)
			break;
	} while (pgd++, addr = next, addr != end);
#if 0
	printk("TSP SWAP [%lx - %lx] vm_flags %lx, vm_page_prot %lx, "
	       "vm_pgoff: %lx , err = %d\n",
	       addr, end, vma->vm_flags, vma->vm_page_prot.pgprot,
	       vma->vm_pgoff, err);
#endif

	return err;
}

int is_vma_smm_swapped(struct vm_area_struct *vma)
{
	if (vma && vma->vm_mm && vma->vm_mm->smm_enabled && vma->vm_mm->smm)
		return current->mm->smm->is_swapped;
	else
		return 0;
}

int is_current_smm_swapped(void)
{
	if (current && current->mm && current->mm->smm_enabled &&
	    current->mm->smm) {
		return current->mm->smm->is_swapped;
	} else
		return 0;
}

void smm_exit_dump(void)
{
	if (current && current->mm && current->mm->smm_show_size) {
		printk("[%s %d]: TSP heap:%ld KB, mmap:%ld KB,2M huge: %ld, 1G huge: %ld, coalesced 2M huge: %ld, coalesced 1G huge: %ld\n",
				current->comm, current->pid, 
				current->mm->heap_segment_used / 1024,
				current->mm->mmap_segment_used / 1024,
				current->mm->smm_hugep_pmd_count,
				current->mm->smm_hugep_pud_count,
				current->mm->smm_coalesce_pmd_count,
				current->mm->smm_coalesce_pud_count
				);

	}
	if (current && current->mm && current->mm->smm_check) {
		smm_check_current();
	}
}

int smm_check_current(void)
{
	struct vm_area_struct *vma;
	unsigned long start = 0;
	unsigned long end = 0;
	int err = 0;

	if (!is_current_smm_swapped())
		return 0;

	vma = current->mm->mmap;
	down_read(&current->mm->mmap_sem);

	while (vma) {
		start = vma->vm_start;
		end = vma->vm_end;
		err = check_smm_range(vma, start, end - start,
				      vma->vm_page_prot);
		if (err)
			break;
		vma = vma->vm_next;
	}
	up_read(&current->mm->mmap_sem);
	if (err)
		printk("[%s %d] TSP CHECK Failed.\n", current->comm,
		       current->pid);
	return err;
}

int smm_swap_current(void)
{
	struct vm_area_struct *vma;
	unsigned long start = 0;
	unsigned long end = 0;
	int err = 0;
#if 0
	printk("smm_swap_current %s %d\n", current->comm, current->pid);
	printk("code: %#lx - %#lx (%#lx)\n",
	       current->mm->smm->code_segment_paddr,
	       current->mm->smm->code_segment_paddr +
		       current->mm->smm->code_segment_size,
	       current->mm->smm->code_segment_size);
	printk("heap: %#lx - %#lx (%#lx)\n",
	       current->mm->smm->heap_segment_paddr,
	       current->mm->smm->heap_segment_paddr +
		       current->mm->smm->heap_segment_size,
	       current->mm->smm->heap_segment_size);
	printk("mmap: %#lx - %#lx (%#lx)\n",
	       current->mm->smm->mmap_segment_paddr,
	       current->mm->smm->mmap_segment_paddr +
		       current->mm->smm->mmap_segment_size,
	       current->mm->smm->mmap_segment_size);
	printk("stack: %#lx - %#lx (%#lx)\n",
	       current->mm->smm->stack_segment_paddr,
	       current->mm->smm->stack_segment_paddr +
		       current->mm->smm->stack_segment_size,
	       current->mm->smm->stack_segment_size);
#endif

	vma = current->mm->mmap;
	down_write(&current->mm->mmap_sem);

	while (vma) {
		start = vma->vm_start;
		end = vma->vm_end;
		err = swap_smm_vma_range(vma, start, end - start);
		if (err)
			break;
		vma = vma->vm_next;
	}
	flush_tlb_all();
	current->mm->smm->is_swapped = 1;
	up_write(&current->mm->mmap_sem);
	return err;
}

void free_smm_page(struct page *page)
{
	set_page_private(page, 0);
	page->mapping = NULL;
	ClearPagePrivate(page);
	page_mapcount_reset(page);
	page->flags = page->flags & (~((1UL << NR_PAGEFLAGS) - 1));
	SetPageSmm(page);
}

void put_smm_page(struct page *page)
{
#if 0
	printk("put_smm_page %#lx, count %ld mapcount %ld\n ",
	       (unsigned long)(page_to_pfn(page) << PAGE_SHIFT),
	       page_count(page), page_mapcount(page));
#endif
	if (put_page_testzero(page))
		free_smm_page(page);
}
EXPORT_SYMBOL(put_smm_page);

static int prep_new_smm_page(struct page *page)
{
	page->flags = page->flags & (~((1UL << NR_PAGEFLAGS) - 1));
	SetPageSmm(page);
	set_page_private(page, 0);
	set_page_refcounted(page);
	page_mapcount_reset(page);
	page->smm_buddy_page = NULL;
	page->mapping = NULL;
	clear_compound_head(page);
	ClearPageHead(page);
	return 0;
}

struct page *alloc_zeroed_smm_page(struct vm_area_struct *vma,
				   unsigned long address)
{
	struct page *page;
	unsigned long paddr;

	if (current->mm->smm == NULL)
		return NULL;
	if (!is_vma_smm_swapped(vma))
		return NULL;

	paddr = smm_vaddr_to_paddr(current->mm->smm, address);
	if (paddr == 0) {
#if 1
		printk("[%s %d] : alloc_zeroed_smm_page [%#lx - %#lx], "
		       "address:%#lx, return NULL\n",
		       current->comm, current->pid, vma->vm_start, vma->vm_end,
		       address);
#endif
		return NULL;
	}

	page = pfn_to_page(paddr >> PAGE_SHIFT);
	prep_new_smm_page(page);
	clear_page(__va(paddr));
	if (vma->vm_mm->smm_show_size) {
		if (smm_vaddr_is_heap(address)) {
			vma->vm_mm->heap_segment_used += PAGE_SIZE;
		}
		if (smm_vaddr_is_mmap(address)) {
			vma->vm_mm->mmap_segment_used += PAGE_SIZE;
		}
	}

#if 0
	if (address >= 0x200000010000 && address <= 0x200000020000) {
		struct page *npage;

	printk("[%s %d] : alloc_zeroed_smm_page [%#lx - %#lx], address:%#lx, "
	       "paddr = %#lx\n",
	       current->comm, current->pid, vma->vm_start, vma->vm_end, address,
	       paddr);

		npage = alloc_zeroed_user_highpage_movable(vma, address);
		printk("page_count: %d %d\n",page_count(npage), page_count(page));
	}
#endif
	return page;
}

bool smm_pmd_huge_vma_suitable(struct vm_area_struct *vma, unsigned long haddr)
{
	if (haddr < vma->vm_start || haddr + TSP_HPAGE_PMD_SIZE > vma->vm_end)
		return false;
	return true;
}
bool smm_pud_huge_vma_suitable(struct vm_area_struct *vma, unsigned long haddr)
{
	if (haddr < vma->vm_start || haddr + TSP_HPAGE_PUD_SIZE > vma->vm_end)
		return false;
	return true;
}
pmd_t smm_maybe_pmd_mkwrite(pmd_t pmd, struct vm_area_struct *vma)
{
	if (likely(vma->vm_flags & VM_WRITE))
		pmd = pmd_mkwrite(pmd);
	return pmd;
}
pud_t smm_maybe_pud_mkwrite(pud_t pud, struct vm_area_struct *vma)
{
	if (likely(vma->vm_flags & VM_WRITE))
		pud = pud_mkwrite(pud);
	return pud;
}

vm_fault_t do_smm_huge_pud_anonymous_page(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	gfp_t gfp;
	struct page *page;
	unsigned long haddr = vmf->address & TSP_HPAGE_PUD_MASK;
	unsigned long paddr;
	vm_fault_t ret = 0;
	int i;

	if (!smm_pud_huge_vma_suitable(vma, haddr)) {
		return VM_FAULT_FALLBACK;
	}

	if (unlikely(anon_vma_prepare(vma))) {
		return VM_FAULT_OOM;
	}


	gfp = GFP_TRANSHUGE_LIGHT;

	paddr = smm_vaddr_to_paddr(vma->vm_mm->smm, haddr);
	if (paddr == 0)
		return VM_FAULT_OOM;

	page = pfn_to_page(paddr >> PAGE_SHIFT);

	vmf->ptl = pud_lock(vma->vm_mm, vmf->pud);
	if (unlikely(!pud_none(*vmf->pud))) {
		goto unlock_release;
	} else {
		pud_t entry;
		ret = check_stable_address_space(vma->vm_mm);
		if (ret)
			goto unlock_release;
		for (i = 0; i < TSP_HPAGE_PUD_NR; i++) {
			prep_new_smm_page(page + i);
			clear_page(__va(paddr + i * PAGE_SIZE));
			__SetPageUptodate(page + i);
		}

		entry = mk_huge_pud(page, vma->vm_page_prot);
		entry = smm_maybe_pud_mkwrite(pud_mkdirty(entry), vma);

		page_add_new_anon_rmap(page, vma, haddr, false);
		set_pud_at(vma->vm_mm, haddr, vmf->pud, entry);
		add_mm_counter(vma->vm_mm, MM_ANONPAGES, TSP_HPAGE_PUD_NR);
		//mm_inc_nr_ptes(vma->vm_mm);
		spin_unlock(vmf->ptl);

		if (vma->vm_mm->smm_show_size) {
			if (smm_vaddr_is_heap(vmf->address)) {
				vma->vm_mm->heap_segment_used += (PUD_PAGE_SIZE);
			}
			if (smm_vaddr_is_mmap(vmf->address)) {
				vma->vm_mm->mmap_segment_used += (PUD_PAGE_SIZE);
			}
		}

		vma->vm_mm->smm_hugep_pud_count++;

	}
	return 0;
unlock_release:
	spin_unlock(vmf->ptl);
	return ret;

	return ret;
}

vm_fault_t do_smm_huge_pmd_anonymous_page(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	gfp_t gfp;
	struct page *page;
	unsigned long haddr = vmf->address & TSP_HPAGE_PMD_MASK;
	unsigned long paddr;
	vm_fault_t ret = 0;

	if (!smm_pmd_huge_vma_suitable(vma, haddr)) {
		return VM_FAULT_FALLBACK;
	}

	if (unlikely(anon_vma_prepare(vma))) {
		return VM_FAULT_OOM;
	}

	gfp = GFP_TRANSHUGE_LIGHT;

	paddr = smm_vaddr_to_paddr(vma->vm_mm->smm, haddr);
	if (paddr == 0)
		return VM_FAULT_OOM;

	page = pfn_to_page(paddr >> PAGE_SHIFT);

	vmf->ptl = pmd_lock(vma->vm_mm, vmf->pmd);
	if (unlikely(!pmd_none(*vmf->pmd))) {
		goto unlock_release;
	} else {
		pmd_t entry;
		int i;

		ret = check_stable_address_space(vma->vm_mm);
		if (ret)
			goto unlock_release;

		//prep_new_smm_page(page);

		for (i = 0; i < TSP_HPAGE_PMD_NR; i++) {
			prep_new_smm_page(page + i);
			clear_page(__va(paddr + i * PAGE_SIZE));
			__SetPageUptodate(page + i);
		}

		entry = mk_huge_pmd(page, vma->vm_page_prot);
		entry = smm_maybe_pmd_mkwrite(pmd_mkdirty(entry), vma);
		page_add_new_anon_rmap(page, vma, haddr, false);
		set_pmd_at(vma->vm_mm, haddr, vmf->pmd, entry);
		add_mm_counter(vma->vm_mm, MM_ANONPAGES, TSP_HPAGE_PMD_NR);
		//mm_inc_nr_ptes(vma->vm_mm);
		spin_unlock(vmf->ptl);
#if 0
		printk("huge [%#lx-%#lx] addr = %#lx "
				"paddr: %#lx entry: %#lx\n",
				vma->vm_start, vma->vm_end, vmf->address, paddr, pmd_val(entry));
#endif
		if (vma->vm_mm->smm_show_size) {
			if (smm_vaddr_is_heap(vmf->address)) {
				vma->vm_mm->heap_segment_used += (PMD_PAGE_SIZE);
			}
			if (smm_vaddr_is_mmap(vmf->address)) {
				vma->vm_mm->mmap_segment_used += (PMD_PAGE_SIZE);
			}
		}

		vma->vm_mm->smm_hugep_pmd_count++;
	}
	return 0;
unlock_release:
#if 0
		printk("unlock_release do_smm_huge_pmd_anonymous_page\n");
#endif

	spin_unlock(vmf->ptl);
	return ret;
}

/*
 * Returns page table lock pointer if a given pmd maps a smm, NULL otherwise.
 *
 * Note that if it returns page table lock pointer, this routine returns without
 * unlocking page table lock. So callers must unlock it.
 */
spinlock_t *__pmd_smm_huge_lock(pmd_t *pmd, struct vm_area_struct *vma)
{
	spinlock_t *ptl;
	ptl = pmd_lock(vma->vm_mm, pmd);
	if (likely(pmd_smm_huge(*pmd)))
		return ptl;
	spin_unlock(ptl);
	return NULL;
}

spinlock_t *__pud_smm_huge_lock(pud_t *pud, struct vm_area_struct *vma)
{
	spinlock_t *ptl;
	ptl = pud_lock(vma->vm_mm, pud);
	if (likely(pud_smm_huge(*pud)))
		return ptl;
	spin_unlock(ptl);
	return NULL;
}

#define smm_tlb_remove_pmd_tlb_entry(tlb, pmdp, address)                       \
	do {                                                                   \
		__tlb_adjust_range(tlb, address, TSP_HPAGE_PMD_SIZE);          \
		tlb->cleared_pmds = 1;                                         \
		__tlb_remove_pmd_tlb_entry(tlb, pmdp, address);                \
	} while (0)

#define smm_tlb_remove_pud_tlb_entry(tlb, pudp, address)                       \
	do {                                                                   \
		__tlb_adjust_range(tlb, address, TSP_HPAGE_PUD_SIZE);          \
		tlb->cleared_puds = 1;                                         \
		__tlb_remove_pud_tlb_entry(tlb, pudp, address);                \
	} while (0)

int zap_smm_huge_pud(struct mmu_gather *tlb, struct vm_area_struct *vma,
		     pud_t *pud, unsigned long addr)
{
	pud_t orig_pud;
	spinlock_t *ptl;
	struct page *page = NULL;

	tlb_change_page_size(tlb, TSP_HPAGE_PUD_SIZE);

	ptl = __pud_smm_huge_lock(pud, vma);
	if (!ptl)
		return 0;
	orig_pud =
		pudp_huge_get_and_clear_full(tlb->mm, addr, pud, tlb->fullmm);
	smm_tlb_remove_pud_tlb_entry(tlb, pud, addr);

	if (pud_present(orig_pud)) {
		page = pud_page(orig_pud);
		page_remove_rmap(page, true);
		VM_BUG_ON_PAGE(page_mapcount(page) < 0, page);
	}
	add_mm_counter(vma->vm_mm, MM_ANONPAGES, -TSP_HPAGE_PUD_NR);
	spin_unlock(ptl);
	//mm_dec_nr_ptes(vma->vm_mm);
	tlb_remove_page_size(tlb, page, TSP_HPAGE_PUD_SIZE);
	return 1;
}

int zap_smm_huge_pmd(struct mmu_gather *tlb, struct vm_area_struct *vma,
		     pmd_t *pmd, unsigned long addr)
{
	pmd_t orig_pmd;
	spinlock_t *ptl;
	struct page *page = NULL;

	tlb_change_page_size(tlb, TSP_HPAGE_PMD_SIZE);

	ptl = __pmd_smm_huge_lock(pmd, vma);
	if (!ptl)
		return 0;
	orig_pmd =
		pmdp_huge_get_and_clear_full(tlb->mm, addr, pmd, tlb->fullmm);
	smm_tlb_remove_pmd_tlb_entry(tlb, pmd, addr);

	if (pmd_present(orig_pmd)) {
		page = pmd_page(orig_pmd);
		page_remove_rmap(page, true);
		VM_BUG_ON_PAGE(page_mapcount(page) < 0, page);
	}
	add_mm_counter(vma->vm_mm, MM_ANONPAGES, -TSP_HPAGE_PMD_NR);
	spin_unlock(ptl);
	//mm_dec_nr_ptes(vma->vm_mm);
	tlb_remove_page_size(tlb, page, TSP_HPAGE_PMD_SIZE);

	return 1;
}

pmd_t smm_pmdp_invalidate(struct vm_area_struct *vma, unsigned long address,
			  pmd_t *pmdp)
{
	pmd_t old = pmdp_establish(vma, address, pmdp, pmd_mknotpresent(*pmdp));
	flush_tlb_range(vma, address, address + TSP_HPAGE_PMD_SIZE);
	return old;
}

pud_t smm_pudp_invalidate(struct vm_area_struct *vma, unsigned long address,
			  pud_t *pudp)
{
	pud_t old = pudp_establish(vma, address, pudp, pud_mknotpresent(*pudp));
	flush_tlb_range(vma, address, address + TSP_HPAGE_PUD_SIZE);
	return old;
}

bool move_smm_huge_pmd(struct vm_area_struct *vma, unsigned long old_addr,
		       unsigned long new_addr, unsigned long old_end,
		       pmd_t *old_pmd, pmd_t *new_pmd)
{
	spinlock_t *old_ptl, *new_ptl;
	pmd_t pmd;
	struct mm_struct *mm = vma->vm_mm;
	bool force_flush = false;

	printk("move_smm_huge_pmd %#lx %#lx\n", old_addr, new_addr);

	if ((old_addr & ~TSP_HPAGE_PMD_MASK) ||
	    (new_addr & ~TSP_HPAGE_PMD_MASK) ||
	    old_end - old_addr < TSP_HPAGE_PMD_SIZE)
		return false;

	/*
	 * The destination pmd shouldn't be established, free_pgtables()
	 * should have release it.
	 */
	if (WARN_ON(!pmd_none(*new_pmd))) {
		VM_BUG_ON(pmd_smm_huge(*new_pmd));
		return false;
	}

	/*
	 * We don't have to worry about the ordering of src and dst
	 * ptlocks because exclusive mmap_sem prevents deadlock.
	 */
	old_ptl = __pmd_smm_huge_lock(old_pmd, vma);
	if (old_ptl) {
		unsigned long pfn;
		unsigned long smm_pfn;
		struct page *old_page, *smm_page;
		int c = TSP_HPAGE_PMD_NR;
		pgprot_t old_prot;

		new_ptl = pmd_lockptr(mm, new_pmd);
		if (new_ptl != old_ptl)
			spin_lock_nested(new_ptl, SINGLE_DEPTH_NESTING);
		pmd = pmdp_huge_get_and_clear(mm, old_addr, old_pmd);
		if (pmd_present(pmd))
			force_flush = true;
		VM_BUG_ON(!pmd_none(*new_pmd));

		old_prot = pmd_pgprot(pmd);
		pfn = pmd_pfn(pmd);
		pmd = pfn_pmd(smm_pfn, old_prot);

		smm_pfn = smm_vaddr_to_paddr(mm->smm, new_addr) >> PAGE_SHIFT;
		while (c--) {
			copy_page(__va(smm_pfn << PAGE_SHIFT),
				  __va(pfn << PAGE_SHIFT));
			old_page = pfn_to_page(pfn);
			smm_page = pfn_to_page(smm_pfn);
			dup_smm_page(old_page, smm_page);
			pfn++;
			smm_pfn++;
		}

		set_pmd_at(mm, new_addr, new_pmd, pmd);
		if (force_flush)
			flush_tlb_range(vma, old_addr, old_addr + PMD_SIZE);
		if (new_ptl != old_ptl)
			spin_unlock(new_ptl);
		spin_unlock(old_ptl);
		return true;
	}
	return false;
}

void split_smm_huge_pud(struct vm_area_struct *vma, pud_t *pud,
			unsigned long address)
{
	struct mm_struct *mm = vma->vm_mm;
	struct page *page;
	spinlock_t *ptl;
	pud_t old_pud, _pud;
	unsigned long haddr, addr;
	struct mmu_notifier_range range;
	pmd_t *pgtable;
	bool young, write, soft_dirty;
	int i;

	mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, vma, vma->vm_mm,
				address & TSP_HPAGE_PUD_MASK,
				(address & TSP_HPAGE_PUD_MASK) +
					TSP_HPAGE_PUD_SIZE);
	mmu_notifier_invalidate_range_start(&range);
	ptl = pud_lock(vma->vm_mm, pud);
	haddr = range.start;

	old_pud = smm_pudp_invalidate(vma, haddr, pud);

	page = pud_page(old_pud);
	if (pud_dirty(old_pud))
		SetPageDirty(page);
	write = pud_write(old_pud);
	young = pud_young(old_pud);
	soft_dirty = pud_soft_dirty(old_pud);

	pgtable = pmd_alloc_one(vma->vm_mm, address);
	pud_populate(mm, &_pud, pgtable);

	for (i = 0, addr = haddr; i < TSP_HPAGE_PMD_NR;
	     i++, addr += TSP_HPAGE_PMD_SIZE) {
		pmd_t entry, *pmd;
		prep_new_smm_page(page + i * TSP_HPAGE_PMD_NR);
		page_add_new_anon_rmap(page + i * TSP_HPAGE_PMD_NR, vma, addr,
				       false);
		entry = mk_huge_pmd(page + i * TSP_HPAGE_PMD_NR,
			       READ_ONCE(vma->vm_page_prot));
		entry = smm_maybe_pmd_mkwrite(entry, vma);

		if (!write)
			entry = pmd_wrprotect(entry);
		if (!young)
			entry = pmd_mkold(entry);
		if (soft_dirty)
			entry = pmd_mksoft_dirty(entry);
		pmd = pmd_offset(&_pud, addr);
		BUG_ON(!pmd_none(*pmd));
		set_pmd_at(mm, addr, pmd, entry);
	}

	smp_wmb(); /* make pte visible before pmd */
	pud_populate(mm, pud, pgtable);

	spin_unlock(ptl);
	mmu_notifier_invalidate_range_only_end(&range);
	mm_inc_nr_ptes(mm);
}

void split_smm_huge_pmd(struct vm_area_struct *vma, pmd_t *pmd,
			unsigned long address)
{
	struct mm_struct *mm = vma->vm_mm;
	struct page *page;
	spinlock_t *ptl;
	pmd_t old_pmd, _pmd;
	unsigned long haddr, addr;
	struct mmu_notifier_range range;
	pgtable_t pgtable;
	bool young, write, soft_dirty, uffd_wp = false;
	int i;

	mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, vma, vma->vm_mm,
				address & TSP_HPAGE_PMD_MASK,
				(address & TSP_HPAGE_PMD_MASK) +
					TSP_HPAGE_PMD_SIZE);
	mmu_notifier_invalidate_range_start(&range);
	ptl = pmd_lock(vma->vm_mm, pmd);
	haddr = range.start;

	old_pmd = smm_pmdp_invalidate(vma, haddr, pmd);

	page = pmd_page(old_pmd);
	if (pmd_dirty(old_pmd))
		SetPageDirty(page);
	write = pmd_write(old_pmd);
	young = pmd_young(old_pmd);
	soft_dirty = pmd_soft_dirty(old_pmd);
	uffd_wp = pmd_uffd_wp(old_pmd);

	pgtable = pte_alloc_one(vma->vm_mm);
	pmd_populate(mm, &_pmd, pgtable);

	//printk("split_huge_pmd %#lx mapcount:%d\n", haddr, page_mapcount(page));
	for (i = 0, addr = haddr; i < TSP_HPAGE_PMD_NR;
	     i++, addr += PAGE_SIZE) {
		pte_t entry, *pte;
		prep_new_smm_page(page + i);
		page_add_new_anon_rmap(page + i, vma, addr, false);
		entry = mk_pte(page + i, READ_ONCE(vma->vm_page_prot));
		entry = maybe_mkwrite(entry, vma);
		if (!write)
			entry = pte_wrprotect(entry);
		if (!young)
			entry = pte_mkold(entry);
		if (soft_dirty)
			entry = pte_mksoft_dirty(entry);
		if (uffd_wp)
			entry = pte_mkuffd_wp(entry);
		pte = pte_offset_map(&_pmd, addr);
		BUG_ON(!pte_none(*pte));
		set_pte_at(mm, addr, pte, entry);
		//atomic_inc(&page[i]._mapcount);
		pte_unmap(pte);
	}

	smp_wmb(); /* make pte visible before pmd */
	pmd_populate(mm, pmd, pgtable);

	spin_unlock(ptl);
	mmu_notifier_invalidate_range_only_end(&range);
	mm_inc_nr_ptes(mm);
}

int smm_pudp_set_access_flags(struct vm_area_struct *vma, unsigned long address,
			      pud_t *pudp, pud_t entry, int dirty)
{
	int changed = !pud_same(*pudp, entry);

	VM_BUG_ON(address & ~TSP_HPAGE_PUD_MASK);

	if (changed && dirty) {
		set_pud(pudp, entry);
		/*
		 * We had a write-protection fault here and changed the pud
		 * to to more permissive. No need to flush the TLB for that,
		 * #PF is architecturally guaranteed to do that and in the
		 * worst-case we'll generate a spurious fault.
		 */
	}

	return changed;
}


int smm_pmdp_set_access_flags(struct vm_area_struct *vma, unsigned long address,
			      pmd_t *pmdp, pmd_t entry, int dirty)
{
	int changed = !pmd_same(*pmdp, entry);

	VM_BUG_ON(address & ~TSP_HPAGE_PMD_MASK);

	if (changed && dirty) {
		set_pmd(pmdp, entry);
		/*
		 * We had a write-protection fault here and changed the pmd
		 * to to more permissive. No need to flush the TLB for that,
		 * #PF is architecturally guaranteed to do that and in the
		 * worst-case we'll generate a spurious fault.
		 */
	}

	return changed;
}

void smm_huge_pud_set_accessed(struct vm_fault *vmf, pud_t orig_pud)
{
	pud_t entry;
	unsigned long haddr;
	bool write = vmf->flags & FAULT_FLAG_WRITE;

	vmf->ptl = pud_lock(vmf->vma->vm_mm, vmf->pud);
	if (unlikely(!pud_same(*vmf->pud, orig_pud)))
		goto unlock;

	entry = pud_mkyoung(orig_pud);
	if (write)
		entry = pud_mkdirty(entry);
	haddr = vmf->address & TSP_HPAGE_PUD_MASK;
	if (smm_pudp_set_access_flags(vmf->vma, haddr, vmf->pud, entry, write))
		update_mmu_cache_pud(vmf->vma, vmf->address, vmf->pud);

unlock:
	spin_unlock(vmf->ptl);
}


void smm_huge_pmd_set_accessed(struct vm_fault *vmf, pmd_t orig_pmd)
{
	pmd_t entry;
	unsigned long haddr;
	bool write = vmf->flags & FAULT_FLAG_WRITE;

	vmf->ptl = pmd_lock(vmf->vma->vm_mm, vmf->pmd);
	if (unlikely(!pmd_same(*vmf->pmd, orig_pmd)))
		goto unlock;

	entry = pmd_mkyoung(orig_pmd);
	if (write)
		entry = pmd_mkdirty(entry);
	haddr = vmf->address & TSP_HPAGE_PMD_MASK;
	if (smm_pmdp_set_access_flags(vmf->vma, haddr, vmf->pmd, entry, write))
		update_mmu_cache_pmd(vmf->vma, vmf->address, vmf->pmd);

unlock:
	spin_unlock(vmf->ptl);
}

/*
 * FOLL_FORCE can write to even unwritable pmd's, but only
 * after we've gone through a COW cycle and they are dirty.
 */
static inline bool can_follow_write_pmd(pmd_t pmd, unsigned int flags)
{
	return pmd_write(pmd) ||
	       ((flags & FOLL_FORCE) && (flags & FOLL_COW) && pmd_dirty(pmd));
}

static void touch_pmd(struct vm_area_struct *vma, unsigned long addr,
		      pmd_t *pmd, int flags)
{
	pmd_t _pmd;

	_pmd = pmd_mkyoung(*pmd);
	if (flags & FOLL_WRITE)
		_pmd = pmd_mkdirty(_pmd);
	if (smm_pmdp_set_access_flags(vma, addr & TSP_HPAGE_PMD_MASK, pmd, _pmd,
				      flags & FOLL_WRITE))
		update_mmu_cache_pmd(vma, addr, pmd);
}

struct page *follow_smm_huge_pmd(struct vm_area_struct *vma, unsigned long addr,
				 pmd_t *pmd, unsigned int flags)
{
	struct mm_struct *mm = vma->vm_mm;
	struct page *page = NULL;

	assert_spin_locked(pmd_lockptr(mm, pmd));

	if (flags & FOLL_WRITE && !can_follow_write_pmd(*pmd, flags))
		goto out;

	/* Full NUMA hinting faults to serialise migration in fault paths */
	if ((flags & FOLL_NUMA) && pmd_protnone(*pmd))
		goto out;

	page = pmd_page(*pmd);
	VM_BUG_ON_PAGE(!PageHead(page) && !is_zone_device_page(page), page);

	if (!try_grab_page(page, flags))
		return ERR_PTR(-ENOMEM);

	if (flags & FOLL_TOUCH)
		touch_pmd(vma, addr, pmd, flags);

	if ((flags & FOLL_MLOCK) && (vma->vm_flags & VM_LOCKED)) {
		/*
		 * We don't mlock() pte-mapped THPs. This way we can avoid
		 * leaking mlocked pages into non-VM_LOCKED VMAs.
		 *
		 * For anon THP:
		 *
		 * In most cases the pmd is the only mapping of the page as we
		 * break COW for the mlock() -- see gup_flags |= FOLL_WRITE for
		 * writable private mappings in populate_vma_page_range().
		 *
		 * The only scenario when we have the page shared here is if we
		 * mlocking read-only mapping shared over fork(). We skip
		 * mlocking such pages.
		 *
		 * For file THP:
		 *
		 * We can expect PageDoubleMap() to be stable under page lock:
		 * for file pages we set it in page_add_file_rmap(), which
		 * requires page to be locked.
		 */

		if (PageAnon(page) && compound_mapcount(page) != 1)
			goto skip_mlock;
		if (PageDoubleMap(page) || !page->mapping)
			goto skip_mlock;
		if (!trylock_page(page))
			goto skip_mlock;
		lru_add_drain();
		if (page->mapping && !PageDoubleMap(page))
			mlock_vma_page(page);
		unlock_page(page);
	}
skip_mlock:
	page += (addr & ~TSP_HPAGE_PMD_MASK) >> PAGE_SHIFT;
	//VM_BUG_ON_PAGE(!PageCompound(page) && !is_zone_device_page(page), page);

out:
	return page;
}

int smm_alloc_and_create(unsigned long code_size, unsigned long heap_size,
			 unsigned long mmap_size, unsigned long stack_size)
{
	int error, fd;
	struct file *file = NULL;
	struct smm *smm = NULL;

	smm = smm_alloc(code_size, heap_size, mmap_size, stack_size);
	if (IS_ERR(smm)) {
		fd = PTR_ERR(smm);
		printk("TSP alloc failed..\n");
		goto out;
	}

	error = get_unused_fd_flags(O_RDWR);
	if (error < 0) {
		fd = error;
		goto out;
	}
	fd = error;

	file = anon_inode_getfile("smm", &smm_fops, smm, O_RDWR | O_CLOEXEC);
	if (IS_ERR(file)) {
		error = PTR_ERR(file);
		put_unused_fd(fd);
		fd = error;
		goto out;
	}
	get_smm(smm);
	fd_install(fd, file);
	current->mm->smm = smm;
out:
	return fd;
}

int smm_setup_current()
{
	unsigned long s, e;
	if (current->mm->smm_enabled == 0)
		return 0;

	if (current->mm && !current->mm->smm && current->mm->mmap_segment_env &&
	    current->mm->code_segment_env && current->mm->heap_segment_env &&
	    current->mm->stack_segment_env) {
		s = ktime_get_ns();
		smm_alloc_and_create(current->mm->code_segment_env,
				     current->mm->heap_segment_env,
				     current->mm->mmap_segment_env,
				     current->mm->stack_segment_env);
		smm_swap_current();
		e = ktime_get_ns();
		printk("[%s %d] TSP enabled, took %ld ns, [CODE:%ld KB] "
		       "[HEAP:%ld KB] [MMAP:%ld KB] [STACK:%ld KB]\n",
		       current->comm, current->pid, 
		       e - s,
		       current->mm->smm->code_segment_swapped / 1024,
		       current->mm->smm->heap_segment_swapped / 1024,
		       current->mm->smm->mmap_segment_swapped / 1024,
		       current->mm->smm->stack_segment_swapped / 1024
		       );
	}
	return 0;
}
