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

#include <linux/proc_fs.h>
#include <linux/tsp.h>

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

                tspblock_add_node(addr, size, nid);

		reserved += size;
		pr_info("tsp: reserved %lu MiB on node %d\n",
			size / SZ_1M, nid);

		if (reserved >= tsp_reserve_size)
                        break;
        }
        __tspblock_dump_all();
}


/*
 * tspblock_lock protects all slob allocator structures.
 */
static DEFINE_SPINLOCK(tspblock_lock);

static struct tspblock_region tspblock_memory_init_regions[INIT_TSPBLOCK_REGIONS] ;
static struct tspblock_region tspblock_reserved_init_regions[INIT_TSPBLOCK_REGIONS] ;

struct tspblock tspblock  = {
	.memory.regions		= tspblock_memory_init_regions,
	.memory.cnt		= 1,	/* empty dummy entry */
	.memory.max		= INIT_TSPBLOCK_REGIONS,

	.reserved.regions	= tspblock_reserved_init_regions,
	.reserved.cnt		= 1,	/* empty dummy entry */
	.reserved.max		= INIT_TSPBLOCK_REGIONS,

	.current_limit		= TSPBLOCK_ALLOC_ANYWHERE,
};

int tspblock_debug = 0;
static int tspblock_can_resize = 1;
static int tspblock_memory_in_slab = 0;
static int tspblock_reserved_in_slab  = 0;
/* inline so we don't get a warning when pr_debug is compiled out */
static const char *
tspblock_type_name(struct tspblock_type *type)
{
	if (type == &tspblock.memory)
		return "memory";
	else if (type == &tspblock.reserved)
		return "reserved";
	else
		return "unknown";
}

/* adjust *@size so that (@base + *@size) doesn't overflow, return new size */
static inline phys_addr_t tspblock_cap_size(phys_addr_t base, phys_addr_t *size)
{
	return *size = min(*size, (phys_addr_t)ULLONG_MAX - base);
}

/*
 * Address comparison utilities
 */
static unsigned long  tspblock_addrs_overlap(phys_addr_t base1, phys_addr_t size1,
				       phys_addr_t base2, phys_addr_t size2)
{
	return ((base1 < (base2 + size2)) && (base2 < (base1 + size1)));
}

static long  tspblock_overlaps_region(struct tspblock_type *type,
					phys_addr_t base, phys_addr_t size)
{
	unsigned long i;

	for (i = 0; i < type->cnt; i++) {
		phys_addr_t rgnbase = type->regions[i].base;
		phys_addr_t rgnsize = type->regions[i].size;
		if (tspblock_addrs_overlap(base, size, rgnbase, rgnsize))
			break;
	}

	return (i < type->cnt) ? i : -1;
}


/**
 * tspblock_find_in_range_node_reverse - find free area in given range and node reverse
 * @start: start of candidate range
 * @end: end of candidate range, can be %tspblock_ALLOC_{ANYWHERE|ACCESSIBLE}
 * @size: size of free area to find
 * @align: alignment of free area to find
 * @nid: nid of the free area to find, %MCK_MAX_NUMNODES for any node
 *
 * Find @size free area aligned to @align in the specified range and node.
 *
 * RETURNS:
 * Found address on success, %0 on failure.
 */
phys_addr_t  tspblock_find_in_range_node_reverse(phys_addr_t start,
					phys_addr_t end, phys_addr_t size,
					phys_addr_t align, int nid)
{
	phys_addr_t this_start, this_end, cand;
	u64 i;

	/* pump up @end */
	if (end == TSPBLOCK_ALLOC_ACCESSIBLE)
		end = tspblock.current_limit;

	/* avoid allocating the first page */
	start = max_t(phys_addr_t, start, PAGE_SIZE);
	end = max(start, end);

	for_each_freemem_range_reverse(i, nid, &this_start, &this_end, NULL) {
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
 * tspblock_find_in_range_node - find free area in given range and node
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
phys_addr_t  tspblock_find_in_range_node(phys_addr_t start,
					phys_addr_t end, phys_addr_t size,
					phys_addr_t align, int nid)
{
	phys_addr_t this_start, this_end, cand;
	u64 i;

	/* pump up @end */
	if (end == TSPBLOCK_ALLOC_ACCESSIBLE)
		end = tspblock.current_limit;

	/* avoid allocating the first page */
	start = max_t(phys_addr_t, start, PAGE_SIZE);
	end = max(start, end);

	for_each_freemem_range(i, nid, &this_start, &this_end, NULL) {
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
 * tspblock_find_in_range_reverse - find free area in given range reverse
 * @start: start of candidate range
 * @end: end of candidate range, can be %tspblock_ALLOC_{ANYWHERE|ACCESSIBLE}
 * @size: size of free area to find
 * @align: alignment of free area to find
 *
 * Find @size free area aligned to @align in the specified range.
 *
 * RETURNS:
 * Found address on success, %0 on failure.
 */
phys_addr_t  tspblock_find_in_range_reverse(phys_addr_t start,
					phys_addr_t end, phys_addr_t size,
					phys_addr_t align)
{
	return tspblock_find_in_range_node_reverse(start, end, size, align,
					   MCK_MAX_NUMNODES);
}




/**
 * tspblock_find_in_range - find free area in given range
 * @start: start of candidate range
 * @end: end of candidate range, can be %tspblock_ALLOC_{ANYWHERE|ACCESSIBLE}
 * @size: size of free area to find
 * @align: alignment of free area to find
 *
 * Find @size free area aligned to @align in the specified range.
 *
 * RETURNS:
 * Found address on success, %0 on failure.
 */
phys_addr_t  tspblock_find_in_range(phys_addr_t start,
					phys_addr_t end, phys_addr_t size,
					phys_addr_t align)
{
	return tspblock_find_in_range_node(start, end, size, align,
					   MCK_MAX_NUMNODES);
}

static void  tspblock_remove_region(struct tspblock_type *type, unsigned long r)
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
		tspblock_set_region_node(&type->regions[0], MCK_MAX_NUMNODES);
	}
}

phys_addr_t  get_allocated_tspblock_reserved_regions_info(
					phys_addr_t *addr)
{
	if (tspblock.reserved.regions == tspblock_reserved_init_regions)
		return 0;

	*addr = __pa(tspblock.reserved.regions);

	return PAGE_ALIGN(sizeof(struct tspblock_region) *
			  tspblock.reserved.max);
}

/**
 * tspblock_double_array - double the size of the tspblock regions array
 * @type: tspblock type of the regions array being doubled
 * @new_area_start: starting address of memory range to avoid overlap with
 * @new_area_size: size of memory range to avoid overlap with
 *
 * Double the size of the @type regions array. If tspblock is being used to
 * allocate memory for a new reserved regions array and there is a previously
 * allocated memory range [@new_area_start,@new_area_start+@new_area_size]
 * waiting to be reserved, ensure the memory used by the new array does
 * not overlap.
 *
 * RETURNS:
 * 0 on success, -1 on failure.
 */
static int  tspblock_double_array(struct tspblock_type *type,
						phys_addr_t new_area_start,
						phys_addr_t new_area_size)
{
	struct tspblock_region *new_array, *old_array;
	phys_addr_t old_alloc_size, new_alloc_size;
	phys_addr_t old_size, new_size, addr;
	int use_slab = slab_is_available();
	int *in_slab;
	/* We don't allow resizing until we know about the reserved regions
	 * of memory that aren't suitable for allocation
	 */
	if (!tspblock_can_resize)
		return -1;

	/* Calculate new doubled size */
	old_size = type->max * sizeof(struct tspblock_region);
	new_size = old_size << 1;
	/*
	 * We need to allocated new one align to PAGE_SIZE,
	 *   so we can free them completely later.
	 */
	old_alloc_size = PAGE_ALIGN(old_size);
	new_alloc_size = PAGE_ALIGN(new_size);

	/* Retrieve the slab flag */
	if (type == &tspblock.memory)
		in_slab = &tspblock_memory_in_slab;
	else
		in_slab = &tspblock_reserved_in_slab;

	/* Try to find some space for it.
	 *
	 * WARNING: We assume that either slab_is_available() and we use it or
	 * we use tspblock for allocations. That means that this is unsafe to
	 * use when bootmem is currently active (unless bootmem itself is
	 * implemented on top of tspblock which isn't the case yet)
	 *
	 * This should however not be an issue for now, as we currently only
	 * call into tspblock while it's still active, or much later when slab
	 * is active for memory hotplug operations
	 */
        new_array = kmalloc(new_size, GFP_KERNEL);
        addr = new_array ? __pa(new_array) : 0;
	if (!addr) {
		pr_err("tspblock: Failed to double %s array from %ld to %ld entries !\n",
		       tspblock_type_name(type), type->max, type->max * 2);
		return -1;
	}

	tspblock_dbg("tspblock: %s is doubled to %ld at [%#010llx-%#010llx]",
			tspblock_type_name(type), type->max * 2, (u64)addr,
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
 * tspblock_merge_regions - merge neighboring compatible regions
 * @type: tspblock type to scan
 *
 * Scan @type and merge neighboring compatible regions.
 */
static void  tspblock_merge_regions(struct tspblock_type *type)
{
	int i = 0;

	/* cnt never goes below 1 */
	while (i < type->cnt - 1) {
		struct tspblock_region *this = &type->regions[i];
		struct tspblock_region *next = &type->regions[i + 1];

		if (this->base + this->size != next->base ||
		    tspblock_get_region_node(this) !=
		    tspblock_get_region_node(next)) {
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
 * tspblock_insert_region - insert new tspblock region
 * @type: tspblock type to insert into
 * @idx: index for the insertion point
 * @base: base address of the new region
 * @size: size of the new region
 *
 * Insert new tspblock region [@base,@base+@size) into @type at @idx.
 * @type must already have extra room to accomodate the new region.
 */
static void  tspblock_insert_region(struct tspblock_type *type,
						   int idx, phys_addr_t base,
						   phys_addr_t size, int nid)
{
	struct tspblock_region *rgn = &type->regions[idx];

	BUG_ON(type->cnt >= type->max);
	memmove(rgn + 1, rgn, (type->cnt - idx) * sizeof(*rgn));
	rgn->base = base;
	rgn->size = size;
	tspblock_set_region_node(rgn, nid);
	type->cnt++;
	type->total_size += size;
}

/**
 * tspblock_add_region - add new tspblock region
 * @type: tspblock type to add new region into
 * @base: base address of the new region
 * @size: size of the new region
 * @nid: nid of the new region
 *
 * Add new tspblock region [@base,@base+@size) into @type.  The new region
 * is allowed to overlap with existing ones - overlaps don't affect already
 * existing regions.  @type is guaranteed to be minimal (all neighbouring
 * compatible regions are merged) after the addition.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
static int  tspblock_add_region(struct tspblock_type *type,
				phys_addr_t base, phys_addr_t size, int nid)
{
	bool insert = false;
	phys_addr_t obase = base;
	phys_addr_t end = base + tspblock_cap_size(base, &size);
	int i, nr_new;

	if (!size)
		return 0;

	/* special case for empty array */
	if (type->regions[0].size == 0) {
		WARN_ON(type->cnt != 1 || type->total_size);
		type->regions[0].base = base;
		type->regions[0].size = size;
		tspblock_set_region_node(&type->regions[0], nid);
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
		struct tspblock_region *rgn = &type->regions[i];
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
				tspblock_insert_region(type, i++, base,
						       rbase - base, nid);
		}
		/* area below @rend is dealt with, forget about it */
		base = min(rend, end);
	}

	/* insert the remaining portion */
	if (base < end) {
		nr_new++;
		if (insert)
			tspblock_insert_region(type, i, base, end - base, nid);
	}

	/*
	 * If this was the first round, resize array and repeat for actual
	 * insertions; otherwise, merge and return.
	 */
	if (!insert) {
		while (type->cnt + nr_new > type->max)
			if (tspblock_double_array(type, obase, size) < 0)
				return -ENOMEM;
		insert = true;
		goto repeat;
	} else {
		tspblock_merge_regions(type);
		return 0;
	}
}

int  tspblock_add_node(phys_addr_t base, phys_addr_t size,
				       int nid)
{
	return tspblock_add_region(&tspblock.memory, base, size, nid);
}

int  tspblock_add(phys_addr_t base, phys_addr_t size)
{
	return tspblock_add_region(&tspblock.memory, base, size, MCK_MAX_NUMNODES);
}

/**
 * tspblock_isolate_range - isolate given range into disjoint tspblocks
 * @type: tspblock type to isolate range for
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
static int  tspblock_isolate_range(struct tspblock_type *type,
					phys_addr_t base, phys_addr_t size,
					int *start_rgn, int *end_rgn)
{
	phys_addr_t end = base + tspblock_cap_size(base, &size);
	int i;

	*start_rgn = *end_rgn = 0;

	if (!size)
		return 0;

	/* we'll create at most two more regions */
	while (type->cnt + 2 > type->max)
		if (tspblock_double_array(type, base, size) < 0)
			return -ENOMEM;

	for (i = 0; i < type->cnt; i++) {
		struct tspblock_region *rgn = &type->regions[i];
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
			tspblock_insert_region(type, i, rbase, base - rbase,
					       tspblock_get_region_node(rgn));
		} else if (rend > end) {
			/*
			 * @rgn intersects from above.  Split and redo the
			 * current region - the new bottom half.
			 */
			rgn->base = end;
			rgn->size -= end - rbase;
			type->total_size -= end - rbase;
			tspblock_insert_region(type, i--, rbase, end - rbase,
					       tspblock_get_region_node(rgn));
		} else {
			/* @rgn is fully contained, record it */
			if (!*end_rgn)
				*start_rgn = i;
			*end_rgn = i + 1;
		}
	}

	return 0;
}

static int  __tspblock_remove(struct tspblock_type *type,
					     phys_addr_t base, phys_addr_t size)
{
	int start_rgn, end_rgn;
	int i, ret;
        unsigned long flags;

	spin_lock_irqsave(&tspblock_lock, flags);
	ret = tspblock_isolate_range(type, base, size, &start_rgn, &end_rgn);
	if (ret) {
                spin_unlock_irqrestore(&tspblock_lock, flags);
		return ret;
        }

	for (i = end_rgn - 1; i >= start_rgn; i--)
		tspblock_remove_region(type, i);
        spin_unlock_irqrestore(&tspblock_lock, flags);
	return 0;
}

int  tspblock_remove(phys_addr_t base, phys_addr_t size)
{
	return __tspblock_remove(&tspblock.memory, base, size);
}

int  tspblock_free(phys_addr_t base, phys_addr_t size)
{
	tspblock_dbg("   tspblock_free: [%#016llx-%#016llx] %pF\n",
		     (unsigned long long)base,
		     (unsigned long long)base + size,
		     (void *)_RET_IP_);

	return __tspblock_remove(&tspblock.reserved, base, size);
}

int  tspblock_reserve(phys_addr_t base, phys_addr_t size)
{
	struct tspblock_type *_rgn = &tspblock.reserved;

	tspblock_dbg("tspblock_reserve: [%#016llx-%#016llx] %pF\n",
		     (unsigned long long)base,
		     (unsigned long long)base + size,
		     (void *)_RET_IP_);

	return tspblock_add_region(_rgn, base, size, MCK_MAX_NUMNODES);
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
void  __next_free_mckmem_range(u64 *idx, int nid,
					   phys_addr_t *out_start,
					   phys_addr_t *out_end, int *out_nid)
{
	struct tspblock_type *mem = &tspblock.memory;
	struct tspblock_type *rsv = &tspblock.reserved;
	int mi = *idx & 0xffffffff;
	int ri = *idx >> 32;

	for ( ; mi < mem->cnt; mi++) {
		struct tspblock_region *m = &mem->regions[mi];
		phys_addr_t m_start = m->base;
		phys_addr_t m_end = m->base + m->size;

		/* only memory regions are associated with nodes, check it */
		if (nid != MCK_MAX_NUMNODES && nid != tspblock_get_region_node(m))
			continue;

		/* scan areas before each reservation for intersection */
		for ( ; ri < rsv->cnt + 1; ri++) {
			struct tspblock_region *r = &rsv->regions[ri];
			phys_addr_t r_start = ri ? r[-1].base + r[-1].size : 0;
			phys_addr_t r_end = ri < rsv->cnt ? r->base : ULLONG_MAX;

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
					*out_nid = tspblock_get_region_node(m);
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
void  __next_free_mckmem_range_rev(u64 *idx, int nid,
					   phys_addr_t *out_start,
					   phys_addr_t *out_end, int *out_nid)
{
	struct tspblock_type *mem = &tspblock.memory;
	struct tspblock_type *rsv = &tspblock.reserved;
	int mi = *idx & 0xffffffff;
	int ri = *idx >> 32;

	if (*idx == (u64)ULLONG_MAX) {
		mi = mem->cnt - 1;
		ri = rsv->cnt;
	}

	for ( ; mi >= 0; mi--) {
		struct tspblock_region *m = &mem->regions[mi];
		phys_addr_t m_start = m->base;
		phys_addr_t m_end = m->base + m->size;

		/* only memory regions are associated with nodes, check it */
		if (nid != MCK_MAX_NUMNODES && nid != tspblock_get_region_node(m))
			continue;

		/* scan areas before each reservation for intersection */
		for ( ; ri >= 0; ri--) {
			struct tspblock_region *r = &rsv->regions[ri];
			phys_addr_t r_start = ri ? r[-1].base + r[-1].size : 0;
			phys_addr_t r_end = ri < rsv->cnt ? r->base : ULLONG_MAX;

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
					*out_nid = tspblock_get_region_node(m);

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
void  __next_mckmem_pfn_range(int *idx, int nid,
				unsigned long *out_start_pfn,
				unsigned long *out_end_pfn, int *out_nid)
{
	struct tspblock_type *type = &tspblock.memory;
	struct tspblock_region *r;

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
 * tspblock_set_node - set node ID on tspblock regions
 * @base: base of area to set node ID for
 * @size: size of area to set node ID for
 * @nid: node ID to set
 *
 * Set the nid of tspblock memory regions in [@base,@base+@size) to @nid.
 * Regions which cross the area boundaries are split as necessary.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
int  tspblock_set_node(phys_addr_t base, phys_addr_t size,
				      int nid)
{
	struct tspblock_type *type = &tspblock.memory;
	int start_rgn, end_rgn;
	int i, ret;

	ret = tspblock_isolate_range(type, base, size, &start_rgn, &end_rgn);
	if (ret)
		return ret;

	for (i = start_rgn; i < end_rgn; i++)
		tspblock_set_region_node(&type->regions[i], nid);

	tspblock_merge_regions(type);
	return 0;
}

static phys_addr_t  tspblock_alloc_base_nid(phys_addr_t size,
					phys_addr_t align, phys_addr_t max_addr,
					int nid)
{
    phys_addr_t found;
    unsigned long flags;

    BUG_ON(align == 0);
    /* align @size to avoid excessive fragmentation on reserved array */
    size = round_up(size, align);

    spin_lock_irqsave(&tspblock_lock, flags);
    found = tspblock_find_in_range_node(0, max_addr, size, align, nid);
    if (found && !tspblock_reserve(found, size)) {
        spin_unlock_irqrestore(&tspblock_lock, flags);
        return found;
    }

    spin_unlock_irqrestore(&tspblock_lock, flags);
    return 0;
}


static phys_addr_t  tspblock_alloc_base_nid_bottom_up(phys_addr_t size,
					phys_addr_t align, phys_addr_t max_addr,
					int nid)
{
	phys_addr_t found;
        unsigned long flags;

        BUG_ON(align == 0);
	/* align @size to avoid excessive fragmentation on reserved array */
	size = round_up(size, align);

	spin_lock_irqsave(&tspblock_lock, flags);
	found = tspblock_find_in_range_node_reverse(0, max_addr, size, align, nid);
	if (found && !tspblock_reserve(found, size)) {
                spin_unlock_irqrestore(&tspblock_lock, flags);
		return found;
        }

        spin_unlock_irqrestore(&tspblock_lock, flags);
	return 0;
}


phys_addr_t  tspblock_alloc_nid_bottom_up(phys_addr_t size, phys_addr_t align, int nid)
{
	return tspblock_alloc_base_nid_bottom_up(size, align, TSPBLOCK_ALLOC_ACCESSIBLE, nid);
}

phys_addr_t  tspblock_alloc_nid(phys_addr_t size, phys_addr_t align, int nid)
{
	return tspblock_alloc_base_nid(size, align, TSPBLOCK_ALLOC_ACCESSIBLE, nid);
}

phys_addr_t __tspblock_alloc_base(phys_addr_t size, phys_addr_t align, phys_addr_t max_addr)
{
	return tspblock_alloc_base_nid(size, align, max_addr, MCK_MAX_NUMNODES);
}


phys_addr_t __tspblock_alloc_base_bottom_up(phys_addr_t size, phys_addr_t align, phys_addr_t max_addr)
{
	return tspblock_alloc_base_nid_bottom_up(size, align, max_addr, MCK_MAX_NUMNODES);
}


phys_addr_t tspblock_alloc_base_bottom_up(phys_addr_t size, phys_addr_t align, phys_addr_t max_addr)
{
	phys_addr_t alloc;

	alloc = __tspblock_alloc_base_bottom_up(size, align, max_addr);

	if (alloc == 0)
		printk("ERROR: Failed to allocate 0x%llx bytes below 0x%llx.\n",
		      (unsigned long long) size, (unsigned long long) max_addr);

	return alloc;
}


phys_addr_t tspblock_alloc_base(phys_addr_t size, phys_addr_t align, phys_addr_t max_addr)
{
	phys_addr_t alloc;

	alloc = __tspblock_alloc_base(size, align, max_addr);

	if (alloc == 0)
		printk("ERROR: Failed to allocate 0x%llx bytes below 0x%llx.\n",
		      (unsigned long long) size, (unsigned long long) max_addr);

	return alloc;
}

/* align should not be 0 */
phys_addr_t tspblock_alloc(phys_addr_t size, phys_addr_t align)
{
        BUG_ON(align == 0);
	return tspblock_alloc_base(size, align, TSPBLOCK_ALLOC_ACCESSIBLE);
}


/* align should not be 0 */
phys_addr_t tspblock_alloc_bottom_up(phys_addr_t size, phys_addr_t align)
{
        BUG_ON(align == 0);
	return tspblock_alloc_base_bottom_up(size, align, TSPBLOCK_ALLOC_ACCESSIBLE);
}

phys_addr_t tspblock_alloc_try_nid_bottom_up(phys_addr_t size, phys_addr_t align, int nid)
{
        phys_addr_t res;
        BUG_ON(align == 0);
	res = tspblock_alloc_nid_bottom_up(size, align, nid);

	if (res)
		return res;
	return tspblock_alloc_base_bottom_up(size, align, TSPBLOCK_ALLOC_ACCESSIBLE);
}



phys_addr_t tspblock_alloc_try_nid(phys_addr_t size, phys_addr_t align, int nid)
{
        phys_addr_t res;
        BUG_ON(align == 0);
	res = tspblock_alloc_nid(size, align, nid);

	if (res)
		return res;
	return tspblock_alloc_base(size, align, TSPBLOCK_ALLOC_ACCESSIBLE);
}


/*
 * Remaining API functions
 */

phys_addr_t tspblock_phys_mem_size(void)
{
	return tspblock.memory.total_size;
}

/* lowest address */
phys_addr_t  tspblock_start_of_DRAM(void)
{
	return tspblock.memory.regions[0].base;
}

phys_addr_t  tspblock_end_of_DRAM(void)
{
	int idx = tspblock.memory.cnt - 1;

	return (tspblock.memory.regions[idx].base + tspblock.memory.regions[idx].size);
}

void tspblock_enforce_memory_limit(phys_addr_t limit)
{
	unsigned long i;
	phys_addr_t max_addr = (phys_addr_t)ULLONG_MAX;

	if (!limit)
		return;

	/* find out max address */
	for (i = 0; i < tspblock.memory.cnt; i++) {
		struct tspblock_region *r = &tspblock.memory.regions[i];

		if (limit <= r->size) {
			max_addr = r->base + limit;
			break;
		}
		limit -= r->size;
	}

	/* truncate both memory and reserved regions */
	__tspblock_remove(&tspblock.memory, max_addr, (phys_addr_t)ULLONG_MAX);
	__tspblock_remove(&tspblock.reserved, max_addr, (phys_addr_t)ULLONG_MAX);
}

static int  tspblock_search(struct tspblock_type *type, phys_addr_t addr)
{
	unsigned int left = 0, right = type->cnt;

	do {
		unsigned int mid = (right + left) / 2;

		if (addr < type->regions[mid].base)
			right = mid;
		else if (addr >= (type->regions[mid].base +
				  type->regions[mid].size))
			left = mid + 1;
		else
			return mid;
	} while (left < right);
	return -1;
}

int tspblock_is_reserved(phys_addr_t addr)
{
	return tspblock_search(&tspblock.reserved, addr) != -1;
}

int  tspblock_is_memory(phys_addr_t addr)
{
	return tspblock_search(&tspblock.memory, addr) != -1;
}

/**
 * tspblock_is_region_memory - check if a region is a subset of memory
 * @base: base of region to check
 * @size: size of region to check
 *
 * Check if the region [@base, @base+@size) is a subset of a memory block.
 *
 * RETURNS:
 * 0 if false, non-zero if true
 */
int  tspblock_is_region_memory(phys_addr_t base, phys_addr_t size)
{
	int idx = tspblock_search(&tspblock.memory, base);
	phys_addr_t end = base + tspblock_cap_size(base, &size);

	if (idx == -1)
		return 0;
	return tspblock.memory.regions[idx].base <= base &&
		(tspblock.memory.regions[idx].base +
		 tspblock.memory.regions[idx].size) >= end;
}

/**
 * tspblock_is_region_reserved - check if a region intersects reserved memory
 * @base: base of region to check
 * @size: size of region to check
 *
 * Check if the region [@base, @base+@size) intersects a reserved memory block.
 *
 * RETURNS:
 * 0 if false, non-zero if true
 */
int  tspblock_is_region_reserved(phys_addr_t base, phys_addr_t size)
{
	tspblock_cap_size(base, &size);
	return tspblock_overlaps_region(&tspblock.reserved, base, size) >= 0;
}

void  tspblock_trim_memory(phys_addr_t align)
{
	int i;
	phys_addr_t start, end, orig_start, orig_end;
	struct tspblock_type *mem = &tspblock.memory;

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
			tspblock_remove_region(mem, i);
			i--;
		}
	}
}

void  tspblock_set_current_limit(phys_addr_t limit)
{
	tspblock.current_limit = limit;
}

static void  tspblock_dump(struct tspblock_type *type, char *name)
{
	unsigned long long base, size;
	int i;

	pr_info(" %s.cnt  = 0x%lx\n", name, type->cnt);

	for (i = 0; i < type->cnt; i++) {
		struct tspblock_region *rgn = &type->regions[i];
		char nid_buf[32] = "";

		base = rgn->base;
		size = rgn->size;
		if (tspblock_get_region_node(rgn) != MCK_MAX_NUMNODES)
			snprintf(nid_buf, sizeof(nid_buf), " on node %d",
				 tspblock_get_region_node(rgn));
		pr_info(" %s[%#x]\t[%#016llx-%#016llx], %#llx bytes%s\n",
			name, i, base, base + size - 1, size, nid_buf);
	}
}

void  __tspblock_dump_all(void)
{
	pr_info("tspblock configuration:\n");
	pr_info(" memory size = %#llx reserved size = %#llx\n",
		(unsigned long long)tspblock.memory.total_size,
		(unsigned long long)tspblock.reserved.total_size);

	tspblock_dump(&tspblock.memory, "memory");
	tspblock_dump(&tspblock.reserved, "reserved");
}

/* Allow tspblock use kmalloc to store mblock info */
void tspblock_allow_resize(void)
{
	tspblock_can_resize = 1;
}

static void  tspblock_dump_show(struct seq_file *m,struct tspblock_type *type, char *name)
{
    unsigned long long base, size;
    int i;

    for (i = 0; i < type->cnt; i++) {
        struct tspblock_region *rgn = &type->regions[i];
        char nid_buf[32] = "";

        base = rgn->base;
        size = rgn->size;
        if (tspblock_get_region_node(rgn) != MCK_MAX_NUMNODES)
            snprintf(nid_buf, sizeof(nid_buf), " on node %d",
                    tspblock_get_region_node(rgn));
        seq_printf(m," %s[%#x]\t[%#016llx-%#016llx], %#llx bytes%s\n",
                name, i, base, base + size - 1, size, nid_buf);
    }
}

static int tspblock_proc_show(struct seq_file *m, void *v)
{
    if (tspblock.memory.total_size > 0)
    {
        seq_printf(m, " Memory total_size = %#llx bytes\n",
                (unsigned long long)tspblock.memory.total_size);
        tspblock_dump_show(m,&tspblock.memory, "memory");
    }
    if (tspblock.reserved.total_size > 0)
    {
        seq_printf(m, " Reserved total_size = %#llx bytes\n",
                (unsigned long long)tspblock.reserved.total_size);
        tspblock_dump_show(m,&tspblock.reserved, "reserved");
    }
    return 0;
}

static int tspblock_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, tspblock_proc_show, NULL);
}

static const struct proc_ops tspblock_proc_fops = {
    .proc_open       = tspblock_proc_open,
    .proc_read       = seq_read,
    .proc_lseek      = seq_lseek,
    .proc_release    = seq_release_private,
};

static int __init proc_tspblock_init(void)
{
        proc_create("tspblock", 0444, NULL, &tspblock_proc_fops);
        return 0;
}
fs_initcall(proc_tspblock_init);



