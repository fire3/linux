/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TSP_H__
#define __TSP_H__

#ifdef __KERNEL__

#include <linux/init.h>
#include <linux/types.h>
#include <linux/numa.h>
#include <linux/mm.h>

extern void __init tsp_reserve(int order);

#define MCK_MAX_NUMNODES 16
#define INIT_TSPBLOCK_REGIONS	128

#define tspblock_is_region_reserved(base, size) tspblock_is_region_reserved(base, size) 
#define tspblock_reserve(base, size) tspblock_reserve(base, size)
#define __tspblock_alloc_base(size, alignment, limit) __tspblock_alloc_base(size, alignment, limit)
#define tspblock_region_memory_end_pfn(reg) tspblock_region_memory_end_pfn(reg)
#define tspblock_region_memory_base_pfn(reg) tspblock_region_memory_base_pfn(reg)
#define tspblock_region tspblock_region

struct tspblock_region {
	phys_addr_t base;
	phys_addr_t size;
	int nid;
};

struct tspblock_type {
	unsigned long cnt;	/* number of regions */
	unsigned long max;	/* size of the allocated array */
	phys_addr_t total_size;	/* size of all regions */
	struct tspblock_region *regions;
};

struct tspblock {
	phys_addr_t current_limit;
	struct tspblock_type memory;
	struct tspblock_type reserved;
};

extern struct tspblock tspblock;
extern int tspblock_debug;

#define tspblock_dbg(fmt, ...) \
	if (tspblock_debug) printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)

phys_addr_t tspblock_find_in_range_node(phys_addr_t start, phys_addr_t end,
				phys_addr_t size, phys_addr_t align, int nid);
phys_addr_t tspblock_find_in_range(phys_addr_t start, phys_addr_t end,
				   phys_addr_t size, phys_addr_t align);
phys_addr_t get_allocated_tspblock_reserved_regions_info(phys_addr_t *addr);
void tspblock_allow_resize(void);
int tspblock_add_node(phys_addr_t base, phys_addr_t size, int nid);
int tspblock_add(phys_addr_t base, phys_addr_t size);
int tspblock_remove(phys_addr_t base, phys_addr_t size);
int tspblock_free(phys_addr_t base, phys_addr_t size);
int tspblock_reserve(phys_addr_t base, phys_addr_t size);
void tspblock_trim_memory(phys_addr_t align);

void __next_mckmem_pfn_range(int *idx, int nid, unsigned long *out_start_pfn,
			  unsigned long *out_end_pfn, int *out_nid);

void __next_free_mckmem_range(u64 *idx, int nid, phys_addr_t *out_start,
			   phys_addr_t *out_end, int *out_nid);

/**
 * for_each_freemem_range - iterate through free tspblock areas
 * @i: u64 used as loop variable
 * @nid: node selector, %MAX_NUMNODES for all nodes
 * @p_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @p_end: ptr to phys_addr_t for end address of the range, can be %NULL
 * @p_nid: ptr to int for nid of the range, can be %NULL
 *
 * Walks over free (memory && !reserved) areas of tspblock.  Available as
 * soon as tspblock is initialized.
 */
#define for_each_freemem_range(i, nid, p_start, p_end, p_nid)		\
	for (i = 0,							\
	     __next_free_mckmem_range(&i, nid, p_start, p_end, p_nid);	\
	     i != (u64)ULLONG_MAX;					\
	     __next_free_mckmem_range(&i, nid, p_start, p_end, p_nid))

void __next_free_mckmem_range_rev(u64 *idx, int nid, phys_addr_t *out_start,
			       phys_addr_t *out_end, int *out_nid);

/**
 * for_each_freemem_range_reverse - rev-iterate through free tspblock areas
 * @i: u64 used as loop variable
 * @nid: node selector, %MAX_NUMNODES for all nodes
 * @p_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @p_end: ptr to phys_addr_t for end address of the range, can be %NULL
 * @p_nid: ptr to int for nid of the range, can be %NULL
 *
 * Walks over free (memory && !reserved) areas of tspblock in reverse
 * order.  Available as soon as tspblock is initialized.
 */
#define for_each_freemem_range_reverse(i, nid, p_start, p_end, p_nid)	\
	for (i = (u64)ULLONG_MAX,					\
	     __next_free_mckmem_range_rev(&i, nid, p_start, p_end, p_nid);	\
	     i != (u64)ULLONG_MAX;					\
	     __next_free_mckmem_range_rev(&i, nid, p_start, p_end, p_nid))

int tspblock_set_node(phys_addr_t base, phys_addr_t size, int nid);

static inline void tspblock_set_region_node(struct tspblock_region *r, int nid)
{
	r->nid = nid;
}

static inline int tspblock_get_region_node(const struct tspblock_region *r)
{
	return r->nid;
}
phys_addr_t tspblock_alloc_nid_bottom_up(phys_addr_t size, phys_addr_t align, int nid);
phys_addr_t tspblock_alloc_nid(phys_addr_t size, phys_addr_t align, int nid);
phys_addr_t tspblock_alloc_try_nid(phys_addr_t size, phys_addr_t align, int nid);

phys_addr_t tspblock_alloc(phys_addr_t size, phys_addr_t align);

/* Flags for tspblock_alloc_base() amd __tspblock_alloc_base() */
#define TSPBLOCK_ALLOC_ANYWHERE	(~(phys_addr_t)0)
#define TSPBLOCK_ALLOC_ACCESSIBLE	0

phys_addr_t tspblock_alloc_base_bottom_up(phys_addr_t size, phys_addr_t align,
				phys_addr_t max_addr);
phys_addr_t tspblock_alloc_base(phys_addr_t size, phys_addr_t align,
				phys_addr_t max_addr);
phys_addr_t __tspblock_alloc_base(phys_addr_t size, phys_addr_t align,
				  phys_addr_t max_addr);
phys_addr_t tspblock_phys_mem_size(void);
phys_addr_t tspblock_start_of_DRAM(void);
phys_addr_t tspblock_end_of_DRAM(void);
void tspblock_enforce_memory_limit(phys_addr_t memory_limit);
int tspblock_is_memory(phys_addr_t addr);
int tspblock_is_region_memory(phys_addr_t base, phys_addr_t size);
int tspblock_is_reserved(phys_addr_t addr);
int tspblock_is_region_reserved(phys_addr_t base, phys_addr_t size);

extern void __tspblock_dump_all(void);

static inline void tspblock_dump_all(void)
{
	if (tspblock_debug)
		__tspblock_dump_all();
}

/**
 * tspblock_set_current_limit - Set the current allocation limit to allow
 *                         limiting allocations to what is currently
 *                         accessible during boot
 * @limit: New limit value (physical address)
 */
void tspblock_set_current_limit(phys_addr_t limit);


/*
 * pfn conversion functions
 *
 * While the memory tspblocks should always be page aligned, the reserved
 * tspblocks may not be. This accessor attempt to provide a very clear
 * idea of what they return for such non aligned tspblocks.
 */

/**
 * tspblock_region_memory_base_pfn - Return the lowest pfn intersecting with the memory region
 * @reg: tspblock_region structure
 */
static inline unsigned long tspblock_region_memory_base_pfn(const struct tspblock_region *reg)
{
	return PFN_UP(reg->base);
}

/**
 * tspblock_region_memory_end_pfn - Return the end_pfn this region
 * @reg: tspblock_region structure
 */
static inline unsigned long tspblock_region_memory_end_pfn(const struct tspblock_region *reg)
{
	return PFN_DOWN(reg->base + reg->size);
}

/**
 * tspblock_region_reserved_base_pfn - Return the lowest pfn intersecting with the reserved region
 * @reg: tspblock_region structure
 */
static inline unsigned long tspblock_region_reserved_base_pfn(const struct tspblock_region *reg)
{
	return PFN_DOWN(reg->base);
}

/**
 * tspblock_region_reserved_end_pfn - Return the end_pfn this region
 * @reg: tspblock_region structure
 */
static inline unsigned long tspblock_region_reserved_end_pfn(const struct tspblock_region *reg)
{
	return PFN_UP(reg->base + reg->size);
}

#define for_each_tspblock(tspblock_type, region)					\
	for (region = tspblock.tspblock_type.regions;				\
	     region < (tspblock.tspblock_type.regions + tspblock.tspblock_type.cnt);	\
	     region++)


int tspblock_internal_test(void);

#define TSPBLOCKIO 0xAF

/*
 * ioctls for /dev/mck fds:
 */
#define TSPBLOCK_GET_API_VERSION       _IO(TSPBLOCKIO,   0x00)
#define TSPBLOCK_ALLOC                 _IOWR(TSPBLOCKIO, 0x02, void *)
#define TSPBLOCK_FREE                  _IOWR(TSPBLOCKIO, 0x03, unsigned long)


struct tsp {
        atomic_t users_count;
        struct mm_struct        *mm;
        struct task_struct      *task;
        unsigned long code_segment_paddr;
        unsigned long code_segment_size;
        unsigned long heap_segment_paddr;
        unsigned long heap_segment_size;
        unsigned long mmap_segment_paddr;
        unsigned long mmap_segment_size;
        unsigned long stack_segment_paddr;
        unsigned long stack_segment_size;
	int is_remaped;
};

struct tsp * tsp_alloc(unsigned long code_size, unsigned long heap_size,
                unsigned long mmap_size, unsigned long stack_size);
void get_tsp(struct tsp *tsp);
void put_tsp(struct tsp *tsp);
extern struct file_operations tsp_fops;
#endif


#endif
