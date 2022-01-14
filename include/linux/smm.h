/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TSP_H__
#define __TSP_H__

#ifdef __KERNEL__

#include <linux/init.h>
#include <linux/types.h>
#include <linux/numa.h>
#include <linux/mm.h>
#include <asm/smm.h>

extern void __init smm_reserve(int order);

#define MCK_MAX_NUMNODES 16
#define INIT_TSPBLOCK_REGIONS	128

#define smmblock_is_region_reserved(base, size) smmblock_is_region_reserved(base, size) 
#define smmblock_reserve(base, size) smmblock_reserve(base, size)
#define __smmblock_alloc_base(size, alignment, limit) __smmblock_alloc_base(size, alignment, limit)
#define smmblock_region_memory_end_pfn(reg) smmblock_region_memory_end_pfn(reg)
#define smmblock_region_memory_base_pfn(reg) smmblock_region_memory_base_pfn(reg)
#define smmblock_region smmblock_region

struct smmblock_region {
	phys_addr_t base;
	phys_addr_t size;
	int nid;
};

struct smmblock_type {
	unsigned long cnt;	/* number of regions */
	unsigned long max;	/* size of the allocated array */
	phys_addr_t total_size;	/* size of all regions */
	struct smmblock_region *regions;
};

struct smmblock {
	phys_addr_t current_limit;
	struct smmblock_type memory;
	struct smmblock_type reserved;
};

extern struct smmblock smmblock;
extern int smmblock_debug;

#define smmblock_dbg(fmt, ...) \
	if (smmblock_debug) printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)

phys_addr_t smmblock_find_in_range_node(phys_addr_t start, phys_addr_t end,
				phys_addr_t size, phys_addr_t align, int nid);
phys_addr_t smmblock_find_in_range(phys_addr_t start, phys_addr_t end,
				   phys_addr_t size, phys_addr_t align);
phys_addr_t get_allocated_smmblock_reserved_regions_info(phys_addr_t *addr);
void smmblock_allow_resize(void);
int smmblock_add_node(phys_addr_t base, phys_addr_t size, int nid);
int smmblock_add(phys_addr_t base, phys_addr_t size);
int smmblock_remove(phys_addr_t base, phys_addr_t size);
int smmblock_free(phys_addr_t base, phys_addr_t size);
int smmblock_reserve(phys_addr_t base, phys_addr_t size);
void smmblock_trim_memory(phys_addr_t align);

void __next_mckmem_pfn_range(int *idx, int nid, unsigned long *out_start_pfn,
			  unsigned long *out_end_pfn, int *out_nid);

void __next_free_mckmem_range(u64 *idx, int nid, phys_addr_t *out_start,
			   phys_addr_t *out_end, int *out_nid);

/**
 * for_each_freemem_range - iterate through free smmblock areas
 * @i: u64 used as loop variable
 * @nid: node selector, %MAX_NUMNODES for all nodes
 * @p_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @p_end: ptr to phys_addr_t for end address of the range, can be %NULL
 * @p_nid: ptr to int for nid of the range, can be %NULL
 *
 * Walks over free (memory && !reserved) areas of smmblock.  Available as
 * soon as smmblock is initialized.
 */
#define for_each_freemem_range(i, nid, p_start, p_end, p_nid)		\
	for (i = 0,							\
	     __next_free_mckmem_range(&i, nid, p_start, p_end, p_nid);	\
	     i != (u64)ULLONG_MAX;					\
	     __next_free_mckmem_range(&i, nid, p_start, p_end, p_nid))

void __next_free_mckmem_range_rev(u64 *idx, int nid, phys_addr_t *out_start,
			       phys_addr_t *out_end, int *out_nid);

/**
 * for_each_freemem_range_reverse - rev-iterate through free smmblock areas
 * @i: u64 used as loop variable
 * @nid: node selector, %MAX_NUMNODES for all nodes
 * @p_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @p_end: ptr to phys_addr_t for end address of the range, can be %NULL
 * @p_nid: ptr to int for nid of the range, can be %NULL
 *
 * Walks over free (memory && !reserved) areas of smmblock in reverse
 * order.  Available as soon as smmblock is initialized.
 */
#define for_each_freemem_range_reverse(i, nid, p_start, p_end, p_nid)	\
	for (i = (u64)ULLONG_MAX,					\
	     __next_free_mckmem_range_rev(&i, nid, p_start, p_end, p_nid);	\
	     i != (u64)ULLONG_MAX;					\
	     __next_free_mckmem_range_rev(&i, nid, p_start, p_end, p_nid))

int smmblock_set_node(phys_addr_t base, phys_addr_t size, int nid);

static inline void smmblock_set_region_node(struct smmblock_region *r, int nid)
{
	r->nid = nid;
}

static inline int smmblock_get_region_node(const struct smmblock_region *r)
{
	return r->nid;
}
phys_addr_t smmblock_alloc_nid_bottom_up(phys_addr_t size, phys_addr_t align, int nid);
phys_addr_t smmblock_alloc_nid(phys_addr_t size, phys_addr_t align, int nid);
phys_addr_t smmblock_alloc_try_nid(phys_addr_t size, phys_addr_t align, int nid);

phys_addr_t smmblock_alloc(phys_addr_t size, phys_addr_t align);

/* Flags for smmblock_alloc_base() amd __smmblock_alloc_base() */
#define TSPBLOCK_ALLOC_ANYWHERE	(~(phys_addr_t)0)
#define TSPBLOCK_ALLOC_ACCESSIBLE	0

phys_addr_t smmblock_alloc_base_bottom_up(phys_addr_t size, phys_addr_t align,
				phys_addr_t max_addr);
phys_addr_t smmblock_alloc_base(phys_addr_t size, phys_addr_t align,
				phys_addr_t max_addr);
phys_addr_t __smmblock_alloc_base(phys_addr_t size, phys_addr_t align,
				  phys_addr_t max_addr);
phys_addr_t smmblock_phys_mem_size(void);
phys_addr_t smmblock_start_of_DRAM(void);
phys_addr_t smmblock_end_of_DRAM(void);
void smmblock_enforce_memory_limit(phys_addr_t memory_limit);
int smmblock_is_memory(phys_addr_t addr);
int smmblock_is_region_memory(phys_addr_t base, phys_addr_t size);
int smmblock_is_reserved(phys_addr_t addr);
int smmblock_is_region_reserved(phys_addr_t base, phys_addr_t size);

extern void __smmblock_dump_all(void);

static inline void smmblock_dump_all(void)
{
	if (smmblock_debug)
		__smmblock_dump_all();
}

/**
 * smmblock_set_current_limit - Set the current allocation limit to allow
 *                         limiting allocations to what is currently
 *                         accessible during boot
 * @limit: New limit value (physical address)
 */
void smmblock_set_current_limit(phys_addr_t limit);


/*
 * pfn conversion functions
 *
 * While the memory smmblocks should always be page aligned, the reserved
 * smmblocks may not be. This accessor attempt to provide a very clear
 * idea of what they return for such non aligned smmblocks.
 */

/**
 * smmblock_region_memory_base_pfn - Return the lowest pfn intersecting with the memory region
 * @reg: smmblock_region structure
 */
static inline unsigned long smmblock_region_memory_base_pfn(const struct smmblock_region *reg)
{
	return PFN_UP(reg->base);
}

/**
 * smmblock_region_memory_end_pfn - Return the end_pfn this region
 * @reg: smmblock_region structure
 */
static inline unsigned long smmblock_region_memory_end_pfn(const struct smmblock_region *reg)
{
	return PFN_DOWN(reg->base + reg->size);
}

/**
 * smmblock_region_reserved_base_pfn - Return the lowest pfn intersecting with the reserved region
 * @reg: smmblock_region structure
 */
static inline unsigned long smmblock_region_reserved_base_pfn(const struct smmblock_region *reg)
{
	return PFN_DOWN(reg->base);
}

/**
 * smmblock_region_reserved_end_pfn - Return the end_pfn this region
 * @reg: smmblock_region structure
 */
static inline unsigned long smmblock_region_reserved_end_pfn(const struct smmblock_region *reg)
{
	return PFN_UP(reg->base + reg->size);
}

#define for_each_smmblock(smmblock_type, region)					\
	for (region = smmblock.smmblock_type.regions;				\
	     region < (smmblock.smmblock_type.regions + smmblock.smmblock_type.cnt);	\
	     region++)


int smmblock_internal_test(void);

#define TSPIO 0xAF

#define TSPBLOCK_ALLOC                 _IOWR(TSPBLOCKIO, 0x02, void *)
#define TSPBLOCK_FREE                  _IOWR(TSPBLOCKIO, 0x03, unsigned long)


struct smm {
        atomic_t users_count;
        struct mm_struct        *mm;
        struct task_struct      *task;
        unsigned long code_segment_paddr;
        unsigned long code_segment_size;
        unsigned long code_segment_swapped;
        unsigned long heap_segment_paddr;
        unsigned long heap_segment_size;
        unsigned long heap_segment_swapped;
        unsigned long mmap_segment_paddr;
        unsigned long mmap_segment_size;
        unsigned long mmap_segment_swapped;
        unsigned long stack_segment_paddr;
        unsigned long stack_segment_size;
        unsigned long stack_segment_swapped;
	int is_swapped;
};

struct smm * smm_alloc(unsigned long code_size, unsigned long heap_size,
                unsigned long mmap_size, unsigned long stack_size);
void get_smm(struct smm *smm);
void put_smm(struct smm *smm);
extern struct file_operations smm_fops;
int smm_swap_current(void);
int smm_check_current(void);
void put_smm_page(struct page *page);
int is_current_smm_swapped(void);
int is_vma_smm_swapped(struct vm_area_struct *vma);
struct page *alloc_zeroed_smm_page(struct vm_area_struct *vma,
				   unsigned long address);
void dup_smm_page(struct page *old_page, struct page *smm_page);
unsigned long smm_vaddr_to_paddr(struct smm *smm, unsigned long vaddr);
vm_fault_t do_smm_huge_pmd_anonymous_page(struct vm_fault *vmf);
vm_fault_t do_smm_huge_pud_anonymous_page(struct vm_fault *vmf);

int zap_smm_huge_pmd(struct mmu_gather *tlb, struct vm_area_struct *vma,
		 pmd_t *pmd, unsigned long addr);
int zap_smm_huge_pud(struct mmu_gather *tlb, struct vm_area_struct *vma,
		     pud_t *pud, unsigned long addr);
void split_smm_huge_pmd(struct vm_area_struct *vma, pmd_t *pmd,
		unsigned long address);
void split_smm_huge_pud(struct vm_area_struct *vma, pud_t *pud,
		unsigned long address);

int smm_alloc_and_create(unsigned long code_size, unsigned long heap_size,
		unsigned long mmap_size, unsigned long stack_size);

int smm_setup_current(void);
void smm_exit_dump(void);
int swap_smm_vma_range(struct vm_area_struct *vma, unsigned long addr,
		   unsigned long size);

int check_smm_range(struct vm_area_struct *vma, unsigned long addr,
		    unsigned long size, pgprot_t prot);

bool move_smm_huge_pmd(struct vm_area_struct *vma, unsigned long old_addr,
		  unsigned long new_addr, unsigned long old_end,
		  pmd_t *old_pmd, pmd_t *new_pmd);

#define tlb_remove_smm_pmd_tlb_entry(tlb, pmdp, address)			\
	do {								\
		__tlb_adjust_range(tlb, address, TSP_HPAGE_PMD_SIZE);	\
		tlb->cleared_pmds = 1;					\
		__tlb_remove_pmd_tlb_entry(tlb, pmdp, address);		\
	} while (0)

void smm_huge_pmd_set_accessed(struct vm_fault *vmf, pmd_t orig_pmd);
void smm_huge_pud_set_accessed(struct vm_fault *vmf, pud_t orig_pud);

struct page *follow_smm_huge_pmd(struct vm_area_struct *vma,
				   unsigned long addr,
				   pmd_t *pmd,
				   unsigned int flags);

spinlock_t *__pmd_smm_huge_lock(pmd_t *pmd, struct vm_area_struct *vma);
static inline spinlock_t *pmd_smm_huge_lock(pmd_t *pmd,
		struct vm_area_struct *vma)
{
	if (pmd_smm_huge(*pmd))
		return __pmd_smm_huge_lock(pmd, vma);
	else
		return NULL;
}

int coalesce_smm_vma(struct vm_area_struct *vma);
int coalesce_smm_pmd(struct vm_area_struct *vma, unsigned long address);
int coalesce_smm_pud(struct vm_area_struct *vma, unsigned long address);


static inline bool smm_pmd_huge_enabled(struct vm_area_struct *vma)
{
	if (!vma->vm_mm->smm_pmd)
		return 0;
	if (smm_vaddr_is_code(vma->vm_start))
		return 0;
	if (smm_vaddr_is_stack(vma->vm_start))
		return 0;
	return 1;
}



#endif


#endif
