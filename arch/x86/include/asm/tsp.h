#ifndef _ARCH_TSP_H
#define _ARCH_TSP_H

#define TSP_SEGMENT_SHIFT 45
#define _TSP_SEGMENT_CODE 0UL
#define _TSP_SEGMENT_HEAP 1UL
#define _TSP_SEGMENT_MMAP 2UL
#define _TSP_SEGMENT_STACK 3UL
#define TSP_SEGMENT_SIZE (1UL << 45)

#define TSP_SEGMENT_BASE_CODE (_TSP_SEGMENT_CODE << TSP_SEGMENT_SHIFT)
#define TSP_SEGMENT_BASE_HEAP (_TSP_SEGMENT_HEAP << TSP_SEGMENT_SHIFT)
#define TSP_SEGMENT_BASE_MMAP (_TSP_SEGMENT_MMAP << TSP_SEGMENT_SHIFT)
#define TSP_SEGMENT_BASE_STACK (_TSP_SEGMENT_STACK << TSP_SEGMENT_SHIFT)

#define TSP_SEGMENT_TOP_CODE (TSP_SEGMENT_BASE_CODE + TSP_SEGMENT_SIZE - 1)
#define TSP_SEGMENT_TOP_HEAP (TSP_SEGMENT_BASE_HEAP + TSP_SEGMENT_SIZE - 1)
#define TSP_SEGMENT_TOP_MMAP (TSP_SEGMENT_BASE_MMAP + TSP_SEGMENT_SIZE - 1)
#define TSP_SEGMENT_TOP_STACK (TSP_SEGMENT_BASE_STACK + TSP_SEGMENT_SIZE - 1)

static inline int tsp_vaddr_is_code(unsigned long vaddr)
{
	if ((vaddr >= TSP_SEGMENT_BASE_CODE) &&
	       (vaddr <= TSP_SEGMENT_TOP_CODE))
		return 1;
	return 0;
}

static inline int tsp_vaddr_is_heap(unsigned long vaddr)
{
	if ((vaddr >= TSP_SEGMENT_BASE_HEAP) &&
	       (vaddr <= TSP_SEGMENT_TOP_HEAP))
		return 1;
	return 0;
}

static inline int tsp_vaddr_is_mmap(unsigned long vaddr)
{
	if ((vaddr >= TSP_SEGMENT_BASE_MMAP) &&
	       (vaddr <= TSP_SEGMENT_TOP_MMAP))
		return 1;
	return 0;
}

static inline int tsp_vaddr_is_stack(unsigned long vaddr)
{
	if ((vaddr >= TSP_SEGMENT_BASE_STACK) &&
	       (vaddr <= TSP_SEGMENT_TOP_STACK))
		return 1;
	return 0;
}

#endif /* _ARCH_TSP_H */
