#ifndef _LINUX_SMM_H
#define _LINUX_SMM_H


#ifdef __KERNEL__


#define SMM_STACK_SIZE_LIMIT 0x10000000ul


extern void __init smm_reserve(int order);
extern bool smm_cma_cancel(unsigned long pfn, unsigned int count);
extern unsigned long smm_cma_reserve(unsigned long count, unsigned long align);
extern void smm_cma_reserve_code(unsigned long size, struct mm_struct *mm);
extern void smm_cma_reserve_stack(unsigned long size, struct mm_struct *mm);
extern void smm_cma_reserve_mem(unsigned long size, struct mm_struct *mm);
extern void exit_smm(struct mm_struct *mm);
extern unsigned long smm_stack_va_to_pa(struct mm_struct *mm, unsigned long va);
extern unsigned long smm_heap_va_to_pa(struct mm_struct *mm, unsigned long va);
extern unsigned long smm_mmap_va_to_pa(struct mm_struct *mm, unsigned long va);
extern void mm_init_smm(struct mm_struct *mm);
#endif /* __KERNEL__ */
#endif /* _LINUX_SMM_H */
