#include <asm/page.h>

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched.h>

#if defined(CONFIG_TRANSPARENT_HUGEPAGE) || defined(CONFIG_HUGETLBFS)
#define PAGES_BETWEEN_RESCHED 64
void clear_gigantic_page(struct page *page,
				unsigned long addr,
				unsigned int pages_per_huge_page)
{
	int i;
	void *dest = page_to_virt(page);
	int resched_count = 0;

	BUG_ON(pages_per_huge_page % PAGES_BETWEEN_RESCHED != 0);
	BUG_ON(!dest);

	for (i = 0; i < pages_per_huge_page; i += PAGES_BETWEEN_RESCHED) {
		__clear_page_nt(dest + (i * PAGE_SIZE),
				PAGES_BETWEEN_RESCHED * PAGE_SIZE);
		resched_count += cond_resched();
	}
	/* __clear_page_nt requrires and `sfence` barrier. */
	wmb();
	pr_debug("clear_gigantic_page: rescheduled %d times\n", resched_count);
}
#endif
