/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/linkage.h>
#include <asm/export.h>

/*
 * Most CPUs support enhanced REP MOVSB/STOSB instructions. It is
 * recommended to use this when possible and we do use them by default.
 * If enhanced REP MOVSB/STOSB is not available, try to use fast string.
 * Otherwise, use original.
 */

/*
 * Zero a page.
 * %rdi	- page
 */
SYM_FUNC_START(clear_page_rep)
	movl $4096/8,%ecx
	xorl %eax,%eax
	rep stosq
	ret
SYM_FUNC_END(clear_page_rep)
EXPORT_SYMBOL_GPL(clear_page_rep)

SYM_FUNC_START(clear_page_orig)
	xorl   %eax,%eax
	movl   $4096/64,%ecx
	.p2align 4
.Lloop:
	decl	%ecx
#define PUT(x) movq %rax,x*8(%rdi)
	movq %rax,(%rdi)
	PUT(1)
	PUT(2)
	PUT(3)
	PUT(4)
	PUT(5)
	PUT(6)
	PUT(7)
	leaq	64(%rdi),%rdi
	jnz	.Lloop
	nop
	ret
SYM_FUNC_END(clear_page_orig)
EXPORT_SYMBOL_GPL(clear_page_orig)

SYM_FUNC_START(clear_page_erms)
	movl $4096,%ecx
	xorl %eax,%eax
	rep stosb
	ret
SYM_FUNC_END(clear_page_erms)
EXPORT_SYMBOL_GPL(clear_page_erms)

/*
 * Zero memory using non temporal stores, bypassing the cache.
 * Requires an `sfence` (wmb()) afterwards.
 * %rdi - destination.
 * %rsi - page size. Must be 64 bit aligned.
*/
SYM_FUNC_START(__clear_page_nt)
	leaq	(%rdi,%rsi), %rdx
	xorl	%eax, %eax
	.p2align 4,,10
	.p2align 3
.L2:
	movnti	%rax, (%rdi)
	addq	$8, %rdi
	cmpq	%rdx, %rdi
	jne	.L2
	ret
SYM_FUNC_END(__clear_page_nt)
EXPORT_SYMBOL(__clear_page_nt)
