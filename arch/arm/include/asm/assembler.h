/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  arch/arm/include/asm/assembler.h
 *
 *  Copyright (C) 1996-2000 Russell King
 *
 *  This file contains arm architecture specific defines
 *  for the different processors.
 *
 *  Do not include any C declarations in this file - it is included by
 *  assembler source.
 */
#ifndef __ASM_ASSEMBLER_H__
#define __ASM_ASSEMBLER_H__

#ifndef __ASSEMBLY__
#error "Only include this from assembly code"
#endif

#include <asm/ptrace.h>
#include <asm/opcodes-virt.h>
#include <asm/asm-offsets.h>
#include <asm/page.h>
#include <asm/thread_info.h>
#include <asm/uaccess-asm.h>

#define IOMEM(x)	(x)

/*
 * Endian independent macros for shifting bytes within registers.
 */
#ifndef __ARMEB__
#define lspull          lsr
#define lspush          lsl
#define get_byte_0      lsl #0
#define get_byte_1	lsr #8
#define get_byte_2	lsr #16
#define get_byte_3	lsr #24
#define put_byte_0      lsl #0
#define put_byte_1	lsl #8
#define put_byte_2	lsl #16
#define put_byte_3	lsl #24
#else
#define lspull          lsl
#define lspush          lsr
#define get_byte_0	lsr #24
#define get_byte_1	lsr #16
#define get_byte_2	lsr #8
#define get_byte_3      lsl #0
#define put_byte_0	lsl #24
#define put_byte_1	lsl #16
#define put_byte_2	lsl #8
#define put_byte_3      lsl #0
#endif

/* Select code for any configuration running in BE8 mode */
#ifdef CONFIG_CPU_ENDIAN_BE8
#define ARM_BE8(code...) code
#else
#define ARM_BE8(code...)
#endif

/*
 * Data preload for architectures that support it
 */
#if __LINUX_ARM_ARCH__ >= 5
#define PLD(code...)	code
#else
#define PLD(code...)
#endif

/*
 * This can be used to enable code to cacheline align the destination
 * pointer when bulk writing to memory.  Experiments on StrongARM and
 * XScale didn't show this a worthwhile thing to do when the cache is not
 * set to write-allocate (this would need further testing on XScale when WA
 * is used).
 *
 * On Feroceon there is much to gain however, regardless of cache mode.
 */
#ifdef CONFIG_CPU_FEROCEON
#define CALGN(code...) code
#else
#define CALGN(code...)
#endif

#define IMM12_MASK 0xfff

/* the frame pointer used for stack unwinding */
ARM(	fpreg	.req	r11	)
THUMB(	fpreg	.req	r7	)

/*
 * Enable and disable interrupts
 */
#if __LINUX_ARM_ARCH__ >= 6
	.macro	disable_irq_notrace
	cpsid	i
	.endm

	.macro	enable_irq_notrace
	cpsie	i
	.endm
#else
	.macro	disable_irq_notrace
	msr	cpsr_c, #PSR_I_BIT | SVC_MODE
	.endm

	.macro	enable_irq_notrace
	msr	cpsr_c, #SVC_MODE
	.endm
#endif

#if __LINUX_ARM_ARCH__ < 7
	.macro	dsb, args
	mcr	p15, 0, r0, c7, c10, 4
	.endm

	.macro	isb, args
	mcr	p15, 0, r0, c7, c5, 4
	.endm
#endif

	.macro asm_trace_hardirqs_off, save=1
#if defined(CONFIG_TRACE_IRQFLAGS)
	.if \save
	stmdb   sp!, {r0-r3, ip, lr}
	.endif
	bl	trace_hardirqs_off
	.if \save
	ldmia	sp!, {r0-r3, ip, lr}
	.endif
#endif
	.endm

	.macro asm_trace_hardirqs_on, cond=al, save=1
#if defined(CONFIG_TRACE_IRQFLAGS)
	/*
	 * actually the registers should be pushed and pop'd conditionally, but
	 * after bl the flags are certainly clobbered
	 */
	.if \save
	stmdb   sp!, {r0-r3, ip, lr}
	.endif
	bl\cond	trace_hardirqs_on
	.if \save
	ldmia	sp!, {r0-r3, ip, lr}
	.endif
#endif
	.endm

	.macro disable_irq, save=1
	disable_irq_notrace
	asm_trace_hardirqs_off \save
	.endm

	.macro enable_irq
	asm_trace_hardirqs_on
	enable_irq_notrace
	.endm
/*
 * Save the current IRQ state and disable IRQs.  Note that this macro
 * assumes FIQs are enabled, and that the processor is in SVC mode.
 */
	.macro	save_and_disable_irqs, oldcpsr
#ifdef CONFIG_CPU_V7M
	mrs	\oldcpsr, primask
#else
	mrs	\oldcpsr, cpsr
#endif
	disable_irq
	.endm

	.macro	save_and_disable_irqs_notrace, oldcpsr
#ifdef CONFIG_CPU_V7M
	mrs	\oldcpsr, primask
#else
	mrs	\oldcpsr, cpsr
#endif
	disable_irq_notrace
	.endm

/*
 * Restore interrupt state previously stored in a register.  We don't
 * guarantee that this will preserve the flags.
 */
	.macro	restore_irqs_notrace, oldcpsr
#ifdef CONFIG_CPU_V7M
	msr	primask, \oldcpsr
#else
	msr	cpsr_c, \oldcpsr
#endif
	.endm

	.macro restore_irqs, oldcpsr
	tst	\oldcpsr, #PSR_I_BIT
	asm_trace_hardirqs_on cond=eq
	restore_irqs_notrace \oldcpsr
	.endm

/*
 * Assembly version of "adr rd, BSYM(sym)".  This should only be used to
 * reference local symbols in the same assembly file which are to be
 * resolved by the assembler.  Other usage is undefined.
 */
	.irp	c,,eq,ne,cs,cc,mi,pl,vs,vc,hi,ls,ge,lt,gt,le,hs,lo
	.macro	badr\c, rd, sym
#ifdef CONFIG_THUMB2_KERNEL
	adr\c	\rd, \sym + 1
#else
	adr\c	\rd, \sym
#endif
	.endm
	.endr

/*
 * Get current thread_info.
 */
	.macro	get_thread_info, rd
	/* thread_info is the first member of struct task_struct */
	get_current \rd
	.endm

/*
 * Increment/decrement the preempt count.
 */
#ifdef CONFIG_PREEMPT_COUNT
	.macro	inc_preempt_count, ti, tmp
	ldr	\tmp, [\ti, #TI_PREEMPT]	@ get preempt count
	add	\tmp, \tmp, #1			@ increment it
	str	\tmp, [\ti, #TI_PREEMPT]
	.endm

	.macro	dec_preempt_count, ti, tmp
	ldr	\tmp, [\ti, #TI_PREEMPT]	@ get preempt count
	sub	\tmp, \tmp, #1			@ decrement it
	str	\tmp, [\ti, #TI_PREEMPT]
	.endm

	.macro	dec_preempt_count_ti, ti, tmp
	get_thread_info \ti
	dec_preempt_count \ti, \tmp
	.endm
#else
	.macro	inc_preempt_count, ti, tmp
	.endm

	.macro	dec_preempt_count, ti, tmp
	.endm

	.macro	dec_preempt_count_ti, ti, tmp
	.endm
#endif

#define USERL(l, x...)				\
9999:	x;					\
	.pushsection __ex_table,"a";		\
	.align	3;				\
	.long	9999b,l;			\
	.popsection

#define USER(x...)	USERL(9001f, x)

#ifdef CONFIG_SMP
#define ALT_SMP(instr...)					\
9998:	instr
/*
 * Note: if you get assembler errors from ALT_UP() when building with
 * CONFIG_THUMB2_KERNEL, you almost certainly need to use
 * ALT_SMP( W(instr) ... )
 */
#define ALT_UP(instr...)					\
	.pushsection ".alt.smp.init", "a"			;\
	.align	2						;\
	.long	9998b - .					;\
9997:	instr							;\
	.if . - 9997b == 2					;\
		nop						;\
	.endif							;\
	.if . - 9997b != 4					;\
		.error "ALT_UP() content must assemble to exactly 4 bytes";\
	.endif							;\
	.popsection
#define ALT_UP_B(label)					\
	.pushsection ".alt.smp.init", "a"			;\
	.align	2						;\
	.long	9998b - .					;\
	W(b)	. + (label - 9998b)					;\
	.popsection
#else
#define ALT_SMP(instr...)
#define ALT_UP(instr...) instr
#define ALT_UP_B(label) b label
#endif

	/*
	 * this_cpu_offset - load the per-CPU offset of this CPU into
	 * 		     register 'rd'
	 */
	.macro		this_cpu_offset, rd:req
#ifdef CONFIG_SMP
ALT_SMP(mrc		p15, 0, \rd, c13, c0, 4)
#ifdef CONFIG_CPU_V6
ALT_UP_B(.L1_\@)
.L0_\@:
	.subsection	1
.L1_\@: ldr_va		\rd, __per_cpu_offset
	b		.L0_\@
	.previous
#endif
#else
	mov		\rd, #0
#endif
	.endm

	/*
	 * set_current - store the task pointer of this CPU's current task
	 */
	.macro		set_current, rn:req, tmp:req
#if defined(CONFIG_CURRENT_POINTER_IN_TPIDRURO) || defined(CONFIG_SMP)
9998:	mcr		p15, 0, \rn, c13, c0, 3		@ set TPIDRURO register
#ifdef CONFIG_CPU_V6
ALT_UP_B(.L0_\@)
	.subsection	1
.L0_\@: str_va		\rn, __current, \tmp
	b		.L1_\@
	.previous
.L1_\@:
#endif
#else
	str_va		\rn, __current, \tmp
#endif
	.endm

	/*
	 * get_current - load the task pointer of this CPU's current task
	 */
	.macro		get_current, rd:req
#if defined(CONFIG_CURRENT_POINTER_IN_TPIDRURO) || defined(CONFIG_SMP)
9998:	mrc		p15, 0, \rd, c13, c0, 3		@ get TPIDRURO register
#ifdef CONFIG_CPU_V6
ALT_UP_B(.L0_\@)
	.subsection	1
.L0_\@: ldr_va		\rd, __current
	b		.L1_\@
	.previous
.L1_\@:
#endif
#else
	ldr_va		\rd, __current
#endif
	.endm

	/*
	 * reload_current - reload the task pointer of this CPU's current task
	 *		    into the TLS register
	 */
	.macro		reload_current, t1:req, t2:req
#if defined(CONFIG_CURRENT_POINTER_IN_TPIDRURO) || defined(CONFIG_SMP)
#ifdef CONFIG_CPU_V6
ALT_SMP(nop)
ALT_UP_B(.L0_\@)
#endif
	ldr_this_cpu	\t1, __entry_task, \t1, \t2
	mcr		p15, 0, \t1, c13, c0, 3		@ store in TPIDRURO
.L0_\@:
#endif
	.endm

/*
 * Instruction barrier
 */
	.macro	instr_sync
#if __LINUX_ARM_ARCH__ >= 7
	isb
#elif __LINUX_ARM_ARCH__ == 6
	mcr	p15, 0, r0, c7, c5, 4
#endif
	.endm

/*
 * SMP data memory barrier
 */
	.macro	smp_dmb mode
#ifdef CONFIG_SMP
#if __LINUX_ARM_ARCH__ >= 7
	.ifeqs "\mode","arm"
	ALT_SMP(dmb	ish)
	.else
	ALT_SMP(W(dmb)	ish)
	.endif
#elif __LINUX_ARM_ARCH__ == 6
	ALT_SMP(mcr	p15, 0, r0, c7, c10, 5)	@ dmb
#else
#error Incompatible SMP platform
#endif
	.ifeqs "\mode","arm"
	ALT_UP(nop)
	.else
	ALT_UP(W(nop))
	.endif
#endif
	.endm

/*
 * Raw SMP data memory barrier
 */
	.macro	__smp_dmb mode
#if __LINUX_ARM_ARCH__ >= 7
	.ifeqs "\mode","arm"
	dmb	ish
	.else
	W(dmb)	ish
	.endif
#elif __LINUX_ARM_ARCH__ == 6
	mcr	p15, 0, r0, c7, c10, 5	@ dmb
#else
	.error "Incompatible SMP platform"
#endif
	.endm

#if defined(CONFIG_CPU_V7M)
	/*
	 * setmode is used to assert to be in svc mode during boot. For v7-M
	 * this is done in __v7m_setup, so setmode can be empty here.
	 */
	.macro	setmode, mode, reg
	.endm
#elif defined(CONFIG_THUMB2_KERNEL)
	.macro	setmode, mode, reg
	mov	\reg, #\mode
	msr	cpsr_c, \reg
	.endm
#else
	.macro	setmode, mode, reg
	msr	cpsr_c, #\mode
	.endm
#endif

/*
 * Helper macro to enter SVC mode cleanly and mask interrupts. reg is
 * a scratch register for the macro to overwrite.
 *
 * This macro is intended for forcing the CPU into SVC mode at boot time.
 * you cannot return to the original mode.
 */
.macro safe_svcmode_maskall reg:req
#if __LINUX_ARM_ARCH__ >= 6 && !defined(CONFIG_CPU_V7M)
	mrs	\reg , cpsr
	eor	\reg, \reg, #HYP_MODE
	tst	\reg, #MODE_MASK
	bic	\reg , \reg , #MODE_MASK
	orr	\reg , \reg , #PSR_I_BIT | PSR_F_BIT | SVC_MODE
THUMB(	orr	\reg , \reg , #PSR_T_BIT	)
	bne	1f
	orr	\reg, \reg, #PSR_A_BIT
	badr	lr, 2f
	msr	spsr_cxsf, \reg
	__MSR_ELR_HYP(14)
	__ERET
1:	msr	cpsr_c, \reg
2:
#else
/*
 * workaround for possibly broken pre-v6 hardware
 * (akita, Sharp Zaurus C-1000, PXA270-based)
 */
	setmode	PSR_F_BIT | PSR_I_BIT | SVC_MODE, \reg
#endif
.endm

/*
 * STRT/LDRT access macros with ARM and Thumb-2 variants
 */
#ifdef CONFIG_THUMB2_KERNEL

	.macro	usraccoff, instr, reg, ptr, inc, off, cond, abort, t=TUSER()
9999:
	.if	\inc == 1
	\instr\()b\t\cond\().w \reg, [\ptr, #\off]
	.elseif	\inc == 4
	\instr\t\cond\().w \reg, [\ptr, #\off]
	.else
	.error	"Unsupported inc macro argument"
	.endif

	.pushsection __ex_table,"a"
	.align	3
	.long	9999b, \abort
	.popsection
	.endm

	.macro	usracc, instr, reg, ptr, inc, cond, rept, abort
	@ explicit IT instruction needed because of the label
	@ introduced by the USER macro
	.ifnc	\cond,al
	.if	\rept == 1
	itt	\cond
	.elseif	\rept == 2
	ittt	\cond
	.else
	.error	"Unsupported rept macro argument"
	.endif
	.endif

	@ Slightly optimised to avoid incrementing the pointer twice
	usraccoff \instr, \reg, \ptr, \inc, 0, \cond, \abort
	.if	\rept == 2
	usraccoff \instr, \reg, \ptr, \inc, \inc, \cond, \abort
	.endif

	add\cond \ptr, #\rept * \inc
	.endm

#else	/* !CONFIG_THUMB2_KERNEL */

	.macro	usracc, instr, reg, ptr, inc, cond, rept, abort, t=TUSER()
	.rept	\rept
9999:
	.if	\inc == 1
	\instr\()b\t\cond \reg, [\ptr], #\inc
	.elseif	\inc == 4
	\instr\t\cond \reg, [\ptr], #\inc
	.else
	.error	"Unsupported inc macro argument"
	.endif

	.pushsection __ex_table,"a"
	.align	3
	.long	9999b, \abort
	.popsection
	.endr
	.endm

#endif	/* CONFIG_THUMB2_KERNEL */

	.macro	strusr, reg, ptr, inc, cond=al, rept=1, abort=9001f
	usracc	str, \reg, \ptr, \inc, \cond, \rept, \abort
	.endm

	.macro	ldrusr, reg, ptr, inc, cond=al, rept=1, abort=9001f
	usracc	ldr, \reg, \ptr, \inc, \cond, \rept, \abort
	.endm

/* Utility macro for declaring string literals */
	.macro	string name:req, string
	.type \name , #object
\name:
	.asciz "\string"
	.size \name , . - \name
	.endm

	.irp	c,,eq,ne,cs,cc,mi,pl,vs,vc,hi,ls,ge,lt,gt,le,hs,lo
	.macro	ret\c, reg
#if __LINUX_ARM_ARCH__ < 6
	mov\c	pc, \reg
#else
	.ifeqs	"\reg", "lr"
	bx\c	\reg
	.else
	mov\c	pc, \reg
	.endif
#endif
	.endm
	.endr

	.macro	ret.w, reg
	ret	\reg
#ifdef CONFIG_THUMB2_KERNEL
	nop
#endif
	.endm

	.macro	bug, msg, line
#ifdef CONFIG_THUMB2_KERNEL
1:	.inst	0xde02
#else
1:	.inst	0xe7f001f2
#endif
#ifdef CONFIG_DEBUG_BUGVERBOSE
	.pushsection .rodata.str, "aMS", %progbits, 1
2:	.asciz	"\msg"
	.popsection
	.pushsection __bug_table, "aw"
	.align	2
	.word	1b, 2b
	.hword	\line
	.popsection
#endif
	.endm

#ifdef CONFIG_KPROBES
#define _ASM_NOKPROBE(entry)				\
	.pushsection "_kprobe_blacklist", "aw" ;	\
	.balign 4 ;					\
	.long entry;					\
	.popsection
#else
#define _ASM_NOKPROBE(entry)
#endif

	.macro		__adldst_l, op, reg, sym, tmp, c
	.if		__LINUX_ARM_ARCH__ < 7
	ldr\c		\tmp, .La\@
	.subsection	1
	.align		2
.La\@:	.long		\sym - .Lpc\@
	.previous
	.else
	.ifnb		\c
 THUMB(	ittt		\c			)
	.endif
	movw\c		\tmp, #:lower16:\sym - .Lpc\@
	movt\c		\tmp, #:upper16:\sym - .Lpc\@
	.endif

#ifndef CONFIG_THUMB2_KERNEL
	.set		.Lpc\@, . + 8			// PC bias
	.ifc		\op, add
	add\c		\reg, \tmp, pc
	.else
	\op\c		\reg, [pc, \tmp]
	.endif
#else
.Lb\@:	add\c		\tmp, \tmp, pc
	/*
	 * In Thumb-2 builds, the PC bias depends on whether we are currently
	 * emitting into a .arm or a .thumb section. The size of the add opcode
	 * above will be 2 bytes when emitting in Thumb mode and 4 bytes when
	 * emitting in ARM mode, so let's use this to account for the bias.
	 */
	.set		.Lpc\@, . + (. - .Lb\@)

	.ifnc		\op, add
	\op\c		\reg, [\tmp]
	.endif
#endif
	.endm

	/*
	 * mov_l - move a constant value or [relocated] address into a register
	 */
	.macro		mov_l, dst:req, imm:req, cond
	.if		__LINUX_ARM_ARCH__ < 7
	ldr\cond	\dst, =\imm
	.else
	movw\cond	\dst, #:lower16:\imm
	movt\cond	\dst, #:upper16:\imm
	.endif
	.endm

	/*
	 * adr_l - adr pseudo-op with unlimited range
	 *
	 * @dst: destination register
	 * @sym: name of the symbol
	 * @cond: conditional opcode suffix
	 */
	.macro		adr_l, dst:req, sym:req, cond
	__adldst_l	add, \dst, \sym, \dst, \cond
	.endm

	/*
	 * ldr_l - ldr <literal> pseudo-op with unlimited range
	 *
	 * @dst: destination register
	 * @sym: name of the symbol
	 * @cond: conditional opcode suffix
	 */
	.macro		ldr_l, dst:req, sym:req, cond
	__adldst_l	ldr, \dst, \sym, \dst, \cond
	.endm

	/*
	 * str_l - str <literal> pseudo-op with unlimited range
	 *
	 * @src: source register
	 * @sym: name of the symbol
	 * @tmp: mandatory scratch register
	 * @cond: conditional opcode suffix
	 */
	.macro		str_l, src:req, sym:req, tmp:req, cond
	__adldst_l	str, \src, \sym, \tmp, \cond
	.endm

	.macro		__ldst_va, op, reg, tmp, sym, cond, offset
#if __LINUX_ARM_ARCH__ >= 7 || \
    !defined(CONFIG_ARM_HAS_GROUP_RELOCS) || \
    (defined(MODULE) && defined(CONFIG_ARM_MODULE_PLTS))
	mov_l		\tmp, \sym, \cond
#else
	/*
	 * Avoid a literal load, by emitting a sequence of ADD/LDR instructions
	 * with the appropriate relocations. The combined sequence has a range
	 * of -/+ 256 MiB, which should be sufficient for the core kernel and
	 * for modules loaded into the module region.
	 */
	.globl		\sym
	.reloc		.L0_\@, R_ARM_ALU_PC_G0_NC, \sym
	.reloc		.L1_\@, R_ARM_ALU_PC_G1_NC, \sym
	.reloc		.L2_\@, R_ARM_LDR_PC_G2, \sym
.L0_\@: sub\cond	\tmp, pc, #8 - \offset
.L1_\@: sub\cond	\tmp, \tmp, #4 - \offset
.L2_\@:
#endif
	\op\cond	\reg, [\tmp, #\offset]
	.endm

	/*
	 * ldr_va - load a 32-bit word from the virtual address of \sym
	 */
	.macro		ldr_va, rd:req, sym:req, cond, tmp, offset=0
	.ifnb		\tmp
	__ldst_va	ldr, \rd, \tmp, \sym, \cond, \offset
	.else
	__ldst_va	ldr, \rd, \rd, \sym, \cond, \offset
	.endif
	.endm

	/*
	 * str_va - store a 32-bit word to the virtual address of \sym
	 */
	.macro		str_va, rn:req, sym:req, tmp:req, cond
	__ldst_va	str, \rn, \tmp, \sym, \cond, 0
	.endm

	/*
	 * ldr_this_cpu_armv6 - Load a 32-bit word from the per-CPU variable 'sym',
	 *			without using a temp register. Supported in ARM mode
	 *			only.
	 */
	.macro		ldr_this_cpu_armv6, rd:req, sym:req
	this_cpu_offset	\rd
	.globl		\sym
	.reloc		.L0_\@, R_ARM_ALU_PC_G0_NC, \sym
	.reloc		.L1_\@, R_ARM_ALU_PC_G1_NC, \sym
	.reloc		.L2_\@, R_ARM_LDR_PC_G2, \sym
	add		\rd, \rd, pc
.L0_\@: sub		\rd, \rd, #4
.L1_\@: sub		\rd, \rd, #0
.L2_\@: ldr		\rd, [\rd, #4]
	.endm

	/*
	 * ldr_this_cpu - Load a 32-bit word from the per-CPU variable 'sym'
	 *		  into register 'rd', which may be the stack pointer,
	 *		  using 't1' and 't2' as general temp registers. These
	 *		  are permitted to overlap with 'rd' if != sp
	 */
	.macro		ldr_this_cpu, rd:req, sym:req, t1:req, t2:req
#ifndef CONFIG_SMP
	ldr_va		\rd, \sym, tmp=\t1
#elif __LINUX_ARM_ARCH__ >= 7 || \
      !defined(CONFIG_ARM_HAS_GROUP_RELOCS) || \
      (defined(MODULE) && defined(CONFIG_ARM_MODULE_PLTS))
	this_cpu_offset	\t1
	mov_l		\t2, \sym
	ldr		\rd, [\t1, \t2]
#else
	ldr_this_cpu_armv6 \rd, \sym
#endif
	.endm

	/*
	 * rev_l - byte-swap a 32-bit value
	 *
	 * @val: source/destination register
	 * @tmp: scratch register
	 */
	.macro		rev_l, val:req, tmp:req
	.if		__LINUX_ARM_ARCH__ < 6
	eor		\tmp, \val, \val, ror #16
	bic		\tmp, \tmp, #0x00ff0000
	mov		\val, \val, ror #8
	eor		\val, \val, \tmp, lsr #8
	.else
	rev		\val, \val
	.endif
	.endm

	/*
	 * bl_r - branch and link to register
	 *
	 * @dst: target to branch to
	 * @c: conditional opcode suffix
	 */
	.macro		bl_r, dst:req, c
	.if		__LINUX_ARM_ARCH__ < 6
	mov\c		lr, pc
	mov\c		pc, \dst
	.else
	blx\c		\dst
	.endif
	.endm

#endif /* __ASM_ASSEMBLER_H__ */
