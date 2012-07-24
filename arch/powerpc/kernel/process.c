/*
 *  Derived from "arch/i386/kernel/process.c"
 *    Copyright (C) 1995  Linus Torvalds
 *
 *  Updated and modified by Cort Dougan (cort@cs.nmt.edu) and
 *  Paul Mackerras (paulus@cs.anu.edu.au)
 *
 *  PowerPC version
 *    Copyright (C) 1995-1996 Gary Thomas (gdt@linuxppc.org)
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 */

#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/user.h>
#include <linux/elf.h>
#include <linux/prctl.h>
#include <linux/init_task.h>
#include <linux/export.h>
#include <linux/kallsyms.h>
#include <linux/mqueue.h>
#include <linux/hardirq.h>
#include <linux/utsname.h>
#include <linux/ftrace.h>
#include <linux/kernel_stat.h>
#include <linux/personality.h>
#include <linux/random.h>
#include <linux/hw_breakpoint.h>
#include <linux/uaccess.h>
#include <linux/elf-randomize.h>
#include <generated/package.h>

#include <asm/pgtable.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/mmu.h>
#include <asm/prom.h>
#include <asm/machdep.h>
#include <asm/time.h>
#include <asm/runlatch.h>
#include <asm/syscalls.h>
#include <asm/switch_to.h>
#include <asm/tm.h>
#include <asm/debug.h>
#ifdef CONFIG_PPC64
#include <asm/firmware.h>
#endif
#include <asm/code-patching.h>
#include <asm/exec.h>
#include <asm/livepatch.h>
#include <asm/cpu_has_feature.h>
#include <asm/asm-prototypes.h>

#include <linux/kprobes.h>
#include <linux/kdebug.h>

/* Transactional Memory debug */
#ifdef TM_DEBUG_SW
#define TM_DEBUG(x...) printk(KERN_INFO x)
#else
#define TM_DEBUG(x...) do { } while(0)
#endif

extern unsigned long _get_SP(void);

#ifdef CONFIG_PPC_TRANSACTIONAL_MEM
static void check_if_tm_restore_required(struct task_struct *tsk)
{
	/*
	 * If we are saving the current thread's registers, and the
	 * thread is in a transactional state, set the TIF_RESTORE_TM
	 * bit so that we know to restore the registers before
	 * returning to userspace.
	 */
	if (tsk == current && tsk->thread.regs &&
	    MSR_TM_ACTIVE(tsk->thread.regs->msr) &&
	    !test_thread_flag(TIF_RESTORE_TM)) {
		tsk->thread.ckpt_regs.msr = tsk->thread.regs->msr;
		set_thread_flag(TIF_RESTORE_TM);
	}
}

static inline bool msr_tm_active(unsigned long msr)
{
	return MSR_TM_ACTIVE(msr);
}
#else
static inline bool msr_tm_active(unsigned long msr) { return false; }
static inline void check_if_tm_restore_required(struct task_struct *tsk) { }
#endif /* CONFIG_PPC_TRANSACTIONAL_MEM */

bool strict_msr_control;
EXPORT_SYMBOL(strict_msr_control);

static int __init enable_strict_msr_control(char *str)
{
	strict_msr_control = true;
	pr_info("Enabling strict facility control\n");

	return 0;
}
early_param("ppc_strict_facility_enable", enable_strict_msr_control);

unsigned long msr_check_and_set(unsigned long bits)
{
	unsigned long oldmsr = mfmsr();
	unsigned long newmsr;

	newmsr = oldmsr | bits;

#ifdef CONFIG_VSX
	if (cpu_has_feature(CPU_FTR_VSX) && (bits & MSR_FP))
		newmsr |= MSR_VSX;
#endif

	if (oldmsr != newmsr)
		mtmsr_isync(newmsr);

	return newmsr;
}

void __msr_check_and_clear(unsigned long bits)
{
	unsigned long oldmsr = mfmsr();
	unsigned long newmsr;

	newmsr = oldmsr & ~bits;

#ifdef CONFIG_VSX
	if (cpu_has_feature(CPU_FTR_VSX) && (bits & MSR_FP))
		newmsr &= ~MSR_VSX;
#endif

	if (oldmsr != newmsr)
		mtmsr_isync(newmsr);
}
EXPORT_SYMBOL(__msr_check_and_clear);

#ifdef CONFIG_PPC_FPU
void __giveup_fpu(struct task_struct *tsk)
{
	unsigned long msr;

	save_fpu(tsk);
	msr = tsk->thread.regs->msr;
	msr &= ~MSR_FP;
#ifdef CONFIG_VSX
	if (cpu_has_feature(CPU_FTR_VSX))
		msr &= ~MSR_VSX;
#endif
	tsk->thread.regs->msr = msr;
}

void giveup_fpu(struct task_struct *tsk)
{
	check_if_tm_restore_required(tsk);

	msr_check_and_set(MSR_FP);
	__giveup_fpu(tsk);
	msr_check_and_clear(MSR_FP);
}
EXPORT_SYMBOL(giveup_fpu);

/*
 * Make sure the floating-point register state in the
 * the thread_struct is up to date for task tsk.
 */
void flush_fp_to_thread(struct task_struct *tsk)
{
	if (tsk->thread.regs) {
		/*
		 * We need to disable preemption here because if we didn't,
		 * another process could get scheduled after the regs->msr
		 * test but before we have finished saving the FP registers
		 * to the thread_struct.  That process could take over the
		 * FPU, and then when we get scheduled again we would store
		 * bogus values for the remaining FP registers.
		 */
		preempt_disable();
		if (tsk->thread.regs->msr & MSR_FP) {
			/*
			 * This should only ever be called for current or
			 * for a stopped child process.  Since we save away
			 * the FP register state on context switch,
			 * there is something wrong if a stopped child appears
			 * to still have its FP state in the CPU registers.
			 */
			BUG_ON(tsk != current);
			giveup_fpu(tsk);
		}
		preempt_enable();
	}
}
EXPORT_SYMBOL_GPL(flush_fp_to_thread);

void enable_kernel_fp(void)
{
	unsigned long cpumsr;

	WARN_ON(preemptible());

	cpumsr = msr_check_and_set(MSR_FP);

	if (current->thread.regs && (current->thread.regs->msr & MSR_FP)) {
		check_if_tm_restore_required(current);
		/*
		 * If a thread has already been reclaimed then the
		 * checkpointed registers are on the CPU but have definitely
		 * been saved by the reclaim code. Don't need to and *cannot*
		 * giveup as this would save  to the 'live' structure not the
		 * checkpointed structure.
		 */
		if(!msr_tm_active(cpumsr) && msr_tm_active(current->thread.regs->msr))
			return;
		__giveup_fpu(current);
	}
}
EXPORT_SYMBOL(enable_kernel_fp);

static int restore_fp(struct task_struct *tsk) {
	if (tsk->thread.load_fp || msr_tm_active(tsk->thread.regs->msr)) {
		load_fp_state(&current->thread.fp_state);
		current->thread.load_fp++;
		return 1;
	}
	return 0;
}
#else
static int restore_fp(struct task_struct *tsk) { return 0; }
#endif /* CONFIG_PPC_FPU */

#ifdef CONFIG_ALTIVEC
#define loadvec(thr) ((thr).load_vec)

static void __giveup_altivec(struct task_struct *tsk)
{
	unsigned long msr;

	save_altivec(tsk);
	msr = tsk->thread.regs->msr;
	msr &= ~MSR_VEC;
#ifdef CONFIG_VSX
	if (cpu_has_feature(CPU_FTR_VSX))
		msr &= ~MSR_VSX;
#endif
	tsk->thread.regs->msr = msr;
}

void giveup_altivec(struct task_struct *tsk)
{
	check_if_tm_restore_required(tsk);

	msr_check_and_set(MSR_VEC);
	__giveup_altivec(tsk);
	msr_check_and_clear(MSR_VEC);
}
EXPORT_SYMBOL(giveup_altivec);

void enable_kernel_altivec(void)
{
	unsigned long cpumsr;

	WARN_ON(preemptible());

	cpumsr = msr_check_and_set(MSR_VEC);

	if (current->thread.regs && (current->thread.regs->msr & MSR_VEC)) {
		check_if_tm_restore_required(current);
		/*
		 * If a thread has already been reclaimed then the
		 * checkpointed registers are on the CPU but have definitely
		 * been saved by the reclaim code. Don't need to and *cannot*
		 * giveup as this would save  to the 'live' structure not the
		 * checkpointed structure.
		 */
		if(!msr_tm_active(cpumsr) && msr_tm_active(current->thread.regs->msr))
			return;
		__giveup_altivec(current);
	}
}
EXPORT_SYMBOL(enable_kernel_altivec);

/*
 * Make sure the VMX/Altivec register state in the
 * the thread_struct is up to date for task tsk.
 */
void flush_altivec_to_thread(struct task_struct *tsk)
{
	if (tsk->thread.regs) {
		preempt_disable();
		if (tsk->thread.regs->msr & MSR_VEC) {
			BUG_ON(tsk != current);
			giveup_altivec(tsk);
		}
		preempt_enable();
	}
}
EXPORT_SYMBOL_GPL(flush_altivec_to_thread);

static int restore_altivec(struct task_struct *tsk)
{
	if (cpu_has_feature(CPU_FTR_ALTIVEC) &&
		(tsk->thread.load_vec || msr_tm_active(tsk->thread.regs->msr))) {
		load_vr_state(&tsk->thread.vr_state);
		tsk->thread.used_vr = 1;
		tsk->thread.load_vec++;

		return 1;
	}
	return 0;
}
#else
#define loadvec(thr) 0
static inline int restore_altivec(struct task_struct *tsk) { return 0; }
#endif /* CONFIG_ALTIVEC */

#ifdef CONFIG_VSX
static void __giveup_vsx(struct task_struct *tsk)
{
	if (tsk->thread.regs->msr & MSR_FP)
		__giveup_fpu(tsk);
	if (tsk->thread.regs->msr & MSR_VEC)
		__giveup_altivec(tsk);
	tsk->thread.regs->msr &= ~MSR_VSX;
}

static void giveup_vsx(struct task_struct *tsk)
{
	check_if_tm_restore_required(tsk);

	msr_check_and_set(MSR_FP|MSR_VEC|MSR_VSX);
	__giveup_vsx(tsk);
	msr_check_and_clear(MSR_FP|MSR_VEC|MSR_VSX);
}

static void save_vsx(struct task_struct *tsk)
{
	if (tsk->thread.regs->msr & MSR_FP)
		save_fpu(tsk);
	if (tsk->thread.regs->msr & MSR_VEC)
		save_altivec(tsk);
}

void enable_kernel_vsx(void)
{
	unsigned long cpumsr;

	WARN_ON(preemptible());

	cpumsr = msr_check_and_set(MSR_FP|MSR_VEC|MSR_VSX);

	if (current->thread.regs &&
	    (current->thread.regs->msr & (MSR_VSX|MSR_VEC|MSR_FP))) {
		check_if_tm_restore_required(current);
		/*
		 * If a thread has already been reclaimed then the
		 * checkpointed registers are on the CPU but have definitely
		 * been saved by the reclaim code. Don't need to and *cannot*
		 * giveup as this would save  to the 'live' structure not the
		 * checkpointed structure.
		 */
		if(!msr_tm_active(cpumsr) && msr_tm_active(current->thread.regs->msr))
			return;
		if (current->thread.regs->msr & MSR_FP)
			__giveup_fpu(current);
		if (current->thread.regs->msr & MSR_VEC)
			__giveup_altivec(current);
		__giveup_vsx(current);
	}
}
EXPORT_SYMBOL(enable_kernel_vsx);

void flush_vsx_to_thread(struct task_struct *tsk)
{
	if (tsk->thread.regs) {
		preempt_disable();
		if (tsk->thread.regs->msr & (MSR_VSX|MSR_VEC|MSR_FP)) {
			BUG_ON(tsk != current);
			giveup_vsx(tsk);
		}
		preempt_enable();
	}
}
EXPORT_SYMBOL_GPL(flush_vsx_to_thread);

static int restore_vsx(struct task_struct *tsk)
{
	if (cpu_has_feature(CPU_FTR_VSX)) {
		tsk->thread.used_vsr = 1;
		return 1;
	}

	return 0;
}
#else
static inline int restore_vsx(struct task_struct *tsk) { return 0; }
static inline void save_vsx(struct task_struct *tsk) { }
#endif /* CONFIG_VSX */

#ifdef CONFIG_SPE
void giveup_spe(struct task_struct *tsk)
{
	check_if_tm_restore_required(tsk);

	msr_check_and_set(MSR_SPE);
	__giveup_spe(tsk);
	msr_check_and_clear(MSR_SPE);
}
EXPORT_SYMBOL(giveup_spe);

void enable_kernel_spe(void)
{
	WARN_ON(preemptible());

	msr_check_and_set(MSR_SPE);

	if (current->thread.regs && (current->thread.regs->msr & MSR_SPE)) {
		check_if_tm_restore_required(current);
		__giveup_spe(current);
	}
}
EXPORT_SYMBOL(enable_kernel_spe);

void flush_spe_to_thread(struct task_struct *tsk)
{
	if (tsk->thread.regs) {
		preempt_disable();
		if (tsk->thread.regs->msr & MSR_SPE) {
			BUG_ON(tsk != current);
			tsk->thread.spefscr = mfspr(SPRN_SPEFSCR);
			giveup_spe(tsk);
		}
		preempt_enable();
	}
}
#endif /* CONFIG_SPE */

static unsigned long msr_all_available;

static int __init init_msr_all_available(void)
{
#ifdef CONFIG_PPC_FPU
	msr_all_available |= MSR_FP;
#endif
#ifdef CONFIG_ALTIVEC
	if (cpu_has_feature(CPU_FTR_ALTIVEC))
		msr_all_available |= MSR_VEC;
#endif
#ifdef CONFIG_VSX
	if (cpu_has_feature(CPU_FTR_VSX))
		msr_all_available |= MSR_VSX;
#endif
#ifdef CONFIG_SPE
	if (cpu_has_feature(CPU_FTR_SPE))
		msr_all_available |= MSR_SPE;
#endif

	return 0;
}
early_initcall(init_msr_all_available);

void giveup_all(struct task_struct *tsk)
{
	unsigned long usermsr;

	if (!tsk->thread.regs)
		return;

	usermsr = tsk->thread.regs->msr;

	if ((usermsr & msr_all_available) == 0)
		return;

	msr_check_and_set(msr_all_available);
	check_if_tm_restore_required(tsk);

#ifdef CONFIG_PPC_FPU
	if (usermsr & MSR_FP)
		__giveup_fpu(tsk);
#endif
#ifdef CONFIG_ALTIVEC
	if (usermsr & MSR_VEC)
		__giveup_altivec(tsk);
#endif
#ifdef CONFIG_VSX
	if (usermsr & MSR_VSX)
		__giveup_vsx(tsk);
#endif
#ifdef CONFIG_SPE
	if (usermsr & MSR_SPE)
		__giveup_spe(tsk);
#endif

	msr_check_and_clear(msr_all_available);
}
EXPORT_SYMBOL(giveup_all);

void restore_math(struct pt_regs *regs)
{
	unsigned long msr;

	if (!msr_tm_active(regs->msr) &&
		!current->thread.load_fp && !loadvec(current->thread))
		return;

	msr = regs->msr;
	msr_check_and_set(msr_all_available);

	/*
	 * Only reload if the bit is not set in the user MSR, the bit BEING set
	 * indicates that the registers are hot
	 */
	if ((!(msr & MSR_FP)) && restore_fp(current))
		msr |= MSR_FP | current->thread.fpexc_mode;

	if ((!(msr & MSR_VEC)) && restore_altivec(current))
		msr |= MSR_VEC;

	if ((msr & (MSR_FP | MSR_VEC)) == (MSR_FP | MSR_VEC) &&
			restore_vsx(current)) {
		msr |= MSR_VSX;
	}

	msr_check_and_clear(msr_all_available);

	regs->msr = msr;
}

void save_all(struct task_struct *tsk)
{
	unsigned long usermsr;

	if (!tsk->thread.regs)
		return;

	usermsr = tsk->thread.regs->msr;

	if ((usermsr & msr_all_available) == 0)
		return;

	msr_check_and_set(msr_all_available);

	/*
	 * Saving the way the register space is in hardware, save_vsx boils
	 * down to a save_fpu() and save_altivec()
	 */
	if (usermsr & MSR_VSX) {
		save_vsx(tsk);
	} else {
		if (usermsr & MSR_FP)
			save_fpu(tsk);

		if (usermsr & MSR_VEC)
			save_altivec(tsk);
	}

	if (usermsr & MSR_SPE)
		__giveup_spe(tsk);

	msr_check_and_clear(msr_all_available);
}

void flush_all_to_thread(struct task_struct *tsk)
{
	if (tsk->thread.regs) {
		preempt_disable();
		BUG_ON(tsk != current);
		save_all(tsk);

#ifdef CONFIG_SPE
		if (tsk->thread.regs->msr & MSR_SPE)
			tsk->thread.spefscr = mfspr(SPRN_SPEFSCR);
#endif

		preempt_enable();
	}
}
EXPORT_SYMBOL(flush_all_to_thread);

#ifdef CONFIG_PPC_ADV_DEBUG_REGS
void do_send_trap(struct pt_regs *regs, unsigned long address,
		  unsigned long error_code, int signal_code, int breakpt)
{
	siginfo_t info;

	current->thread.trap_nr = signal_code;
	if (notify_die(DIE_DABR_MATCH, "dabr_match", regs, error_code,
			11, SIGSEGV) == NOTIFY_STOP)
		return;

	/* Deliver the signal to userspace */
	info.si_signo = SIGTRAP;
	info.si_errno = breakpt;	/* breakpoint or watchpoint id */
	info.si_code = signal_code;
	info.si_addr = (void __user *)address;
	force_sig_info(SIGTRAP, &info, current);
}
#else	/* !CONFIG_PPC_ADV_DEBUG_REGS */
void do_break (struct pt_regs *regs, unsigned long address,
		    unsigned long error_code)
{
	siginfo_t info;

	current->thread.trap_nr = TRAP_HWBKPT;
	if (notify_die(DIE_DABR_MATCH, "dabr_match", regs, error_code,
			11, SIGSEGV) == NOTIFY_STOP)
		return;

	if (debugger_break_match(regs))
		return;

	/* Clear the breakpoint */
	hw_breakpoint_disable();

	/* Deliver the signal to userspace */
	info.si_signo = SIGTRAP;
	info.si_errno = 0;
	info.si_code = TRAP_HWBKPT;
	info.si_addr = (void __user *)address;
	force_sig_info(SIGTRAP, &info, current);
}
#endif	/* CONFIG_PPC_ADV_DEBUG_REGS */

static DEFINE_PER_CPU(struct arch_hw_breakpoint, current_brk);

#ifdef CONFIG_PPC_ADV_DEBUG_REGS
/*
 * Set the debug registers back to their default "safe" values.
 */
static void set_debug_reg_defaults(struct thread_struct *thread)
{
	thread->debug.iac1 = thread->debug.iac2 = 0;
#if CONFIG_PPC_ADV_DEBUG_IACS > 2
	thread->debug.iac3 = thread->debug.iac4 = 0;
#endif
	thread->debug.dac1 = thread->debug.dac2 = 0;
#if CONFIG_PPC_ADV_DEBUG_DVCS > 0
	thread->debug.dvc1 = thread->debug.dvc2 = 0;
#endif
	thread->debug.dbcr0 = 0;
#ifdef CONFIG_BOOKE
	/*
	 * Force User/Supervisor bits to b11 (user-only MSR[PR]=1)
	 */
	thread->debug.dbcr1 = DBCR1_IAC1US | DBCR1_IAC2US |
			DBCR1_IAC3US | DBCR1_IAC4US;
	/*
	 * Force Data Address Compare User/Supervisor bits to be User-only
	 * (0b11 MSR[PR]=1) and set all other bits in DBCR2 register to be 0.
	 */
	thread->debug.dbcr2 = DBCR2_DAC1US | DBCR2_DAC2US;
#else
	thread->debug.dbcr1 = 0;
#endif
}

static void prime_debug_regs(struct debug_reg *debug)
{
	/*
	 * We could have inherited MSR_DE from userspace, since
	 * it doesn't get cleared on exception entry.  Make sure
	 * MSR_DE is clear before we enable any debug events.
	 */
	mtmsr(mfmsr() & ~MSR_DE);

	mtspr(SPRN_IAC1, debug->iac1);
	mtspr(SPRN_IAC2, debug->iac2);
#if CONFIG_PPC_ADV_DEBUG_IACS > 2
	mtspr(SPRN_IAC3, debug->iac3);
	mtspr(SPRN_IAC4, debug->iac4);
#endif
	mtspr(SPRN_DAC1, debug->dac1);
	mtspr(SPRN_DAC2, debug->dac2);
#if CONFIG_PPC_ADV_DEBUG_DVCS > 0
	mtspr(SPRN_DVC1, debug->dvc1);
	mtspr(SPRN_DVC2, debug->dvc2);
#endif
	mtspr(SPRN_DBCR0, debug->dbcr0);
	mtspr(SPRN_DBCR1, debug->dbcr1);
#ifdef CONFIG_BOOKE
	mtspr(SPRN_DBCR2, debug->dbcr2);
#endif
}
/*
 * Unless neither the old or new thread are making use of the
 * debug registers, set the debug registers from the values
 * stored in the new thread.
 */
void switch_booke_debug_regs(struct debug_reg *new_debug)
{
	if ((current->thread.debug.dbcr0 & DBCR0_IDM)
		|| (new_debug->dbcr0 & DBCR0_IDM))
			prime_debug_regs(new_debug);
}
EXPORT_SYMBOL_GPL(switch_booke_debug_regs);
#else	/* !CONFIG_PPC_ADV_DEBUG_REGS */
#ifndef CONFIG_HAVE_HW_BREAKPOINT
static void set_debug_reg_defaults(struct thread_struct *thread)
{
	thread->hw_brk.address = 0;
	thread->hw_brk.type = 0;
	set_breakpoint(&thread->hw_brk);
}
#endif /* !CONFIG_HAVE_HW_BREAKPOINT */
#endif	/* CONFIG_PPC_ADV_DEBUG_REGS */

#ifdef CONFIG_PPC_ADV_DEBUG_REGS
static inline int __set_dabr(unsigned long dabr, unsigned long dabrx)
{
	mtspr(SPRN_DAC1, dabr);
#ifdef CONFIG_PPC_47x
	isync();
#endif
	return 0;
}
#elif defined(CONFIG_PPC_BOOK3S)
static inline int __set_dabr(unsigned long dabr, unsigned long dabrx)
{
	mtspr(SPRN_DABR, dabr);
	if (cpu_has_feature(CPU_FTR_DABRX))
		mtspr(SPRN_DABRX, dabrx);
	return 0;
}
#else
static inline int __set_dabr(unsigned long dabr, unsigned long dabrx)
{
	return -EINVAL;
}
#endif

static inline int set_dabr(struct arch_hw_breakpoint *brk)
{
	unsigned long dabr, dabrx;

	dabr = brk->address | (brk->type & HW_BRK_TYPE_DABR);
	dabrx = ((brk->type >> 3) & 0x7);

	if (ppc_md.set_dabr)
		return ppc_md.set_dabr(dabr, dabrx);

	return __set_dabr(dabr, dabrx);
}

static inline int set_dawr(struct arch_hw_breakpoint *brk)
{
	unsigned long dawr, dawrx, mrd;

	dawr = brk->address;

	dawrx  = (brk->type & (HW_BRK_TYPE_READ | HW_BRK_TYPE_WRITE)) \
		                   << (63 - 58); //* read/write bits */
	dawrx |= ((brk->type & (HW_BRK_TYPE_TRANSLATE)) >> 2) \
		                   << (63 - 59); //* translate */
	dawrx |= (brk->type & (HW_BRK_TYPE_PRIV_ALL)) \
		                   >> 3; //* PRIM bits */
	/* dawr length is stored in field MDR bits 48:53.  Matches range in
	   doublewords (64 bits) baised by -1 eg. 0b000000=1DW and
	   0b111111=64DW.
	   brk->len is in bytes.
	   This aligns up to double word size, shifts and does the bias.
	*/
	mrd = ((brk->len + 7) >> 3) - 1;
	dawrx |= (mrd & 0x3f) << (63 - 53);

	if (ppc_md.set_dawr)
		return ppc_md.set_dawr(dawr, dawrx);
	mtspr(SPRN_DAWR, dawr);
	mtspr(SPRN_DAWRX, dawrx);
	return 0;
}

void __set_breakpoint(struct arch_hw_breakpoint *brk)
{
	memcpy(this_cpu_ptr(&current_brk), brk, sizeof(*brk));

	if (cpu_has_feature(CPU_FTR_DAWR))
		set_dawr(brk);
	else
		set_dabr(brk);
}

void set_breakpoint(struct arch_hw_breakpoint *brk)
{
	preempt_disable();
	__set_breakpoint(brk);
	preempt_enable();
}

#ifdef CONFIG_PPC64
DEFINE_PER_CPU(struct cpu_usage, cpu_usage_array);
#endif

static inline bool hw_brk_match(struct arch_hw_breakpoint *a,
			      struct arch_hw_breakpoint *b)
{
	if (a->address != b->address)
		return false;
	if (a->type != b->type)
		return false;
	if (a->len != b->len)
		return false;
	return true;
}

#ifdef CONFIG_PPC_TRANSACTIONAL_MEM

static inline bool tm_enabled(struct task_struct *tsk)
{
	return tsk && tsk->thread.regs && (tsk->thread.regs->msr & MSR_TM);
}

static void tm_reclaim_thread(struct thread_struct *thr,
			      struct thread_info *ti, uint8_t cause)
{
	/*
	 * Use the current MSR TM suspended bit to track if we have
	 * checkpointed state outstanding.
	 * On signal delivery, we'd normally reclaim the checkpointed
	 * state to obtain stack pointer (see:get_tm_stackpointer()).
	 * This will then directly return to userspace without going
	 * through __switch_to(). However, if the stack frame is bad,
	 * we need to exit this thread which calls __switch_to() which
	 * will again attempt to reclaim the already saved tm state.
	 * Hence we need to check that we've not already reclaimed
	 * this state.
	 * We do this using the current MSR, rather tracking it in
	 * some specific thread_struct bit, as it has the additional
	 * benefit of checking for a potential TM bad thing exception.
	 */
	if (!MSR_TM_SUSPENDED(mfmsr()))
		return;

	/*
	 * If we are in a transaction and FP is off then we can't have
	 * used FP inside that transaction. Hence the checkpointed
	 * state is the same as the live state. We need to copy the
	 * live state to the checkpointed state so that when the
	 * transaction is restored, the checkpointed state is correct
	 * and the aborted transaction sees the correct state. We use
	 * ckpt_regs.msr here as that's what tm_reclaim will use to
	 * determine if it's going to write the checkpointed state or
	 * not. So either this will write the checkpointed registers,
	 * or reclaim will. Similarly for VMX.
	 */
	if ((thr->ckpt_regs.msr & MSR_FP) == 0)
		memcpy(&thr->ckfp_state, &thr->fp_state,
		       sizeof(struct thread_fp_state));
	if ((thr->ckpt_regs.msr & MSR_VEC) == 0)
		memcpy(&thr->ckvr_state, &thr->vr_state,
		       sizeof(struct thread_vr_state));

	giveup_all(container_of(thr, struct task_struct, thread));

	tm_reclaim(thr, thr->ckpt_regs.msr, cause);
}

void tm_reclaim_current(uint8_t cause)
{
	tm_enable();
	tm_reclaim_thread(&current->thread, current_thread_info(), cause);
}

static inline void tm_reclaim_task(struct task_struct *tsk)
{
	/* We have to work out if we're switching from/to a task that's in the
	 * middle of a transaction.
	 *
	 * In switching we need to maintain a 2nd register state as
	 * oldtask->thread.ckpt_regs.  We tm_reclaim(oldproc); this saves the
	 * checkpointed (tbegin) state in ckpt_regs, ckfp_state and
	 * ckvr_state
	 *
	 * We also context switch (save) TFHAR/TEXASR/TFIAR in here.
	 */
	struct thread_struct *thr = &tsk->thread;

	if (!thr->regs)
		return;

	if (!MSR_TM_ACTIVE(thr->regs->msr))
		goto out_and_saveregs;

	TM_DEBUG("--- tm_reclaim on pid %d (NIP=%lx, "
		 "ccr=%lx, msr=%lx, trap=%lx)\n",
		 tsk->pid, thr->regs->nip,
		 thr->regs->ccr, thr->regs->msr,
		 thr->regs->trap);

	tm_reclaim_thread(thr, task_thread_info(tsk), TM_CAUSE_RESCHED);

	TM_DEBUG("--- tm_reclaim on pid %d complete\n",
		 tsk->pid);

out_and_saveregs:
	/* Always save the regs here, even if a transaction's not active.
	 * This context-switches a thread's TM info SPRs.  We do it here to
	 * be consistent with the restore path (in recheckpoint) which
	 * cannot happen later in _switch().
	 */
	tm_save_sprs(thr);
}

extern void __tm_recheckpoint(struct thread_struct *thread,
			      unsigned long orig_msr);

void tm_recheckpoint(struct thread_struct *thread,
		     unsigned long orig_msr)
{
	unsigned long flags;

	if (!(thread->regs->msr & MSR_TM))
		return;

	/* We really can't be interrupted here as the TEXASR registers can't
	 * change and later in the trecheckpoint code, we have a userspace R1.
	 * So let's hard disable over this region.
	 */
	local_irq_save(flags);
	hard_irq_disable();

	/* The TM SPRs are restored here, so that TEXASR.FS can be set
	 * before the trecheckpoint and no explosion occurs.
	 */
	tm_restore_sprs(thread);

	__tm_recheckpoint(thread, orig_msr);

	local_irq_restore(flags);
}

static inline void tm_recheckpoint_new_task(struct task_struct *new)
{
	unsigned long msr;

	if (!cpu_has_feature(CPU_FTR_TM))
		return;

	/* Recheckpoint the registers of the thread we're about to switch to.
	 *
	 * If the task was using FP, we non-lazily reload both the original and
	 * the speculative FP register states.  This is because the kernel
	 * doesn't see if/when a TM rollback occurs, so if we take an FP
	 * unavailable later, we are unable to determine which set of FP regs
	 * need to be restored.
	 */
	if (!tm_enabled(new))
		return;

	if (!MSR_TM_ACTIVE(new->thread.regs->msr)){
		tm_restore_sprs(&new->thread);
		return;
	}
	msr = new->thread.ckpt_regs.msr;
	/* Recheckpoint to restore original checkpointed register state. */
	TM_DEBUG("*** tm_recheckpoint of pid %d "
		 "(new->msr 0x%lx, new->origmsr 0x%lx)\n",
		 new->pid, new->thread.regs->msr, msr);

	tm_recheckpoint(&new->thread, msr);

	/*
	 * The checkpointed state has been restored but the live state has
	 * not, ensure all the math functionality is turned off to trigger
	 * restore_math() to reload.
	 */
	new->thread.regs->msr &= ~(MSR_FP | MSR_VEC | MSR_VSX);

	TM_DEBUG("*** tm_recheckpoint of pid %d complete "
		 "(kernel msr 0x%lx)\n",
		 new->pid, mfmsr());
}

static inline void __switch_to_tm(struct task_struct *prev,
		struct task_struct *new)
{
	if (cpu_has_feature(CPU_FTR_TM)) {
		if (tm_enabled(prev) || tm_enabled(new))
			tm_enable();

		if (tm_enabled(prev)) {
			prev->thread.load_tm++;
			tm_reclaim_task(prev);
			if (!MSR_TM_ACTIVE(prev->thread.regs->msr) && prev->thread.load_tm == 0)
				prev->thread.regs->msr &= ~MSR_TM;
		}

		tm_recheckpoint_new_task(new);
	}
}

/*
 * This is called if we are on the way out to userspace and the
 * TIF_RESTORE_TM flag is set.  It checks if we need to reload
 * FP and/or vector state and does so if necessary.
 * If userspace is inside a transaction (whether active or
 * suspended) and FP/VMX/VSX instructions have ever been enabled
 * inside that transaction, then we have to keep them enabled
 * and keep the FP/VMX/VSX state loaded while ever the transaction
 * continues.  The reason is that if we didn't, and subsequently
 * got a FP/VMX/VSX unavailable interrupt inside a transaction,
 * we don't know whether it's the same transaction, and thus we
 * don't know which of the checkpointed state and the transactional
 * state to use.
 */
void restore_tm_state(struct pt_regs *regs)
{
	unsigned long msr_diff;

	/*
	 * This is the only moment we should clear TIF_RESTORE_TM as
	 * it is here that ckpt_regs.msr and pt_regs.msr become the same
	 * again, anything else could lead to an incorrect ckpt_msr being
	 * saved and therefore incorrect signal contexts.
	 */
	clear_thread_flag(TIF_RESTORE_TM);
	if (!MSR_TM_ACTIVE(regs->msr))
		return;

	msr_diff = current->thread.ckpt_regs.msr & ~regs->msr;
	msr_diff &= MSR_FP | MSR_VEC | MSR_VSX;

	/* Ensure that restore_math() will restore */
	if (msr_diff & MSR_FP)
		current->thread.load_fp = 1;
#ifdef CONFIG_ALTIVEC
	if (cpu_has_feature(CPU_FTR_ALTIVEC) && msr_diff & MSR_VEC)
		current->thread.load_vec = 1;
#endif
	restore_math(regs);

	regs->msr |= msr_diff;
}

#else
#define tm_recheckpoint_new_task(new)
#define __switch_to_tm(prev, new)
#endif /* CONFIG_PPC_TRANSACTIONAL_MEM */

static inline void save_sprs(struct thread_struct *t)
{
#ifdef CONFIG_ALTIVEC
	if (cpu_has_feature(CPU_FTR_ALTIVEC))
		t->vrsave = mfspr(SPRN_VRSAVE);
#endif
#ifdef CONFIG_PPC_BOOK3S_64
	if (cpu_has_feature(CPU_FTR_DSCR))
		t->dscr = mfspr(SPRN_DSCR);

	if (cpu_has_feature(CPU_FTR_ARCH_207S)) {
		t->bescr = mfspr(SPRN_BESCR);
		t->ebbhr = mfspr(SPRN_EBBHR);
		t->ebbrr = mfspr(SPRN_EBBRR);

		t->fscr = mfspr(SPRN_FSCR);

		/*
		 * Note that the TAR is not available for use in the kernel.
		 * (To provide this, the TAR should be backed up/restored on
		 * exception entry/exit instead, and be in pt_regs.  FIXME,
		 * this should be in pt_regs anyway (for debug).)
		 */
		t->tar = mfspr(SPRN_TAR);
	}

	if (cpu_has_feature(CPU_FTR_ARCH_300)) {
		/* Conditionally save Load Monitor registers, if enabled */
		if (t->fscr & FSCR_LM) {
			t->lmrr = mfspr(SPRN_LMRR);
			t->lmser = mfspr(SPRN_LMSER);
		}
	}
#endif
}

static inline void restore_sprs(struct thread_struct *old_thread,
				struct thread_struct *new_thread)
{
#ifdef CONFIG_ALTIVEC
	if (cpu_has_feature(CPU_FTR_ALTIVEC) &&
	    old_thread->vrsave != new_thread->vrsave)
		mtspr(SPRN_VRSAVE, new_thread->vrsave);
#endif
#ifdef CONFIG_PPC_BOOK3S_64
	if (cpu_has_feature(CPU_FTR_DSCR)) {
		u64 dscr = get_paca()->dscr_default;
		if (new_thread->dscr_inherit)
			dscr = new_thread->dscr;

		if (old_thread->dscr != dscr)
			mtspr(SPRN_DSCR, dscr);
	}

	if (cpu_has_feature(CPU_FTR_ARCH_207S)) {
		if (old_thread->bescr != new_thread->bescr)
			mtspr(SPRN_BESCR, new_thread->bescr);
		if (old_thread->ebbhr != new_thread->ebbhr)
			mtspr(SPRN_EBBHR, new_thread->ebbhr);
		if (old_thread->ebbrr != new_thread->ebbrr)
			mtspr(SPRN_EBBRR, new_thread->ebbrr);

		if (old_thread->fscr != new_thread->fscr)
			mtspr(SPRN_FSCR, new_thread->fscr);

		if (old_thread->tar != new_thread->tar)
			mtspr(SPRN_TAR, new_thread->tar);
	}

	if (cpu_has_feature(CPU_FTR_ARCH_300)) {
		/* Conditionally restore Load Monitor registers, if enabled */
		if (new_thread->fscr & FSCR_LM) {
			if (old_thread->lmrr != new_thread->lmrr)
				mtspr(SPRN_LMRR, new_thread->lmrr);
			if (old_thread->lmser != new_thread->lmser)
				mtspr(SPRN_LMSER, new_thread->lmser);
		}
	}
#endif
}

struct task_struct *__switch_to(struct task_struct *prev,
	struct task_struct *new)
{
	struct thread_struct *new_thread, *old_thread;
	struct task_struct *last;
#ifdef CONFIG_PPC_BOOK3S_64
	struct ppc64_tlb_batch *batch;
#endif

	new_thread = &new->thread;
	old_thread = &current->thread;

	WARN_ON(!irqs_disabled());

#ifdef CONFIG_PPC64
	/*
	 * Collect processor utilization data per process
	 */
	if (firmware_has_feature(FW_FEATURE_SPLPAR)) {
		struct cpu_usage *cu = this_cpu_ptr(&cpu_usage_array);
		long unsigned start_tb, current_tb;
		start_tb = old_thread->start_tb;
		cu->current_tb = current_tb = mfspr(SPRN_PURR);
		old_thread->accum_tb += (current_tb - start_tb);
		new_thread->start_tb = current_tb;
	}
#endif /* CONFIG_PPC64 */

#ifdef CONFIG_PPC_STD_MMU_64
	batch = this_cpu_ptr(&ppc64_tlb_batch);
	if (batch->active) {
		current_thread_info()->local_flags |= _TLF_LAZY_MMU;
		if (batch->index)
			__flush_tlb_pending(batch);
		batch->active = 0;
	}
#endif /* CONFIG_PPC_STD_MMU_64 */

#ifdef CONFIG_PPC_ADV_DEBUG_REGS
	switch_booke_debug_regs(&new->thread.debug);
#else
/*
 * For PPC_BOOK3S_64, we use the hw-breakpoint interfaces that would
 * schedule DABR
 */
#ifndef CONFIG_HAVE_HW_BREAKPOINT
	if (unlikely(!hw_brk_match(this_cpu_ptr(&current_brk), &new->thread.hw_brk)))
		__set_breakpoint(&new->thread.hw_brk);
#endif /* CONFIG_HAVE_HW_BREAKPOINT */
#endif

	/*
	 * We need to save SPRs before treclaim/trecheckpoint as these will
	 * change a number of them.
	 */
	save_sprs(&prev->thread);

	/* Save FPU, Altivec, VSX and SPE state */
	giveup_all(prev);

	__switch_to_tm(prev, new);

	/*
	 * We can't take a PMU exception inside _switch() since there is a
	 * window where the kernel stack SLB and the kernel stack are out
	 * of sync. Hard disable here.
	 */
	hard_irq_disable();

	/*
	 * Call restore_sprs() before calling _switch(). If we move it after
	 * _switch() then we miss out on calling it for new tasks. The reason
	 * for this is we manually create a stack frame for new tasks that
	 * directly returns through ret_from_fork() or
	 * ret_from_kernel_thread(). See copy_thread() for details.
	 */
	restore_sprs(old_thread, new_thread);

	last = _switch(old_thread, new_thread);

#ifdef CONFIG_PPC_STD_MMU_64
	if (current_thread_info()->local_flags & _TLF_LAZY_MMU) {
		current_thread_info()->local_flags &= ~_TLF_LAZY_MMU;
		batch = this_cpu_ptr(&ppc64_tlb_batch);
		batch->active = 1;
	}

	if (current_thread_info()->task->thread.regs)
		restore_math(current_thread_info()->task->thread.regs);
#endif /* CONFIG_PPC_STD_MMU_64 */

	return last;
}

static int instructions_to_print = 16;

static void show_instructions(struct pt_regs *regs)
{
	int i;
	unsigned long pc = regs->nip - (instructions_to_print * 3 / 4 *
			sizeof(int));

	printk("Instruction dump:");

	for (i = 0; i < instructions_to_print; i++) {
		int instr;

		if (!(i % 8))
			pr_cont("\n");

#if !defined(CONFIG_BOOKE)
		/* If executing with the IMMU off, adjust pc rather
		 * than print XXXXXXXX.
		 */
		if (!(regs->msr & MSR_IR))
			pc = (unsigned long)phys_to_virt(pc);
#endif

		if (!__kernel_text_address(pc) ||
		     probe_kernel_address((unsigned int __user *)pc, instr)) {
			pr_cont("XXXXXXXX ");
		} else {
			if (regs->nip == pc)
				pr_cont("<%08x> ", instr);
			else
				pr_cont("%08x ", instr);
		}

		pc += sizeof(int);
	}

	pr_cont("\n");
}

struct regbit {
	unsigned long bit;
	const char *name;
};

static struct regbit msr_bits[] = {
#if defined(CONFIG_PPC64) && !defined(CONFIG_BOOKE)
	{MSR_SF,	"SF"},
	{MSR_HV,	"HV"},
#endif
	{MSR_VEC,	"VEC"},
	{MSR_VSX,	"VSX"},
#ifdef CONFIG_BOOKE
	{MSR_CE,	"CE"},
#endif
	{MSR_EE,	"EE"},
	{MSR_PR,	"PR"},
	{MSR_FP,	"FP"},
	{MSR_ME,	"ME"},
#ifdef CONFIG_BOOKE
	{MSR_DE,	"DE"},
#else
	{MSR_SE,	"SE"},
	{MSR_BE,	"BE"},
#endif
	{MSR_IR,	"IR"},
	{MSR_DR,	"DR"},
	{MSR_PMM,	"PMM"},
#ifndef CONFIG_BOOKE
	{MSR_RI,	"RI"},
	{MSR_LE,	"LE"},
#endif
	{0,		NULL}
};

static void print_bits(unsigned long val, struct regbit *bits, const char *sep)
{
	const char *s = "";

	for (; bits->bit; ++bits)
		if (val & bits->bit) {
			pr_cont("%s%s", s, bits->name);
			s = sep;
		}
}

#ifdef CONFIG_PPC_TRANSACTIONAL_MEM
static struct regbit msr_tm_bits[] = {
	{MSR_TS_T,	"T"},
	{MSR_TS_S,	"S"},
	{MSR_TM,	"E"},
	{0,		NULL}
};

static void print_tm_bits(unsigned long val)
{
/*
 * This only prints something if at least one of the TM bit is set.
 * Inside the TM[], the output means:
 *   E: Enabled		(bit 32)
 *   S: Suspended	(bit 33)
 *   T: Transactional	(bit 34)
 */
	if (val & (MSR_TM | MSR_TS_S | MSR_TS_T)) {
		pr_cont(",TM[");
		print_bits(val, msr_tm_bits, "");
		pr_cont("]");
	}
}
#else
static void print_tm_bits(unsigned long val) {}
#endif

static void print_msr_bits(unsigned long val)
{
	pr_cont("<");
	print_bits(val, msr_bits, ",");
	print_tm_bits(val);
	pr_cont(">");
}

#ifdef CONFIG_PPC64
#define REG		"%016lx"
#define REGS_PER_LINE	4
#define LAST_VOLATILE	13
#else
#define REG		"%08lx"
#define REGS_PER_LINE	8
#define LAST_VOLATILE	12
#endif

void show_regs(struct pt_regs * regs)
{
	int i, trap;

	show_regs_print_info(KERN_DEFAULT);

	printk("NIP: "REG" LR: "REG" CTR: "REG"\n",
	       regs->nip, regs->link, regs->ctr);
	printk("REGS: %p TRAP: %04lx   %s  (%s%s)\n",
	       regs, regs->trap, print_tainted(), init_utsname()->release,
	       LINUX_PACKAGE_ID);
	printk("MSR: "REG" ", regs->msr);
	print_msr_bits(regs->msr);
	printk("  CR: %08lx  XER: %08lx\n", regs->ccr, regs->xer);
	trap = TRAP(regs);
	if ((regs->trap != 0xc00) && cpu_has_feature(CPU_FTR_CFAR))
		pr_cont("CFAR: "REG" ", regs->orig_gpr3);
	if (trap == 0x200 || trap == 0x300 || trap == 0x600)
#if defined(CONFIG_4xx) || defined(CONFIG_BOOKE)
		pr_cont("DEAR: "REG" ESR: "REG" ", regs->dar, regs->dsisr);
#else
		pr_cont("DAR: "REG" DSISR: %08lx ", regs->dar, regs->dsisr);
#endif
#ifdef CONFIG_PPC64
	pr_cont("SOFTE: %ld ", regs->softe);
#endif
#ifdef CONFIG_PPC_TRANSACTIONAL_MEM
	if (MSR_TM_ACTIVE(regs->msr))
		pr_cont("\nPACATMSCRATCH: %016llx ", get_paca()->tm_scratch);
#endif

	for (i = 0;  i < 32;  i++) {
		if ((i % REGS_PER_LINE) == 0)
			pr_cont("\nGPR%02d: ", i);
		pr_cont(REG " ", regs->gpr[i]);
		if (i == LAST_VOLATILE && !FULL_REGS(regs))
			break;
	}
	pr_cont("\n");
#ifdef CONFIG_KALLSYMS
	/*
	 * Lookup NIP late so we have the best change of getting the
	 * above info out without failing
	 */
	printk("NIP ["REG"] %pS\n", regs->nip, (void *)regs->nip);
	printk("LR ["REG"] %pS\n", regs->link, (void *)regs->link);
#endif
	show_stack(current, (unsigned long *) regs->gpr[1]);
	if (!user_mode(regs))
		show_instructions(regs);
}

void flush_thread(void)
{
#ifdef CONFIG_HAVE_HW_BREAKPOINT
	flush_ptrace_hw_breakpoint(current);
#else /* CONFIG_HAVE_HW_BREAKPOINT */
	set_debug_reg_defaults(&current->thread);
#endif /* CONFIG_HAVE_HW_BREAKPOINT */
}

void
release_thread(struct task_struct *t)
{
}

/*
 * this gets called so that we can store coprocessor state into memory and
 * copy the current task into the new thread.
 */
int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src)
{
	flush_all_to_thread(src);
	/*
	 * Flush TM state out so we can copy it.  __switch_to_tm() does this
	 * flush but it removes the checkpointed state from the current CPU and
	 * transitions the CPU out of TM mode.  Hence we need to call
	 * tm_recheckpoint_new_task() (on the same task) to restore the
	 * checkpointed state back and the TM mode.
	 *
	 * Can't pass dst because it isn't ready. Doesn't matter, passing
	 * dst is only important for __switch_to()
	 */
	__switch_to_tm(src, src);

	*dst = *src;

	clear_task_ebb(dst);

	return 0;
}

static void setup_ksp_vsid(struct task_struct *p, unsigned long sp)
{
#ifdef CONFIG_PPC_STD_MMU_64
	unsigned long sp_vsid;
	unsigned long llp = mmu_psize_defs[mmu_linear_psize].sllp;

	if (radix_enabled())
		return;

	if (mmu_has_feature(MMU_FTR_1T_SEGMENT))
		sp_vsid = get_kernel_vsid(sp, MMU_SEGSIZE_1T)
			<< SLB_VSID_SHIFT_1T;
	else
		sp_vsid = get_kernel_vsid(sp, MMU_SEGSIZE_256M)
			<< SLB_VSID_SHIFT;
	sp_vsid |= SLB_VSID_KERNEL | llp;
	p->thread.ksp_vsid = sp_vsid;
#endif
}

/*
 * Copy a thread..
 */

/*
 * Copy architecture-specific thread state
 */
int copy_thread(unsigned long clone_flags, unsigned long usp,
		unsigned long kthread_arg, struct task_struct *p)
{
	struct pt_regs *childregs, *kregs;
	extern void ret_from_fork(void);
	extern void ret_from_kernel_thread(void);
	void (*f)(void);
	unsigned long sp = (unsigned long)task_stack_page(p) + THREAD_SIZE;
	struct thread_info *ti = task_thread_info(p);

	klp_init_thread_info(ti);

	/* Copy registers */
	sp -= sizeof(struct pt_regs);
	childregs = (struct pt_regs *) sp;
	if (unlikely(p->flags & PF_KTHREAD)) {
		/* kernel thread */
		memset(childregs, 0, sizeof(struct pt_regs));
		childregs->gpr[1] = sp + sizeof(struct pt_regs);
		/* function */
		if (usp)
			childregs->gpr[14] = ppc_function_entry((void *)usp);
#ifdef CONFIG_PPC64
		clear_tsk_thread_flag(p, TIF_32BIT);
		childregs->softe = 1;
#endif
		childregs->gpr[15] = kthread_arg;
		p->thread.regs = NULL;	/* no user register state */
		ti->flags |= _TIF_RESTOREALL;
		f = ret_from_kernel_thread;
	} else {
		/* user thread */
		struct pt_regs *regs = current_pt_regs();
		CHECK_FULL_REGS(regs);
		*childregs = *regs;
		if (usp)
			childregs->gpr[1] = usp;
		p->thread.regs = childregs;
		childregs->gpr[3] = 0;  /* Result from fork() */
		if (clone_flags & CLONE_SETTLS) {
#ifdef CONFIG_PPC64
			if (!is_32bit_task())
				childregs->gpr[13] = childregs->gpr[6];
			else
#endif
				childregs->gpr[2] = childregs->gpr[6];
		}

		f = ret_from_fork;
	}
	childregs->msr &= ~(MSR_FP|MSR_VEC|MSR_VSX);
	sp -= STACK_FRAME_OVERHEAD;

	/*
	 * The way this works is that at some point in the future
	 * some task will call _switch to switch to the new task.
	 * That will pop off the stack frame created below and start
	 * the new task running at ret_from_fork.  The new task will
	 * do some house keeping and then return from the fork or clone
	 * system call, using the stack frame created above.
	 */
	((unsigned long *)sp)[0] = 0;
	sp -= sizeof(struct pt_regs);
	kregs = (struct pt_regs *) sp;
	sp -= STACK_FRAME_OVERHEAD;
	p->thread.ksp = sp;
#ifdef CONFIG_PPC32
	p->thread.ksp_limit = (unsigned long)task_stack_page(p) +
				_ALIGN_UP(sizeof(struct thread_info), 16);
#endif
#ifdef CONFIG_HAVE_HW_BREAKPOINT
	p->thread.ptrace_bps[0] = NULL;
#endif

	p->thread.fp_save_area = NULL;
#ifdef CONFIG_ALTIVEC
	p->thread.vr_save_area = NULL;
#endif

	setup_ksp_vsid(p, sp);

#ifdef CONFIG_PPC64 
	if (cpu_has_feature(CPU_FTR_DSCR)) {
		p->thread.dscr_inherit = current->thread.dscr_inherit;
		p->thread.dscr = mfspr(SPRN_DSCR);
	}
	if (cpu_has_feature(CPU_FTR_HAS_PPR))
		p->thread.ppr = INIT_PPR;
#endif
	kregs->nip = ppc_function_entry(f);
	return 0;
}

/*
 * Set up a thread for executing a new program
 */
void start_thread(struct pt_regs *regs, unsigned long start, unsigned long sp)
{
#ifdef CONFIG_PPC64
	unsigned long load_addr = regs->gpr[2];	/* saved by ELF_PLAT_INIT */
#endif

	/*
	 * If we exec out of a kernel thread then thread.regs will not be
	 * set.  Do it now.
	 */
	if (!current->thread.regs) {
		struct pt_regs *regs = task_stack_page(current) + THREAD_SIZE;
		current->thread.regs = regs - 1;
	}

#ifdef CONFIG_PPC_TRANSACTIONAL_MEM
	/*
	 * Clear any transactional state, we're exec()ing. The cause is
	 * not important as there will never be a recheckpoint so it's not
	 * user visible.
	 */
	if (MSR_TM_SUSPENDED(mfmsr()))
		tm_reclaim_current(0);
#endif

	memset(regs->gpr, 0, sizeof(regs->gpr));
	regs->ctr = 0;
	regs->link = 0;
	regs->xer = 0;
	regs->ccr = 0;
	regs->gpr[1] = sp;

	/*
	 * We have just cleared all the nonvolatile GPRs, so make
	 * FULL_REGS(regs) return true.  This is necessary to allow
	 * ptrace to examine the thread immediately after exec.
	 */
	regs->trap &= ~1UL;

#ifdef CONFIG_PPC32
	regs->mq = 0;
	regs->nip = start;
	regs->msr = MSR_USER;
#else
	if (!is_32bit_task()) {
		unsigned long entry;

		if (is_elf2_task()) {
			/* Look ma, no function descriptors! */
			entry = start;

			/*
			 * Ulrich says:
			 *   The latest iteration of the ABI requires that when
			 *   calling a function (at its global entry point),
			 *   the caller must ensure r12 holds the entry point
			 *   address (so that the function can quickly
			 *   establish addressability).
			 */
			regs->gpr[12] = start;
			/* Make sure that's restored on entry to userspace. */
			set_thread_flag(TIF_RESTOREALL);
		} else {
			unsigned long toc;

			/* start is a relocated pointer to the function
			 * descriptor for the elf _start routine.  The first
			 * entry in the function descriptor is the entry
			 * address of _start and the second entry is the TOC
			 * value we need to use.
			 */
			__get_user(entry, (unsigned long __user *)start);
			__get_user(toc, (unsigned long __user *)start+1);

			/* Check whether the e_entry function descriptor entries
			 * need to be relocated before we can use them.
			 */
			if (load_addr != 0) {
				entry += load_addr;
				toc   += load_addr;
			}
			regs->gpr[2] = toc;
		}
		regs->nip = entry;
		regs->msr = MSR_USER64;
	} else {
		regs->nip = start;
		regs->gpr[2] = 0;
		regs->msr = MSR_USER32;
	}
#endif
#ifdef CONFIG_VSX
	current->thread.used_vsr = 0;
#endif
	current->thread.load_fp = 0;
	memset(&current->thread.fp_state, 0, sizeof(current->thread.fp_state));
	current->thread.fp_save_area = NULL;
#ifdef CONFIG_ALTIVEC
	memset(&current->thread.vr_state, 0, sizeof(current->thread.vr_state));
	current->thread.vr_state.vscr.u[3] = 0x00010000; /* Java mode disabled */
	current->thread.vr_save_area = NULL;
	current->thread.vrsave = 0;
	current->thread.used_vr = 0;
	current->thread.load_vec = 0;
#endif /* CONFIG_ALTIVEC */
#ifdef CONFIG_SPE
	memset(current->thread.evr, 0, sizeof(current->thread.evr));
	current->thread.acc = 0;
	current->thread.spefscr = 0;
	current->thread.used_spe = 0;
#endif /* CONFIG_SPE */
#ifdef CONFIG_PPC_TRANSACTIONAL_MEM
	current->thread.tm_tfhar = 0;
	current->thread.tm_texasr = 0;
	current->thread.tm_tfiar = 0;
	current->thread.load_tm = 0;
#endif /* CONFIG_PPC_TRANSACTIONAL_MEM */
}
EXPORT_SYMBOL(start_thread);

#define PR_FP_ALL_EXCEPT (PR_FP_EXC_DIV | PR_FP_EXC_OVF | PR_FP_EXC_UND \
		| PR_FP_EXC_RES | PR_FP_EXC_INV)

int set_fpexc_mode(struct task_struct *tsk, unsigned int val)
{
	struct pt_regs *regs = tsk->thread.regs;

	/* This is a bit hairy.  If we are an SPE enabled  processor
	 * (have embedded fp) we store the IEEE exception enable flags in
	 * fpexc_mode.  fpexc_mode is also used for setting FP exception
	 * mode (asyn, precise, disabled) for 'Classic' FP. */
	if (val & PR_FP_EXC_SW_ENABLE) {
#ifdef CONFIG_SPE
		if (cpu_has_feature(CPU_FTR_SPE)) {
			/*
			 * When the sticky exception bits are set
			 * directly by userspace, it must call prctl
			 * with PR_GET_FPEXC (with PR_FP_EXC_SW_ENABLE
			 * in the existing prctl settings) or
			 * PR_SET_FPEXC (with PR_FP_EXC_SW_ENABLE in
			 * the bits being set).  <fenv.h> functions
			 * saving and restoring the whole
			 * floating-point environment need to do so
			 * anyway to restore the prctl settings from
			 * the saved environment.
			 */
			tsk->thread.spefscr_last = mfspr(SPRN_SPEFSCR);
			tsk->thread.fpexc_mode = val &
				(PR_FP_EXC_SW_ENABLE | PR_FP_ALL_EXCEPT);
			return 0;
		} else {
			return -EINVAL;
		}
#else
		return -EINVAL;
#endif
	}

	/* on a CONFIG_SPE this does not hurt us.  The bits that
	 * __pack_fe01 use do not overlap with bits used for
	 * PR_FP_EXC_SW_ENABLE.  Additionally, the MSR[FE0,FE1] bits
	 * on CONFIG_SPE implementations are reserved so writing to
	 * them does not change anything */
	if (val > PR_FP_EXC_PRECISE)
		return -EINVAL;
	tsk->thread.fpexc_mode = __pack_fe01(val);
	if (regs != NULL && (regs->msr & MSR_FP) != 0)
		regs->msr = (regs->msr & ~(MSR_FE0|MSR_FE1))
			| tsk->thread.fpexc_mode;
	return 0;
}

int get_fpexc_mode(struct task_struct *tsk, unsigned long adr)
{
	unsigned int val;

	if (tsk->thread.fpexc_mode & PR_FP_EXC_SW_ENABLE)
#ifdef CONFIG_SPE
		if (cpu_has_feature(CPU_FTR_SPE)) {
			/*
			 * When the sticky exception bits are set
			 * directly by userspace, it must call prctl
			 * with PR_GET_FPEXC (with PR_FP_EXC_SW_ENABLE
			 * in the existing prctl settings) or
			 * PR_SET_FPEXC (with PR_FP_EXC_SW_ENABLE in
			 * the bits being set).  <fenv.h> functions
			 * saving and restoring the whole
			 * floating-point environment need to do so
			 * anyway to restore the prctl settings from
			 * the saved environment.
			 */
			tsk->thread.spefscr_last = mfspr(SPRN_SPEFSCR);
			val = tsk->thread.fpexc_mode;
		} else
			return -EINVAL;
#else
		return -EINVAL;
#endif
	else
		val = __unpack_fe01(tsk->thread.fpexc_mode);
	return put_user(val, (unsigned int __user *) adr);
}

int set_endian(struct task_struct *tsk, unsigned int val)
{
	struct pt_regs *regs = tsk->thread.regs;

	if ((val == PR_ENDIAN_LITTLE && !cpu_has_feature(CPU_FTR_REAL_LE)) ||
	    (val == PR_ENDIAN_PPC_LITTLE && !cpu_has_feature(CPU_FTR_PPC_LE)))
		return -EINVAL;

	if (regs == NULL)
		return -EINVAL;

	if (val == PR_ENDIAN_BIG)
		regs->msr &= ~MSR_LE;
	else if (val == PR_ENDIAN_LITTLE || val == PR_ENDIAN_PPC_LITTLE)
		regs->msr |= MSR_LE;
	else
		return -EINVAL;

	return 0;
}

int get_endian(struct task_struct *tsk, unsigned long adr)
{
	struct pt_regs *regs = tsk->thread.regs;
	unsigned int val;

	if (!cpu_has_feature(CPU_FTR_PPC_LE) &&
	    !cpu_has_feature(CPU_FTR_REAL_LE))
		return -EINVAL;

	if (regs == NULL)
		return -EINVAL;

	if (regs->msr & MSR_LE) {
		if (cpu_has_feature(CPU_FTR_REAL_LE))
			val = PR_ENDIAN_LITTLE;
		else
			val = PR_ENDIAN_PPC_LITTLE;
	} else
		val = PR_ENDIAN_BIG;

	return put_user(val, (unsigned int __user *)adr);
}

int set_unalign_ctl(struct task_struct *tsk, unsigned int val)
{
	tsk->thread.align_ctl = val;
	return 0;
}

int get_unalign_ctl(struct task_struct *tsk, unsigned long adr)
{
	return put_user(tsk->thread.align_ctl, (unsigned int __user *)adr);
}

static inline int valid_irq_stack(unsigned long sp, struct task_struct *p,
				  unsigned long nbytes)
{
	unsigned long stack_page;
	unsigned long cpu = task_cpu(p);

	/*
	 * Avoid crashing if the stack has overflowed and corrupted
	 * task_cpu(p), which is in the thread_info struct.
	 */
	if (cpu < NR_CPUS && cpu_possible(cpu)) {
		stack_page = (unsigned long) hardirq_ctx[cpu];
		if (sp >= stack_page + sizeof(struct thread_struct)
		    && sp <= stack_page + THREAD_SIZE - nbytes)
			return 1;

		stack_page = (unsigned long) softirq_ctx[cpu];
		if (sp >= stack_page + sizeof(struct thread_struct)
		    && sp <= stack_page + THREAD_SIZE - nbytes)
			return 1;
	}
	return 0;
}

int validate_sp(unsigned long sp, struct task_struct *p,
		       unsigned long nbytes)
{
	unsigned long stack_page = (unsigned long)task_stack_page(p);

	if (sp >= stack_page + sizeof(struct thread_struct)
	    && sp <= stack_page + THREAD_SIZE - nbytes)
		return 1;

	return valid_irq_stack(sp, p, nbytes);
}

EXPORT_SYMBOL(validate_sp);

unsigned long get_wchan(struct task_struct *p)
{
	unsigned long ip, sp;
	int count = 0;

	if (!p || p == current || p->state == TASK_RUNNING)
		return 0;

	sp = p->thread.ksp;
	if (!validate_sp(sp, p, STACK_FRAME_OVERHEAD))
		return 0;

	do {
		sp = *(unsigned long *)sp;
		if (!validate_sp(sp, p, STACK_FRAME_OVERHEAD))
			return 0;
		if (count > 0) {
			ip = ((unsigned long *)sp)[STACK_FRAME_LR_SAVE];
			if (!in_sched_functions(ip))
				return ip;
		}
	} while (count++ < 16);
	return 0;
}

static int kstack_depth_to_print = CONFIG_PRINT_STACK_DEPTH;

void show_stack(struct task_struct *tsk, unsigned long *stack)
{
	unsigned long sp, ip, lr, newsp;
	int count = 0;
	int firstframe = 1;
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	int curr_frame = current->curr_ret_stack;
	extern void return_to_handler(void);
	unsigned long rth = (unsigned long)return_to_handler;
#endif

	sp = (unsigned long) stack;
	if (tsk == NULL)
		tsk = current;
	if (sp == 0) {
		if (tsk == current)
			sp = current_stack_pointer();
		else
			sp = tsk->thread.ksp;
	}

	lr = 0;
	printk("Call Trace:\n");
	do {
		if (!validate_sp(sp, tsk, STACK_FRAME_OVERHEAD))
			return;

		stack = (unsigned long *) sp;
		newsp = stack[0];
		ip = stack[STACK_FRAME_LR_SAVE];
		if (!firstframe || ip != lr) {
			printk("["REG"] ["REG"] %pS", sp, ip, (void *)ip);
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
			if ((ip == rth) && curr_frame >= 0) {
				pr_cont(" (%pS)",
				       (void *)current->ret_stack[curr_frame].ret);
				curr_frame--;
			}
#endif
			if (firstframe)
				pr_cont(" (unreliable)");
			pr_cont("\n");
		}
		firstframe = 0;

		/*
		 * See if this is an exception frame.
		 * We look for the "regshere" marker in the current frame.
		 */
		if (validate_sp(sp, tsk, STACK_INT_FRAME_SIZE)
		    && stack[STACK_FRAME_MARKER] == STACK_FRAME_REGS_MARKER) {
			struct pt_regs *regs = (struct pt_regs *)
				(sp + STACK_FRAME_OVERHEAD);
			lr = regs->link;
			printk("--- interrupt: %lx at %pS\n    LR = %pS\n",
			       regs->trap, (void *)regs->nip, (void *)lr);
			firstframe = 1;
		}

		sp = newsp;
	} while (count++ < kstack_depth_to_print);
}

#ifdef CONFIG_PPC64
/* Called with hard IRQs off */
void notrace __ppc64_runlatch_on(void)
{
	struct thread_info *ti = current_thread_info();
	unsigned long ctrl;

	ctrl = mfspr(SPRN_CTRLF);
	ctrl |= CTRL_RUNLATCH;
	mtspr(SPRN_CTRLT, ctrl);

	ti->local_flags |= _TLF_RUNLATCH;
}

/* Called with hard IRQs off */
void notrace __ppc64_runlatch_off(void)
{
	struct thread_info *ti = current_thread_info();
	unsigned long ctrl;

	ti->local_flags &= ~_TLF_RUNLATCH;

	ctrl = mfspr(SPRN_CTRLF);
	ctrl &= ~CTRL_RUNLATCH;
	mtspr(SPRN_CTRLT, ctrl);
}
#endif /* CONFIG_PPC64 */

unsigned long arch_align_stack(unsigned long sp)
{
	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
		sp -= get_random_int() & ~PAGE_MASK;
	return sp & ~0xf;
}

static inline unsigned long brk_rnd(void)
{
        unsigned long rnd = 0;

	/* 8MB for 32bit, 1GB for 64bit */
	if (is_32bit_task())
		rnd = (get_random_long() % (1UL<<(23-PAGE_SHIFT)));
	else
		rnd = (get_random_long() % (1UL<<(30-PAGE_SHIFT)));

	return rnd << PAGE_SHIFT;
}

unsigned long arch_randomize_brk(struct mm_struct *mm)
{
	unsigned long base = mm->brk;
	unsigned long ret;

#ifdef CONFIG_PPC_STD_MMU_64
	/*
	 * If we are using 1TB segments and we are allowed to randomise
	 * the heap, we can put it above 1TB so it is backed by a 1TB
	 * segment. Otherwise the heap will be in the bottom 1TB
	 * which always uses 256MB segments and this may result in a
	 * performance penalty. We don't need to worry about radix. For
	 * radix, mmu_highuser_ssize remains unchanged from 256MB.
	 */
	if (!is_32bit_task() && (mmu_highuser_ssize == MMU_SEGSIZE_1T))
		base = max_t(unsigned long, mm->brk, 1UL << SID_SHIFT_1T);
#endif

	ret = PAGE_ALIGN(base + brk_rnd());

	if (ret < mm->brk)
		return mm->brk;

	return ret;
}

