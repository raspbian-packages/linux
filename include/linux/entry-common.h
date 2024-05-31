/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_ENTRYCOMMON_H
#define __LINUX_ENTRYCOMMON_H

#include <linux/static_call_types.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include <linux/seccomp.h>
#include <linux/sched.h>
#include <linux/context_tracking.h>
#include <linux/livepatch.h>
#include <linux/resume_user_mode.h>
#include <linux/tick.h>
#include <linux/kmsan.h>

#include <asm/entry-common.h>

/*
 * Define dummy _TIF work flags if not defined by the architecture or for
 * disabled functionality.
 */
#ifndef _TIF_PATCH_PENDING
# define _TIF_PATCH_PENDING		(0)
#endif

#ifndef _TIF_UPROBE
# define _TIF_UPROBE			(0)
#endif

/*
 * SYSCALL_WORK flags handled in syscall_enter_from_user_mode()
 */
#ifndef ARCH_SYSCALL_WORK_ENTER
# define ARCH_SYSCALL_WORK_ENTER	(0)
#endif

/*
 * SYSCALL_WORK flags handled in syscall_exit_to_user_mode()
 */
#ifndef ARCH_SYSCALL_WORK_EXIT
# define ARCH_SYSCALL_WORK_EXIT		(0)
#endif

#define SYSCALL_WORK_ENTER	(SYSCALL_WORK_SECCOMP |			\
				 SYSCALL_WORK_SYSCALL_TRACEPOINT |	\
				 SYSCALL_WORK_SYSCALL_TRACE |		\
				 SYSCALL_WORK_SYSCALL_EMU |		\
				 SYSCALL_WORK_SYSCALL_AUDIT |		\
				 SYSCALL_WORK_SYSCALL_USER_DISPATCH |	\
				 ARCH_SYSCALL_WORK_ENTER)
#define SYSCALL_WORK_EXIT	(SYSCALL_WORK_SYSCALL_TRACEPOINT |	\
				 SYSCALL_WORK_SYSCALL_TRACE |		\
				 SYSCALL_WORK_SYSCALL_AUDIT |		\
				 SYSCALL_WORK_SYSCALL_USER_DISPATCH |	\
				 SYSCALL_WORK_SYSCALL_EXIT_TRAP	|	\
				 ARCH_SYSCALL_WORK_EXIT)

/*
 * TIF flags handled in exit_to_user_mode_loop()
 */
#ifndef ARCH_EXIT_TO_USER_MODE_WORK
# define ARCH_EXIT_TO_USER_MODE_WORK		(0)
#endif

#define EXIT_TO_USER_MODE_WORK						\
	(_TIF_SIGPENDING | _TIF_NOTIFY_RESUME | _TIF_UPROBE |		\
	 _TIF_NEED_RESCHED | _TIF_PATCH_PENDING | _TIF_NOTIFY_SIGNAL |	\
	 ARCH_EXIT_TO_USER_MODE_WORK)

/**
 * arch_enter_from_user_mode - Architecture specific sanity check for user mode regs
 * @regs:	Pointer to currents pt_regs
 *
 * Defaults to an empty implementation. Can be replaced by architecture
 * specific code.
 *
 * Invoked from syscall_enter_from_user_mode() in the non-instrumentable
 * section. Use __always_inline so the compiler cannot push it out of line
 * and make it instrumentable.
 */
static __always_inline void arch_enter_from_user_mode(struct pt_regs *regs);

#ifndef arch_enter_from_user_mode
static __always_inline void arch_enter_from_user_mode(struct pt_regs *regs) {}
#endif

/**
 * enter_from_user_mode - Establish state when coming from user mode
 *
 * Syscall/interrupt entry disables interrupts, but user mode is traced as
 * interrupts enabled. Also with NO_HZ_FULL RCU might be idle.
 *
 * 1) Tell lockdep that interrupts are disabled
 * 2) Invoke context tracking if enabled to reactivate RCU
 * 3) Trace interrupts off state
 *
 * Invoked from architecture specific syscall entry code with interrupts
 * disabled. The calling code has to be non-instrumentable. When the
 * function returns all state is correct and interrupts are still
 * disabled. The subsequent functions can be instrumented.
 *
 * This is invoked when there is architecture specific functionality to be
 * done between establishing state and enabling interrupts. The caller must
 * enable interrupts before invoking syscall_enter_from_user_mode_work().
 */
static __always_inline void enter_from_user_mode(struct pt_regs *regs)
{
	arch_enter_from_user_mode(regs);
	lockdep_hardirqs_off(CALLER_ADDR0);

	CT_WARN_ON(__ct_state() != CONTEXT_USER);
	user_exit_irqoff();

	instrumentation_begin();
	kmsan_unpoison_entry_regs(regs);
	trace_hardirqs_off_finish();
	instrumentation_end();
}

/**
 * syscall_enter_from_user_mode_prepare - Establish state and enable interrupts
 * @regs:	Pointer to currents pt_regs
 *
 * Invoked from architecture specific syscall entry code with interrupts
 * disabled. The calling code has to be non-instrumentable. When the
 * function returns all state is correct, interrupts are enabled and the
 * subsequent functions can be instrumented.
 *
 * This handles lockdep, RCU (context tracking) and tracing state, i.e.
 * the functionality provided by enter_from_user_mode().
 *
 * This is invoked when there is extra architecture specific functionality
 * to be done between establishing state and handling user mode entry work.
 */
void syscall_enter_from_user_mode_prepare(struct pt_regs *regs);

long syscall_trace_enter(struct pt_regs *regs, long syscall,
			 unsigned long work);

/**
 * syscall_enter_from_user_mode_work - Check and handle work before invoking
 *				       a syscall
 * @regs:	Pointer to currents pt_regs
 * @syscall:	The syscall number
 *
 * Invoked from architecture specific syscall entry code with interrupts
 * enabled after invoking syscall_enter_from_user_mode_prepare() and extra
 * architecture specific work.
 *
 * Returns: The original or a modified syscall number
 *
 * If the returned syscall number is -1 then the syscall should be
 * skipped. In this case the caller may invoke syscall_set_error() or
 * syscall_set_return_value() first.  If neither of those are called and -1
 * is returned, then the syscall will fail with ENOSYS.
 *
 * It handles the following work items:
 *
 *  1) syscall_work flag dependent invocations of
 *     ptrace_report_syscall_entry(), __secure_computing(), trace_sys_enter()
 *  2) Invocation of audit_syscall_entry()
 */
static __always_inline long syscall_enter_from_user_mode_work(struct pt_regs *regs, long syscall)
{
	unsigned long work = READ_ONCE(current_thread_info()->syscall_work);

	if (work & SYSCALL_WORK_ENTER)
		syscall = syscall_trace_enter(regs, syscall, work);

	return syscall;
}

/**
 * syscall_enter_from_user_mode - Establish state and check and handle work
 *				  before invoking a syscall
 * @regs:	Pointer to currents pt_regs
 * @syscall:	The syscall number
 *
 * Invoked from architecture specific syscall entry code with interrupts
 * disabled. The calling code has to be non-instrumentable. When the
 * function returns all state is correct, interrupts are enabled and the
 * subsequent functions can be instrumented.
 *
 * This is combination of syscall_enter_from_user_mode_prepare() and
 * syscall_enter_from_user_mode_work().
 *
 * Returns: The original or a modified syscall number. See
 * syscall_enter_from_user_mode_work() for further explanation.
 */
static __always_inline long syscall_enter_from_user_mode(struct pt_regs *regs, long syscall)
{
	long ret;

	enter_from_user_mode(regs);

	instrumentation_begin();
	local_irq_enable();
	ret = syscall_enter_from_user_mode_work(regs, syscall);
	instrumentation_end();

	return ret;
}

/**
 * local_irq_enable_exit_to_user - Exit to user variant of local_irq_enable()
 * @ti_work:	Cached TIF flags gathered with interrupts disabled
 *
 * Defaults to local_irq_enable(). Can be supplied by architecture specific
 * code.
 */
static inline void local_irq_enable_exit_to_user(unsigned long ti_work);

#ifndef local_irq_enable_exit_to_user
static inline void local_irq_enable_exit_to_user(unsigned long ti_work)
{
	local_irq_enable();
}
#endif

/**
 * local_irq_disable_exit_to_user - Exit to user variant of local_irq_disable()
 *
 * Defaults to local_irq_disable(). Can be supplied by architecture specific
 * code.
 */
static inline void local_irq_disable_exit_to_user(void);

#ifndef local_irq_disable_exit_to_user
static inline void local_irq_disable_exit_to_user(void)
{
	local_irq_disable();
}
#endif

/**
 * arch_exit_to_user_mode_work - Architecture specific TIF work for exit
 *				 to user mode.
 * @regs:	Pointer to currents pt_regs
 * @ti_work:	Cached TIF flags gathered with interrupts disabled
 *
 * Invoked from exit_to_user_mode_loop() with interrupt enabled
 *
 * Defaults to NOOP. Can be supplied by architecture specific code.
 */
static inline void arch_exit_to_user_mode_work(struct pt_regs *regs,
					       unsigned long ti_work);

#ifndef arch_exit_to_user_mode_work
static inline void arch_exit_to_user_mode_work(struct pt_regs *regs,
					       unsigned long ti_work)
{
}
#endif

/**
 * arch_exit_to_user_mode_prepare - Architecture specific preparation for
 *				    exit to user mode.
 * @regs:	Pointer to currents pt_regs
 * @ti_work:	Cached TIF flags gathered with interrupts disabled
 *
 * Invoked from exit_to_user_mode_prepare() with interrupt disabled as the last
 * function before return. Defaults to NOOP.
 */
static inline void arch_exit_to_user_mode_prepare(struct pt_regs *regs,
						  unsigned long ti_work);

#ifndef arch_exit_to_user_mode_prepare
static inline void arch_exit_to_user_mode_prepare(struct pt_regs *regs,
						  unsigned long ti_work)
{
}
#endif

/**
 * arch_exit_to_user_mode - Architecture specific final work before
 *			    exit to user mode.
 *
 * Invoked from exit_to_user_mode() with interrupt disabled as the last
 * function before return. Defaults to NOOP.
 *
 * This needs to be __always_inline because it is non-instrumentable code
 * invoked after context tracking switched to user mode.
 *
 * An architecture implementation must not do anything complex, no locking
 * etc. The main purpose is for speculation mitigations.
 */
static __always_inline void arch_exit_to_user_mode(void);

#ifndef arch_exit_to_user_mode
static __always_inline void arch_exit_to_user_mode(void) { }
#endif

/**
 * arch_do_signal_or_restart -  Architecture specific signal delivery function
 * @regs:	Pointer to currents pt_regs
 *
 * Invoked from exit_to_user_mode_loop().
 */
void arch_do_signal_or_restart(struct pt_regs *regs);

/**
 * exit_to_user_mode_loop - do any pending work before leaving to user space
 */
unsigned long exit_to_user_mode_loop(struct pt_regs *regs,
				     unsigned long ti_work);

/**
 * exit_to_user_mode_prepare - call exit_to_user_mode_loop() if required
 * @regs:	Pointer to pt_regs on entry stack
 *
 * 1) check that interrupts are disabled
 * 2) call tick_nohz_user_enter_prepare()
 * 3) call exit_to_user_mode_loop() if any flags from
 *    EXIT_TO_USER_MODE_WORK are set
 * 4) check that interrupts are still disabled
 */
static __always_inline void exit_to_user_mode_prepare(struct pt_regs *regs)
{
	unsigned long ti_work;

	lockdep_assert_irqs_disabled();

	/* Flush pending rcuog wakeup before the last need_resched() check */
	tick_nohz_user_enter_prepare();

	ti_work = read_thread_flags();
	if (unlikely(ti_work & EXIT_TO_USER_MODE_WORK))
		ti_work = exit_to_user_mode_loop(regs, ti_work);

	arch_exit_to_user_mode_prepare(regs, ti_work);

	/* Ensure that kernel state is sane for a return to userspace */
	kmap_assert_nomap();
	lockdep_assert_irqs_disabled();
	lockdep_sys_exit();
}

/**
 * exit_to_user_mode - Fixup state when exiting to user mode
 *
 * Syscall/interrupt exit enables interrupts, but the kernel state is
 * interrupts disabled when this is invoked. Also tell RCU about it.
 *
 * 1) Trace interrupts on state
 * 2) Invoke context tracking if enabled to adjust RCU state
 * 3) Invoke architecture specific last minute exit code, e.g. speculation
 *    mitigations, etc.: arch_exit_to_user_mode()
 * 4) Tell lockdep that interrupts are enabled
 *
 * Invoked from architecture specific code when syscall_exit_to_user_mode()
 * is not suitable as the last step before returning to userspace. Must be
 * invoked with interrupts disabled and the caller must be
 * non-instrumentable.
 * The caller has to invoke syscall_exit_to_user_mode_work() before this.
 */
static __always_inline void exit_to_user_mode(void)
{
	instrumentation_begin();
	trace_hardirqs_on_prepare();
	lockdep_hardirqs_on_prepare();
	instrumentation_end();

	user_enter_irqoff();
	arch_exit_to_user_mode();
	lockdep_hardirqs_on(CALLER_ADDR0);
}

/**
 * syscall_exit_to_user_mode_work - Handle work before returning to user mode
 * @regs:	Pointer to currents pt_regs
 *
 * Same as step 1 and 2 of syscall_exit_to_user_mode() but without calling
 * exit_to_user_mode() to perform the final transition to user mode.
 *
 * Calling convention is the same as for syscall_exit_to_user_mode() and it
 * returns with all work handled and interrupts disabled. The caller must
 * invoke exit_to_user_mode() before actually switching to user mode to
 * make the final state transitions. Interrupts must stay disabled between
 * return from this function and the invocation of exit_to_user_mode().
 */
void syscall_exit_to_user_mode_work(struct pt_regs *regs);

/**
 * syscall_exit_to_user_mode - Handle work before returning to user mode
 * @regs:	Pointer to currents pt_regs
 *
 * Invoked with interrupts enabled and fully valid regs. Returns with all
 * work handled, interrupts disabled such that the caller can immediately
 * switch to user mode. Called from architecture specific syscall and ret
 * from fork code.
 *
 * The call order is:
 *  1) One-time syscall exit work:
 *	- rseq syscall exit
 *      - audit
 *	- syscall tracing
 *	- ptrace (single stepping)
 *
 *  2) Preparatory work
 *	- Exit to user mode loop (common TIF handling). Invokes
 *	  arch_exit_to_user_mode_work() for architecture specific TIF work
 *	- Architecture specific one time work arch_exit_to_user_mode_prepare()
 *	- Address limit and lockdep checks
 *
 *  3) Final transition (lockdep, tracing, context tracking, RCU), i.e. the
 *     functionality in exit_to_user_mode().
 *
 * This is a combination of syscall_exit_to_user_mode_work() (1,2) and
 * exit_to_user_mode(). This function is preferred unless there is a
 * compelling architectural reason to use the separate functions.
 */
void syscall_exit_to_user_mode(struct pt_regs *regs);

/**
 * irqentry_enter_from_user_mode - Establish state before invoking the irq handler
 * @regs:	Pointer to currents pt_regs
 *
 * Invoked from architecture specific entry code with interrupts disabled.
 * Can only be called when the interrupt entry came from user mode. The
 * calling code must be non-instrumentable.  When the function returns all
 * state is correct and the subsequent functions can be instrumented.
 *
 * The function establishes state (lockdep, RCU (context tracking), tracing)
 */
void irqentry_enter_from_user_mode(struct pt_regs *regs);

/**
 * irqentry_exit_to_user_mode - Interrupt exit work
 * @regs:	Pointer to current's pt_regs
 *
 * Invoked with interrupts disabled and fully valid regs. Returns with all
 * work handled, interrupts disabled such that the caller can immediately
 * switch to user mode. Called from architecture specific interrupt
 * handling code.
 *
 * The call order is #2 and #3 as described in syscall_exit_to_user_mode().
 * Interrupt exit is not invoking #1 which is the syscall specific one time
 * work.
 */
void irqentry_exit_to_user_mode(struct pt_regs *regs);

#ifndef irqentry_state
/**
 * struct irqentry_state - Opaque object for exception state storage
 * @exit_rcu: Used exclusively in the irqentry_*() calls; signals whether the
 *            exit path has to invoke ct_irq_exit().
 * @lockdep: Used exclusively in the irqentry_nmi_*() calls; ensures that
 *           lockdep state is restored correctly on exit from nmi.
 *
 * This opaque object is filled in by the irqentry_*_enter() functions and
 * must be passed back into the corresponding irqentry_*_exit() functions
 * when the exception is complete.
 *
 * Callers of irqentry_*_[enter|exit]() must consider this structure opaque
 * and all members private.  Descriptions of the members are provided to aid in
 * the maintenance of the irqentry_*() functions.
 */
typedef struct irqentry_state {
	union {
		bool	exit_rcu;
		bool	lockdep;
	};
} irqentry_state_t;
#endif

/**
 * irqentry_enter - Handle state tracking on ordinary interrupt entries
 * @regs:	Pointer to pt_regs of interrupted context
 *
 * Invokes:
 *  - lockdep irqflag state tracking as low level ASM entry disabled
 *    interrupts.
 *
 *  - Context tracking if the exception hit user mode.
 *
 *  - The hardirq tracer to keep the state consistent as low level ASM
 *    entry disabled interrupts.
 *
 * As a precondition, this requires that the entry came from user mode,
 * idle, or a kernel context in which RCU is watching.
 *
 * For kernel mode entries RCU handling is done conditional. If RCU is
 * watching then the only RCU requirement is to check whether the tick has
 * to be restarted. If RCU is not watching then ct_irq_enter() has to be
 * invoked on entry and ct_irq_exit() on exit.
 *
 * Avoiding the ct_irq_enter/exit() calls is an optimization but also
 * solves the problem of kernel mode pagefaults which can schedule, which
 * is not possible after invoking ct_irq_enter() without undoing it.
 *
 * For user mode entries irqentry_enter_from_user_mode() is invoked to
 * establish the proper context for NOHZ_FULL. Otherwise scheduling on exit
 * would not be possible.
 *
 * Returns: An opaque object that must be passed to idtentry_exit()
 */
irqentry_state_t noinstr irqentry_enter(struct pt_regs *regs);

/**
 * irqentry_exit_cond_resched - Conditionally reschedule on return from interrupt
 *
 * Conditional reschedule with additional sanity checks.
 */
void raw_irqentry_exit_cond_resched(void);
#ifdef CONFIG_PREEMPT_DYNAMIC
#if defined(CONFIG_HAVE_PREEMPT_DYNAMIC_CALL)
#define irqentry_exit_cond_resched_dynamic_enabled	raw_irqentry_exit_cond_resched
#define irqentry_exit_cond_resched_dynamic_disabled	NULL
DECLARE_STATIC_CALL(irqentry_exit_cond_resched, raw_irqentry_exit_cond_resched);
#define irqentry_exit_cond_resched()	static_call(irqentry_exit_cond_resched)()
#elif defined(CONFIG_HAVE_PREEMPT_DYNAMIC_KEY)
DECLARE_STATIC_KEY_TRUE(sk_dynamic_irqentry_exit_cond_resched);
void dynamic_irqentry_exit_cond_resched(void);
#define irqentry_exit_cond_resched()	dynamic_irqentry_exit_cond_resched()
#endif
#else /* CONFIG_PREEMPT_DYNAMIC */
#define irqentry_exit_cond_resched()	raw_irqentry_exit_cond_resched()
#endif /* CONFIG_PREEMPT_DYNAMIC */

/**
 * irqentry_exit - Handle return from exception that used irqentry_enter()
 * @regs:	Pointer to pt_regs (exception entry regs)
 * @state:	Return value from matching call to irqentry_enter()
 *
 * Depending on the return target (kernel/user) this runs the necessary
 * preemption and work checks if possible and required and returns to
 * the caller with interrupts disabled and no further work pending.
 *
 * This is the last action before returning to the low level ASM code which
 * just needs to return to the appropriate context.
 *
 * Counterpart to irqentry_enter().
 */
void noinstr irqentry_exit(struct pt_regs *regs, irqentry_state_t state);

/**
 * irqentry_nmi_enter - Handle NMI entry
 * @regs:	Pointer to currents pt_regs
 *
 * Similar to irqentry_enter() but taking care of the NMI constraints.
 */
irqentry_state_t noinstr irqentry_nmi_enter(struct pt_regs *regs);

/**
 * irqentry_nmi_exit - Handle return from NMI handling
 * @regs:	Pointer to pt_regs (NMI entry regs)
 * @irq_state:	Return value from matching call to irqentry_nmi_enter()
 *
 * Last action before returning to the low level assembly code.
 *
 * Counterpart to irqentry_nmi_enter().
 */
void noinstr irqentry_nmi_exit(struct pt_regs *regs, irqentry_state_t irq_state);

#endif
