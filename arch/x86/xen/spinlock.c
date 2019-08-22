/*
 * Split spinlock implementation out into its own file, so it can be
 * compiled in a FTRACE-compatible way.
 */
#include <linux/kernel_stat.h>
#include <linux/spinlock.h>
#include <linux/debugfs.h>
#include <linux/log2.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/atomic.h>

#include <asm/paravirt.h>

#include <xen/interface/xen.h>
#include <xen/events.h>

#include "xen-ops.h"
#include "debugfs.h"

static DEFINE_PER_CPU(int, lock_kicker_irq) = -1;
static DEFINE_PER_CPU(char *, irq_name);
static DEFINE_PER_CPU(atomic_t, xen_qlock_wait_nest);
static bool xen_pvspin = true;

#include <asm/qspinlock.h>

static void xen_qlock_kick(int cpu)
{
	int irq = per_cpu(lock_kicker_irq, cpu);

	/* Don't kick if the target's kicker interrupt is not initialized. */
	if (irq == -1)
		return;

	xen_send_IPI_one(cpu, XEN_SPIN_UNLOCK_VECTOR);
}

/*
 * Halt the current CPU & release it back to the host
 */
static void xen_qlock_wait(u8 *byte, u8 val)
{
	int irq = __this_cpu_read(lock_kicker_irq);
	atomic_t *nest_cnt = this_cpu_ptr(&xen_qlock_wait_nest);

	/* If kicker interrupts not initialized yet, just spin */
	if (irq == -1 || in_nmi())
		return;

	/* Detect reentry. */
	atomic_inc(nest_cnt);

	/* If irq pending already and no nested call clear it. */
	if (atomic_read(nest_cnt) == 1 && xen_test_irq_pending(irq)) {
		xen_clear_irq_pending(irq);
	} else if (READ_ONCE(*byte) == val) {
		/* Block until irq becomes pending (or a spurious wakeup) */
		xen_poll_irq(irq);
	}

	atomic_dec(nest_cnt);
}

static irqreturn_t dummy_handler(int irq, void *dev_id)
{
	BUG();
	return IRQ_HANDLED;
}

void xen_init_lock_cpu(int cpu)
{
	int irq;
	char *name;

	if (!xen_pvspin)
		return;

	WARN(per_cpu(lock_kicker_irq, cpu) >= 0, "spinlock on CPU%d exists on IRQ%d!\n",
	     cpu, per_cpu(lock_kicker_irq, cpu));

	name = kasprintf(GFP_KERNEL, "spinlock%d", cpu);
	irq = bind_ipi_to_irqhandler(XEN_SPIN_UNLOCK_VECTOR,
				     cpu,
				     dummy_handler,
				     IRQF_PERCPU|IRQF_NOBALANCING,
				     name,
				     NULL);

	if (irq >= 0) {
		disable_irq(irq); /* make sure it's never delivered */
		per_cpu(lock_kicker_irq, cpu) = irq;
		per_cpu(irq_name, cpu) = name;
	}

	printk("cpu %d spinlock event irq %d\n", cpu, irq);
}

void xen_uninit_lock_cpu(int cpu)
{
	if (!xen_pvspin)
		return;

	unbind_from_irqhandler(per_cpu(lock_kicker_irq, cpu), NULL);
	per_cpu(lock_kicker_irq, cpu) = -1;
	kfree(per_cpu(irq_name, cpu));
	per_cpu(irq_name, cpu) = NULL;
}


/*
 * Our init of PV spinlocks is split in two init functions due to us
 * using paravirt patching and jump labels patching and having to do
 * all of this before SMP code is invoked.
 *
 * The paravirt patching needs to be done _before_ the alternative asm code
 * is started, otherwise we would not patch the core kernel code.
 */
void __init xen_init_spinlocks(void)
{

	if (!xen_pvspin) {
		printk(KERN_DEBUG "xen: PV spinlocks disabled\n");
		return;
	}
	printk(KERN_DEBUG "xen: PV spinlocks enabled\n");

	__pv_init_lock_hash();
	pv_lock_ops.queued_spin_lock_slowpath = __pv_queued_spin_lock_slowpath;
	pv_lock_ops.queued_spin_unlock = PV_CALLEE_SAVE(__pv_queued_spin_unlock);
	pv_lock_ops.wait = xen_qlock_wait;
	pv_lock_ops.kick = xen_qlock_kick;
}

/*
 * While the jump_label init code needs to happend _after_ the jump labels are
 * enabled and before SMP is started. Hence we use pre-SMP initcall level
 * init. We cannot do it in xen_init_spinlocks as that is done before
 * jump labels are activated.
 */
static __init int xen_init_spinlocks_jump(void)
{
	if (!xen_pvspin)
		return 0;

	if (!xen_domain())
		return 0;

	static_key_slow_inc(&paravirt_ticketlocks_enabled);
	return 0;
}
early_initcall(xen_init_spinlocks_jump);

static __init int xen_parse_nopvspin(char *arg)
{
	xen_pvspin = false;
	return 0;
}
early_param("xen_nopvspin", xen_parse_nopvspin);

