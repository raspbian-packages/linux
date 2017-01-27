#if !defined(_TRACE_KVM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KVM_H

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm

/*
 * Tracepoints for vgic
 */
TRACE_EVENT(vgic_update_irq_pending,
	TP_PROTO(unsigned long vcpu_id, __u32 irq, bool level),
	TP_ARGS(vcpu_id, irq, level),

	TP_STRUCT__entry(
		__field(	unsigned long,	vcpu_id	)
		__field(	__u32,		irq	)
		__field(	bool,		level	)
	),

	TP_fast_assign(
		__entry->vcpu_id	= vcpu_id;
		__entry->irq		= irq;
		__entry->level		= level;
	),

	TP_printk("VCPU: %ld, IRQ %d, level: %d",
		  __entry->vcpu_id, __entry->irq, __entry->level)
);

/*
 * Tracepoints for arch_timer
 */
TRACE_EVENT(kvm_timer_update_irq,
	TP_PROTO(unsigned long vcpu_id, __u32 irq, int level),
	TP_ARGS(vcpu_id, irq, level),

	TP_STRUCT__entry(
		__field(	unsigned long,	vcpu_id	)
		__field(	__u32,		irq	)
		__field(	int,		level	)
	),

	TP_fast_assign(
		__entry->vcpu_id	= vcpu_id;
		__entry->irq		= irq;
		__entry->level		= level;
	),

	TP_printk("VCPU: %ld, IRQ %d, level %d",
		  __entry->vcpu_id, __entry->irq, __entry->level)
);

#endif /* _TRACE_KVM_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../../virt/kvm/arm
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

/* This part must be outside protection */
#include <trace/define_trace.h>
