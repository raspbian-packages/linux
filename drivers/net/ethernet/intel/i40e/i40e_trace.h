/*******************************************************************************
 *
 * Intel(R) 40-10 Gigabit Ethernet Connection Network Driver
 * Copyright(c) 2013 - 2017 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Contact Information:
 * e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 ******************************************************************************/

/* Modeled on trace-events-sample.h */

/* The trace subsystem name for i40e will be "i40e".
 *
 * This file is named i40e_trace.h.
 *
 * Since this include file's name is different from the trace
 * subsystem name, we'll have to define TRACE_INCLUDE_FILE at the end
 * of this file.
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM i40e

/* See trace-events-sample.h for a detailed description of why this
 * guard clause is different from most normal include files.
 */
#if !defined(_I40E_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)
#define _I40E_TRACE_H_

#include <linux/tracepoint.h>

/**
 * i40e_trace() macro enables shared code to refer to trace points
 * like:
 *
 * trace_i40e{,vf}_example(args...)
 *
 * ... as:
 *
 * i40e_trace(example, args...)
 *
 * ... to resolve to the PF or VF version of the tracepoint without
 * ifdefs, and to allow tracepoints to be disabled entirely at build
 * time.
 *
 * Trace point should always be referred to in the driver via this
 * macro.
 *
 * Similarly, i40e_trace_enabled(trace_name) wraps references to
 * trace_i40e{,vf}_<trace_name>_enabled() functions.
 */
#define _I40E_TRACE_NAME(trace_name) (trace_ ## i40e ## _ ## trace_name)
#define I40E_TRACE_NAME(trace_name) _I40E_TRACE_NAME(trace_name)

#define i40e_trace(trace_name, args...) I40E_TRACE_NAME(trace_name)(args)

#define i40e_trace_enabled(trace_name) I40E_TRACE_NAME(trace_name##_enabled)()

/* Events common to PF and VF. Corresponding versions will be defined
 * for both, named trace_i40e_* and trace_i40evf_*. The i40e_trace()
 * macro above will select the right trace point name for the driver
 * being built from shared code.
 */

/* Events related to a vsi & ring */
DECLARE_EVENT_CLASS(
	i40e_tx_template,

	TP_PROTO(struct i40e_ring *ring,
		 struct i40e_tx_desc *desc,
		 struct i40e_tx_buffer *buf),

	TP_ARGS(ring, desc, buf),

	/* The convention here is to make the first fields in the
	 * TP_STRUCT match the TP_PROTO exactly. This enables the use
	 * of the args struct generated by the tplist tool (from the
	 * bcc-tools package) to be used for those fields. To access
	 * fields other than the tracepoint args will require the
	 * tplist output to be adjusted.
	 */
	TP_STRUCT__entry(
		__field(void*, ring)
		__field(void*, desc)
		__field(void*, buf)
		__string(devname, ring->netdev->name)
	),

	TP_fast_assign(
		__entry->ring = ring;
		__entry->desc = desc;
		__entry->buf = buf;
		__assign_str(devname, ring->netdev->name);
	),

	TP_printk(
		"netdev: %s ring: %p desc: %p buf %p",
		__get_str(devname), __entry->ring,
		__entry->desc, __entry->buf)
);

DEFINE_EVENT(
	i40e_tx_template, i40e_clean_tx_irq,
	TP_PROTO(struct i40e_ring *ring,
		 struct i40e_tx_desc *desc,
		 struct i40e_tx_buffer *buf),

	TP_ARGS(ring, desc, buf));

DEFINE_EVENT(
	i40e_tx_template, i40e_clean_tx_irq_unmap,
	TP_PROTO(struct i40e_ring *ring,
		 struct i40e_tx_desc *desc,
		 struct i40e_tx_buffer *buf),

	TP_ARGS(ring, desc, buf));

DECLARE_EVENT_CLASS(
	i40e_rx_template,

	TP_PROTO(struct i40e_ring *ring,
		 union i40e_32byte_rx_desc *desc,
		 struct sk_buff *skb),

	TP_ARGS(ring, desc, skb),

	TP_STRUCT__entry(
		__field(void*, ring)
		__field(void*, desc)
		__field(void*, skb)
		__string(devname, ring->netdev->name)
	),

	TP_fast_assign(
		__entry->ring = ring;
		__entry->desc = desc;
		__entry->skb = skb;
		__assign_str(devname, ring->netdev->name);
	),

	TP_printk(
		"netdev: %s ring: %p desc: %p skb %p",
		__get_str(devname), __entry->ring,
		__entry->desc, __entry->skb)
);

DEFINE_EVENT(
	i40e_rx_template, i40e_clean_rx_irq,
	TP_PROTO(struct i40e_ring *ring,
		 union i40e_32byte_rx_desc *desc,
		 struct sk_buff *skb),

	TP_ARGS(ring, desc, skb));

DEFINE_EVENT(
	i40e_rx_template, i40e_clean_rx_irq_rx,
	TP_PROTO(struct i40e_ring *ring,
		 union i40e_32byte_rx_desc *desc,
		 struct sk_buff *skb),

	TP_ARGS(ring, desc, skb));

DECLARE_EVENT_CLASS(
	i40e_xmit_template,

	TP_PROTO(struct sk_buff *skb,
		 struct i40e_ring *ring),

	TP_ARGS(skb, ring),

	TP_STRUCT__entry(
		__field(void*, skb)
		__field(void*, ring)
		__string(devname, ring->netdev->name)
	),

	TP_fast_assign(
		__entry->skb = skb;
		__entry->ring = ring;
		__assign_str(devname, ring->netdev->name);
	),

	TP_printk(
		"netdev: %s skb: %p ring: %p",
		__get_str(devname), __entry->skb,
		__entry->ring)
);

DEFINE_EVENT(
	i40e_xmit_template, i40e_xmit_frame_ring,
	TP_PROTO(struct sk_buff *skb,
		 struct i40e_ring *ring),

	TP_ARGS(skb, ring));

DEFINE_EVENT(
	i40e_xmit_template, i40e_xmit_frame_ring_drop,
	TP_PROTO(struct sk_buff *skb,
		 struct i40e_ring *ring),

	TP_ARGS(skb, ring));

/* Events unique to the PF. */

#endif /* _I40E_TRACE_H_ */
/* This must be outside ifdef _I40E_TRACE_H */

/* This trace include file is not located in the .../include/trace
 * with the kernel tracepoint definitions, because we're a loadable
 * module.
 */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE i40e_trace
#include <trace/define_trace.h>
