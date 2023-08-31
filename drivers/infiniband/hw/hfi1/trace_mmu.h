/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2017 Intel Corporation.
 */

#if !defined(__HFI1_TRACE_MMU_H) || defined(TRACE_HEADER_MULTI_READ)
#define __HFI1_TRACE_MMU_H

#include <linux/tracepoint.h>
#include <linux/trace_seq.h>

#include "hfi.h"

#undef TRACE_SYSTEM
#define TRACE_SYSTEM hfi1_mmu

DECLARE_EVENT_CLASS(hfi1_mmu_rb_template,
		    TP_PROTO(unsigned long addr, unsigned long len),
		    TP_ARGS(addr, len),
		    TP_STRUCT__entry(__field(unsigned long, addr)
				     __field(unsigned long, len)
			    ),
		    TP_fast_assign(__entry->addr = addr;
				   __entry->len = len;
			    ),
		    TP_printk("MMU node addr 0x%lx, len %lu",
			      __entry->addr,
			      __entry->len
			    )
);

DEFINE_EVENT(hfi1_mmu_rb_template, hfi1_mmu_rb_insert,
	     TP_PROTO(unsigned long addr, unsigned long len),
	     TP_ARGS(addr, len));

DEFINE_EVENT(hfi1_mmu_rb_template, hfi1_mmu_rb_search,
	     TP_PROTO(unsigned long addr, unsigned long len),
	     TP_ARGS(addr, len));

DEFINE_EVENT(hfi1_mmu_rb_template, hfi1_mmu_mem_invalidate,
	     TP_PROTO(unsigned long addr, unsigned long len),
	     TP_ARGS(addr, len));

#endif /* __HFI1_TRACE_RC_H */

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace_mmu
#include <trace/define_trace.h>
