/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
 */

#ifndef _ASM_ARC_ATOMIC_H
#define _ASM_ARC_ATOMIC_H

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <linux/compiler.h>
#include <asm/cmpxchg.h>
#include <asm/barrier.h>
#include <asm/smp.h>

#define arch_atomic_read(v)  READ_ONCE((v)->counter)

#ifdef CONFIG_ARC_HAS_LLSC
#include <asm/atomic-llsc.h>
#else
#include <asm/atomic-spinlock.h>
#endif

#define arch_atomic_cmpxchg(v, o, n)					\
({									\
	arch_cmpxchg(&((v)->counter), (o), (n));			\
})

#ifdef arch_cmpxchg_relaxed
#define arch_atomic_cmpxchg_relaxed(v, o, n)				\
({									\
	arch_cmpxchg_relaxed(&((v)->counter), (o), (n));		\
})
#endif

#define arch_atomic_xchg(v, n)						\
({									\
	arch_xchg(&((v)->counter), (n));				\
})

#ifdef arch_xchg_relaxed
#define arch_atomic_xchg_relaxed(v, n)					\
({									\
	arch_xchg_relaxed(&((v)->counter), (n));			\
})
#endif

/*
 * 64-bit atomics
 */
#ifdef CONFIG_GENERIC_ATOMIC64
#include <asm-generic/atomic64.h>
#else
#include <asm/atomic64-arcv2.h>
#endif

#endif	/* !__ASSEMBLY__ */

#endif
