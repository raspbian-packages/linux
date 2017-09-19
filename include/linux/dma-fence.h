/*
 * Fence mechanism for dma-buf to allow for asynchronous dma access
 *
 * Copyright (C) 2012 Canonical Ltd
 * Copyright (C) 2012 Texas Instruments
 *
 * Authors:
 * Rob Clark <robdclark@gmail.com>
 * Maarten Lankhorst <maarten.lankhorst@canonical.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef __LINUX_DMA_FENCE_H
#define __LINUX_DMA_FENCE_H

#include <linux/err.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/bitops.h>
#include <linux/kref.h>
#include <linux/sched.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>

struct dma_fence;
struct dma_fence_ops;
struct dma_fence_cb;

/**
 * struct dma_fence - software synchronization primitive
 * @refcount: refcount for this fence
 * @ops: dma_fence_ops associated with this fence
 * @rcu: used for releasing fence with kfree_rcu
 * @cb_list: list of all callbacks to call
 * @lock: spin_lock_irqsave used for locking
 * @context: execution context this fence belongs to, returned by
 *           dma_fence_context_alloc()
 * @seqno: the sequence number of this fence inside the execution context,
 * can be compared to decide which fence would be signaled later.
 * @flags: A mask of DMA_FENCE_FLAG_* defined below
 * @timestamp: Timestamp when the fence was signaled.
 * @error: Optional, only valid if < 0, must be set before calling
 * dma_fence_signal, indicates that the fence has completed with an error.
 *
 * the flags member must be manipulated and read using the appropriate
 * atomic ops (bit_*), so taking the spinlock will not be needed most
 * of the time.
 *
 * DMA_FENCE_FLAG_SIGNALED_BIT - fence is already signaled
 * DMA_FENCE_FLAG_ENABLE_SIGNAL_BIT - enable_signaling might have been called
 * DMA_FENCE_FLAG_USER_BITS - start of the unused bits, can be used by the
 * implementer of the fence for its own purposes. Can be used in different
 * ways by different fence implementers, so do not rely on this.
 *
 * Since atomic bitops are used, this is not guaranteed to be the case.
 * Particularly, if the bit was set, but dma_fence_signal was called right
 * before this bit was set, it would have been able to set the
 * DMA_FENCE_FLAG_SIGNALED_BIT, before enable_signaling was called.
 * Adding a check for DMA_FENCE_FLAG_SIGNALED_BIT after setting
 * DMA_FENCE_FLAG_ENABLE_SIGNAL_BIT closes this race, and makes sure that
 * after dma_fence_signal was called, any enable_signaling call will have either
 * been completed, or never called at all.
 */
struct dma_fence {
	struct kref refcount;
	const struct dma_fence_ops *ops;
	struct rcu_head rcu;
	struct list_head cb_list;
	spinlock_t *lock;
	u64 context;
	unsigned seqno;
	unsigned long flags;
	ktime_t timestamp;
	int error;
};

enum dma_fence_flag_bits {
	DMA_FENCE_FLAG_SIGNALED_BIT,
	DMA_FENCE_FLAG_ENABLE_SIGNAL_BIT,
	DMA_FENCE_FLAG_USER_BITS, /* must always be last member */
};

typedef void (*dma_fence_func_t)(struct dma_fence *fence,
				 struct dma_fence_cb *cb);

/**
 * struct dma_fence_cb - callback for dma_fence_add_callback
 * @node: used by dma_fence_add_callback to append this struct to fence::cb_list
 * @func: dma_fence_func_t to call
 *
 * This struct will be initialized by dma_fence_add_callback, additional
 * data can be passed along by embedding dma_fence_cb in another struct.
 */
struct dma_fence_cb {
	struct list_head node;
	dma_fence_func_t func;
};

/**
 * struct dma_fence_ops - operations implemented for fence
 * @get_driver_name: returns the driver name.
 * @get_timeline_name: return the name of the context this fence belongs to.
 * @enable_signaling: enable software signaling of fence.
 * @signaled: [optional] peek whether the fence is signaled, can be null.
 * @wait: custom wait implementation, or dma_fence_default_wait.
 * @release: [optional] called on destruction of fence, can be null
 * @fill_driver_data: [optional] callback to fill in free-form debug info
 * Returns amount of bytes filled, or -errno.
 * @fence_value_str: [optional] fills in the value of the fence as a string
 * @timeline_value_str: [optional] fills in the current value of the timeline
 * as a string
 *
 * Notes on enable_signaling:
 * For fence implementations that have the capability for hw->hw
 * signaling, they can implement this op to enable the necessary
 * irqs, or insert commands into cmdstream, etc.  This is called
 * in the first wait() or add_callback() path to let the fence
 * implementation know that there is another driver waiting on
 * the signal (ie. hw->sw case).
 *
 * This function can be called called from atomic context, but not
 * from irq context, so normal spinlocks can be used.
 *
 * A return value of false indicates the fence already passed,
 * or some failure occurred that made it impossible to enable
 * signaling. True indicates successful enabling.
 *
 * fence->error may be set in enable_signaling, but only when false is
 * returned.
 *
 * Calling dma_fence_signal before enable_signaling is called allows
 * for a tiny race window in which enable_signaling is called during,
 * before, or after dma_fence_signal. To fight this, it is recommended
 * that before enable_signaling returns true an extra reference is
 * taken on the fence, to be released when the fence is signaled.
 * This will mean dma_fence_signal will still be called twice, but
 * the second time will be a noop since it was already signaled.
 *
 * Notes on signaled:
 * May set fence->error if returning true.
 *
 * Notes on wait:
 * Must not be NULL, set to dma_fence_default_wait for default implementation.
 * the dma_fence_default_wait implementation should work for any fence, as long
 * as enable_signaling works correctly.
 *
 * Must return -ERESTARTSYS if the wait is intr = true and the wait was
 * interrupted, and remaining jiffies if fence has signaled, or 0 if wait
 * timed out. Can also return other error values on custom implementations,
 * which should be treated as if the fence is signaled. For example a hardware
 * lockup could be reported like that.
 *
 * Notes on release:
 * Can be NULL, this function allows additional commands to run on
 * destruction of the fence. Can be called from irq context.
 * If pointer is set to NULL, kfree will get called instead.
 */

struct dma_fence_ops {
	const char * (*get_driver_name)(struct dma_fence *fence);
	const char * (*get_timeline_name)(struct dma_fence *fence);
	bool (*enable_signaling)(struct dma_fence *fence);
	bool (*signaled)(struct dma_fence *fence);
	signed long (*wait)(struct dma_fence *fence,
			    bool intr, signed long timeout);
	void (*release)(struct dma_fence *fence);

	int (*fill_driver_data)(struct dma_fence *fence, void *data, int size);
	void (*fence_value_str)(struct dma_fence *fence, char *str, int size);
	void (*timeline_value_str)(struct dma_fence *fence,
				   char *str, int size);
};

void dma_fence_init(struct dma_fence *fence, const struct dma_fence_ops *ops,
		    spinlock_t *lock, u64 context, unsigned seqno);

void dma_fence_release(struct kref *kref);
void dma_fence_free(struct dma_fence *fence);

/**
 * dma_fence_put - decreases refcount of the fence
 * @fence:	[in]	fence to reduce refcount of
 */
static inline void dma_fence_put(struct dma_fence *fence)
{
	if (fence)
		kref_put(&fence->refcount, dma_fence_release);
}

/**
 * dma_fence_get - increases refcount of the fence
 * @fence:	[in]	fence to increase refcount of
 *
 * Returns the same fence, with refcount increased by 1.
 */
static inline struct dma_fence *dma_fence_get(struct dma_fence *fence)
{
	if (fence)
		kref_get(&fence->refcount);
	return fence;
}

/**
 * dma_fence_get_rcu - get a fence from a reservation_object_list with
 *                     rcu read lock
 * @fence:	[in]	fence to increase refcount of
 *
 * Function returns NULL if no refcount could be obtained, or the fence.
 */
static inline struct dma_fence *dma_fence_get_rcu(struct dma_fence *fence)
{
	if (kref_get_unless_zero(&fence->refcount))
		return fence;
	else
		return NULL;
}

/**
 * dma_fence_get_rcu_safe  - acquire a reference to an RCU tracked fence
 * @fencep:	[in]	pointer to fence to increase refcount of
 *
 * Function returns NULL if no refcount could be obtained, or the fence.
 * This function handles acquiring a reference to a fence that may be
 * reallocated within the RCU grace period (such as with SLAB_TYPESAFE_BY_RCU),
 * so long as the caller is using RCU on the pointer to the fence.
 *
 * An alternative mechanism is to employ a seqlock to protect a bunch of
 * fences, such as used by struct reservation_object. When using a seqlock,
 * the seqlock must be taken before and checked after a reference to the
 * fence is acquired (as shown here).
 *
 * The caller is required to hold the RCU read lock.
 */
static inline struct dma_fence *
dma_fence_get_rcu_safe(struct dma_fence * __rcu *fencep)
{
	do {
		struct dma_fence *fence;

		fence = rcu_dereference(*fencep);
		if (!fence || !dma_fence_get_rcu(fence))
			return NULL;

		/* The atomic_inc_not_zero() inside dma_fence_get_rcu()
		 * provides a full memory barrier upon success (such as now).
		 * This is paired with the write barrier from assigning
		 * to the __rcu protected fence pointer so that if that
		 * pointer still matches the current fence, we know we
		 * have successfully acquire a reference to it. If it no
		 * longer matches, we are holding a reference to some other
		 * reallocated pointer. This is possible if the allocator
		 * is using a freelist like SLAB_TYPESAFE_BY_RCU where the
		 * fence remains valid for the RCU grace period, but it
		 * may be reallocated. When using such allocators, we are
		 * responsible for ensuring the reference we get is to
		 * the right fence, as below.
		 */
		if (fence == rcu_access_pointer(*fencep))
			return rcu_pointer_handoff(fence);

		dma_fence_put(fence);
	} while (1);
}

int dma_fence_signal(struct dma_fence *fence);
int dma_fence_signal_locked(struct dma_fence *fence);
signed long dma_fence_default_wait(struct dma_fence *fence,
				   bool intr, signed long timeout);
int dma_fence_add_callback(struct dma_fence *fence,
			   struct dma_fence_cb *cb,
			   dma_fence_func_t func);
bool dma_fence_remove_callback(struct dma_fence *fence,
			       struct dma_fence_cb *cb);
void dma_fence_enable_sw_signaling(struct dma_fence *fence);

/**
 * dma_fence_is_signaled_locked - Return an indication if the fence
 *                                is signaled yet.
 * @fence:	[in]	the fence to check
 *
 * Returns true if the fence was already signaled, false if not. Since this
 * function doesn't enable signaling, it is not guaranteed to ever return
 * true if dma_fence_add_callback, dma_fence_wait or
 * dma_fence_enable_sw_signaling haven't been called before.
 *
 * This function requires fence->lock to be held.
 */
static inline bool
dma_fence_is_signaled_locked(struct dma_fence *fence)
{
	if (test_bit(DMA_FENCE_FLAG_SIGNALED_BIT, &fence->flags))
		return true;

	if (fence->ops->signaled && fence->ops->signaled(fence)) {
		dma_fence_signal_locked(fence);
		return true;
	}

	return false;
}

/**
 * dma_fence_is_signaled - Return an indication if the fence is signaled yet.
 * @fence:	[in]	the fence to check
 *
 * Returns true if the fence was already signaled, false if not. Since this
 * function doesn't enable signaling, it is not guaranteed to ever return
 * true if dma_fence_add_callback, dma_fence_wait or
 * dma_fence_enable_sw_signaling haven't been called before.
 *
 * It's recommended for seqno fences to call dma_fence_signal when the
 * operation is complete, it makes it possible to prevent issues from
 * wraparound between time of issue and time of use by checking the return
 * value of this function before calling hardware-specific wait instructions.
 */
static inline bool
dma_fence_is_signaled(struct dma_fence *fence)
{
	if (test_bit(DMA_FENCE_FLAG_SIGNALED_BIT, &fence->flags))
		return true;

	if (fence->ops->signaled && fence->ops->signaled(fence)) {
		dma_fence_signal(fence);
		return true;
	}

	return false;
}

/**
 * dma_fence_is_later - return if f1 is chronologically later than f2
 * @f1:	[in]	the first fence from the same context
 * @f2:	[in]	the second fence from the same context
 *
 * Returns true if f1 is chronologically later than f2. Both fences must be
 * from the same context, since a seqno is not re-used across contexts.
 */
static inline bool dma_fence_is_later(struct dma_fence *f1,
				      struct dma_fence *f2)
{
	if (WARN_ON(f1->context != f2->context))
		return false;

	return (int)(f1->seqno - f2->seqno) > 0;
}

/**
 * dma_fence_later - return the chronologically later fence
 * @f1:	[in]	the first fence from the same context
 * @f2:	[in]	the second fence from the same context
 *
 * Returns NULL if both fences are signaled, otherwise the fence that would be
 * signaled last. Both fences must be from the same context, since a seqno is
 * not re-used across contexts.
 */
static inline struct dma_fence *dma_fence_later(struct dma_fence *f1,
						struct dma_fence *f2)
{
	if (WARN_ON(f1->context != f2->context))
		return NULL;

	/*
	 * Can't check just DMA_FENCE_FLAG_SIGNALED_BIT here, it may never
	 * have been set if enable_signaling wasn't called, and enabling that
	 * here is overkill.
	 */
	if (dma_fence_is_later(f1, f2))
		return dma_fence_is_signaled(f1) ? NULL : f1;
	else
		return dma_fence_is_signaled(f2) ? NULL : f2;
}

/**
 * dma_fence_get_status_locked - returns the status upon completion
 * @fence: [in]	the dma_fence to query
 *
 * Drivers can supply an optional error status condition before they signal
 * the fence (to indicate whether the fence was completed due to an error
 * rather than success). The value of the status condition is only valid
 * if the fence has been signaled, dma_fence_get_status_locked() first checks
 * the signal state before reporting the error status.
 *
 * Returns 0 if the fence has not yet been signaled, 1 if the fence has
 * been signaled without an error condition, or a negative error code
 * if the fence has been completed in err.
 */
static inline int dma_fence_get_status_locked(struct dma_fence *fence)
{
	if (dma_fence_is_signaled_locked(fence))
		return fence->error ?: 1;
	else
		return 0;
}

int dma_fence_get_status(struct dma_fence *fence);

/**
 * dma_fence_set_error - flag an error condition on the fence
 * @fence: [in]	the dma_fence
 * @error: [in]	the error to store
 *
 * Drivers can supply an optional error status condition before they signal
 * the fence, to indicate that the fence was completed due to an error
 * rather than success. This must be set before signaling (so that the value
 * is visible before any waiters on the signal callback are woken). This
 * helper exists to help catching erroneous setting of #dma_fence.error.
 */
static inline void dma_fence_set_error(struct dma_fence *fence,
				       int error)
{
	BUG_ON(test_bit(DMA_FENCE_FLAG_SIGNALED_BIT, &fence->flags));
	BUG_ON(error >= 0 || error < -MAX_ERRNO);

	fence->error = error;
}

signed long dma_fence_wait_timeout(struct dma_fence *,
				   bool intr, signed long timeout);
signed long dma_fence_wait_any_timeout(struct dma_fence **fences,
				       uint32_t count,
				       bool intr, signed long timeout,
				       uint32_t *idx);

/**
 * dma_fence_wait - sleep until the fence gets signaled
 * @fence:	[in]	the fence to wait on
 * @intr:	[in]	if true, do an interruptible wait
 *
 * This function will return -ERESTARTSYS if interrupted by a signal,
 * or 0 if the fence was signaled. Other error values may be
 * returned on custom implementations.
 *
 * Performs a synchronous wait on this fence. It is assumed the caller
 * directly or indirectly holds a reference to the fence, otherwise the
 * fence might be freed before return, resulting in undefined behavior.
 */
static inline signed long dma_fence_wait(struct dma_fence *fence, bool intr)
{
	signed long ret;

	/* Since dma_fence_wait_timeout cannot timeout with
	 * MAX_SCHEDULE_TIMEOUT, only valid return values are
	 * -ERESTARTSYS and MAX_SCHEDULE_TIMEOUT.
	 */
	ret = dma_fence_wait_timeout(fence, intr, MAX_SCHEDULE_TIMEOUT);

	return ret < 0 ? ret : 0;
}

u64 dma_fence_context_alloc(unsigned num);

#define DMA_FENCE_TRACE(f, fmt, args...) \
	do {								\
		struct dma_fence *__ff = (f);				\
		if (IS_ENABLED(CONFIG_DMA_FENCE_TRACE))			\
			pr_info("f %llu#%u: " fmt,			\
				__ff->context, __ff->seqno, ##args);	\
	} while (0)

#define DMA_FENCE_WARN(f, fmt, args...) \
	do {								\
		struct dma_fence *__ff = (f);				\
		pr_warn("f %llu#%u: " fmt, __ff->context, __ff->seqno,	\
			 ##args);					\
	} while (0)

#define DMA_FENCE_ERR(f, fmt, args...) \
	do {								\
		struct dma_fence *__ff = (f);				\
		pr_err("f %llu#%u: " fmt, __ff->context, __ff->seqno,	\
			##args);					\
	} while (0)

#endif /* __LINUX_DMA_FENCE_H */
