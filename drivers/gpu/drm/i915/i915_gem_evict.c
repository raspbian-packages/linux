/*
 * Copyright © 2008-2010 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Authors:
 *    Eric Anholt <eric@anholt.net>
 *    Chris Wilson <chris@chris-wilson.co.uuk>
 *
 */

#include <drm/drmP.h>
#include <drm/i915_drm.h>

#include "i915_drv.h"
#include "intel_drv.h"
#include "i915_trace.h"

static int switch_to_pinned_context(struct drm_i915_private *dev_priv)
{
	struct intel_engine_cs *engine;

	if (i915.enable_execlists)
		return 0;

	for_each_engine(engine, dev_priv) {
		struct drm_i915_gem_request *req;
		int ret;

		if (engine->last_context == NULL)
			continue;

		if (engine->last_context == dev_priv->kernel_context)
			continue;

		req = i915_gem_request_alloc(engine, dev_priv->kernel_context);
		if (IS_ERR(req))
			return PTR_ERR(req);

		ret = i915_switch_context(req);
		i915_add_request_no_flush(req);
		if (ret)
			return ret;
	}

	return 0;
}


static bool
mark_free(struct i915_vma *vma, struct list_head *unwind)
{
	if (vma->pin_count)
		return false;

	if (WARN_ON(!list_empty(&vma->exec_list)))
		return false;

	list_add(&vma->exec_list, unwind);
	return drm_mm_scan_add_block(&vma->node);
}

/**
 * i915_gem_evict_something - Evict vmas to make room for binding a new one
 * @dev: drm_device
 * @vm: address space to evict from
 * @min_size: size of the desired free space
 * @alignment: alignment constraint of the desired free space
 * @cache_level: cache_level for the desired space
 * @start: start (inclusive) of the range from which to evict objects
 * @end: end (exclusive) of the range from which to evict objects
 * @flags: additional flags to control the eviction algorithm
 *
 * This function will try to evict vmas until a free space satisfying the
 * requirements is found. Callers must check first whether any such hole exists
 * already before calling this function.
 *
 * This function is used by the object/vma binding code.
 *
 * Since this function is only used to free up virtual address space it only
 * ignores pinned vmas, and not object where the backing storage itself is
 * pinned. Hence obj->pages_pin_count does not protect against eviction.
 *
 * To clarify: This is for freeing up virtual address space, not for freeing
 * memory in e.g. the shrinker.
 */
int
i915_gem_evict_something(struct drm_device *dev, struct i915_address_space *vm,
			 int min_size, unsigned alignment, unsigned cache_level,
			 unsigned long start, unsigned long end,
			 unsigned flags)
{
	struct list_head eviction_list, unwind_list;
	struct i915_vma *vma;
	int ret = 0;
	int pass = 0;

	trace_i915_gem_evict(dev, min_size, alignment, flags);

	/*
	 * The goal is to evict objects and amalgamate space in LRU order.
	 * The oldest idle objects reside on the inactive list, which is in
	 * retirement order. The next objects to retire are those on the (per
	 * ring) active list that do not have an outstanding flush. Once the
	 * hardware reports completion (the seqno is updated after the
	 * batchbuffer has been finished) the clean buffer objects would
	 * be retired to the inactive list. Any dirty objects would be added
	 * to the tail of the flushing list. So after processing the clean
	 * active objects we need to emit a MI_FLUSH to retire the flushing
	 * list, hence the retirement order of the flushing list is in
	 * advance of the dirty objects on the active lists.
	 *
	 * The retirement sequence is thus:
	 *   1. Inactive objects (already retired)
	 *   2. Clean active objects
	 *   3. Flushing list
	 *   4. Dirty active objects.
	 *
	 * On each list, the oldest objects lie at the HEAD with the freshest
	 * object on the TAIL.
	 */

	INIT_LIST_HEAD(&unwind_list);
	if (start != 0 || end != vm->total) {
		drm_mm_init_scan_with_range(&vm->mm, min_size,
					    alignment, cache_level,
					    start, end);
	} else
		drm_mm_init_scan(&vm->mm, min_size, alignment, cache_level);

search_again:
	/* First see if there is a large enough contiguous idle region... */
	list_for_each_entry(vma, &vm->inactive_list, vm_link) {
		if (mark_free(vma, &unwind_list))
			goto found;
	}

	if (flags & PIN_NONBLOCK)
		goto none;

	/* Now merge in the soon-to-be-expired objects... */
	list_for_each_entry(vma, &vm->active_list, vm_link) {
		if (mark_free(vma, &unwind_list))
			goto found;
	}

none:
	/* Nothing found, clean up and bail out! */
	while (!list_empty(&unwind_list)) {
		vma = list_first_entry(&unwind_list,
				       struct i915_vma,
				       exec_list);
		ret = drm_mm_scan_remove_block(&vma->node);
		BUG_ON(ret);

		list_del_init(&vma->exec_list);
	}

	/* Can we unpin some objects such as idle hw contents,
	 * or pending flips?
	 */
	if (flags & PIN_NONBLOCK)
		return -ENOSPC;

	/* Only idle the GPU and repeat the search once */
	if (pass++ == 0) {
		struct drm_i915_private *dev_priv = to_i915(dev);

		if (i915_is_ggtt(vm)) {
			ret = switch_to_pinned_context(dev_priv);
			if (ret)
				return ret;
		}

		ret = i915_gem_wait_for_idle(dev_priv);
		if (ret)
			return ret;

		i915_gem_retire_requests(dev_priv);
		goto search_again;
	}

	/* If we still have pending pageflip completions, drop
	 * back to userspace to give our workqueues time to
	 * acquire our locks and unpin the old scanouts.
	 */
	return intel_has_pending_fb_unpin(dev) ? -EAGAIN : -ENOSPC;

found:
	/* drm_mm doesn't allow any other other operations while
	 * scanning, therefore store to be evicted objects on a
	 * temporary list. */
	INIT_LIST_HEAD(&eviction_list);
	while (!list_empty(&unwind_list)) {
		vma = list_first_entry(&unwind_list,
				       struct i915_vma,
				       exec_list);
		if (drm_mm_scan_remove_block(&vma->node)) {
			list_move(&vma->exec_list, &eviction_list);
			drm_gem_object_reference(&vma->obj->base);
			continue;
		}
		list_del_init(&vma->exec_list);
	}

	/* Unbinding will emit any required flushes */
	while (!list_empty(&eviction_list)) {
		struct drm_gem_object *obj;
		vma = list_first_entry(&eviction_list,
				       struct i915_vma,
				       exec_list);

		obj =  &vma->obj->base;
		list_del_init(&vma->exec_list);
		if (ret == 0)
			ret = i915_vma_unbind(vma);

		drm_gem_object_unreference(obj);
	}

	return ret;
}

int
i915_gem_evict_for_vma(struct i915_vma *target)
{
	struct drm_mm_node *node, *next;

	list_for_each_entry_safe(node, next,
			&target->vm->mm.head_node.node_list,
			node_list) {
		struct i915_vma *vma;
		int ret;

		if (node->start + node->size <= target->node.start)
			continue;
		if (node->start >= target->node.start + target->node.size)
			break;

		vma = container_of(node, typeof(*vma), node);

		if (vma->pin_count) {
			if (!vma->exec_entry || (vma->pin_count > 1))
				/* Object is pinned for some other use */
				return -EBUSY;

			/* We need to evict a buffer in the same batch */
			if (vma->exec_entry->flags & EXEC_OBJECT_PINNED)
				/* Overlapping fixed objects in the same batch */
				return -EINVAL;

			return -ENOSPC;
		}

		ret = i915_vma_unbind(vma);
		if (ret)
			return ret;
	}

	return 0;
}

/**
 * i915_gem_evict_vm - Evict all idle vmas from a vm
 * @vm: Address space to cleanse
 * @do_idle: Boolean directing whether to idle first.
 *
 * This function evicts all idles vmas from a vm. If all unpinned vmas should be
 * evicted the @do_idle needs to be set to true.
 *
 * This is used by the execbuf code as a last-ditch effort to defragment the
 * address space.
 *
 * To clarify: This is for freeing up virtual address space, not for freeing
 * memory in e.g. the shrinker.
 */
int i915_gem_evict_vm(struct i915_address_space *vm, bool do_idle)
{
	struct i915_vma *vma, *next;
	int ret;

	WARN_ON(!mutex_is_locked(&vm->dev->struct_mutex));
	trace_i915_gem_evict_vm(vm);

	if (do_idle) {
		struct drm_i915_private *dev_priv = to_i915(vm->dev);

		if (i915_is_ggtt(vm)) {
			ret = switch_to_pinned_context(dev_priv);
			if (ret)
				return ret;
		}

		ret = i915_gem_wait_for_idle(dev_priv);
		if (ret)
			return ret;

		i915_gem_retire_requests(dev_priv);

		WARN_ON(!list_empty(&vm->active_list));
	}

	list_for_each_entry_safe(vma, next, &vm->inactive_list, vm_link)
		if (vma->pin_count == 0)
			WARN_ON(i915_vma_unbind(vma));

	return 0;
}
