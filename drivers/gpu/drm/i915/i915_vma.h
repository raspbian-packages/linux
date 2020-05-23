/*
 * Copyright © 2016 Intel Corporation
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
 */

#ifndef __I915_VMA_H__
#define __I915_VMA_H__

#include <linux/io-mapping.h>
#include <linux/rbtree.h>

#include <drm/drm_mm.h>

#include "gem/i915_gem_object.h"

#include "i915_gem_gtt.h"
#include "i915_gem_fence_reg.h"

#include "i915_active.h"
#include "i915_request.h"
#include "i915_vma_types.h"

struct i915_vma *
i915_vma_instance(struct drm_i915_gem_object *obj,
		  struct i915_address_space *vm,
		  const struct i915_ggtt_view *view);

void i915_vma_unpin_and_release(struct i915_vma **p_vma, unsigned int flags);
#define I915_VMA_RELEASE_MAP BIT(0)

static inline bool i915_vma_is_active(const struct i915_vma *vma)
{
	return !i915_active_is_idle(&vma->active);
}

int __must_check __i915_vma_move_to_active(struct i915_vma *vma,
					   struct i915_request *rq);
int __must_check i915_vma_move_to_active(struct i915_vma *vma,
					 struct i915_request *rq,
					 unsigned int flags);

#define __i915_vma_flags(v) ((unsigned long *)&(v)->flags.counter)

static inline bool i915_vma_is_ggtt(const struct i915_vma *vma)
{
	return test_bit(I915_VMA_GGTT_BIT, __i915_vma_flags(vma));
}

static inline bool i915_vma_has_ggtt_write(const struct i915_vma *vma)
{
	return test_bit(I915_VMA_GGTT_WRITE_BIT, __i915_vma_flags(vma));
}

static inline void i915_vma_set_ggtt_write(struct i915_vma *vma)
{
	GEM_BUG_ON(!i915_vma_is_ggtt(vma));
	set_bit(I915_VMA_GGTT_WRITE_BIT, __i915_vma_flags(vma));
}

static inline bool i915_vma_unset_ggtt_write(struct i915_vma *vma)
{
	return test_and_clear_bit(I915_VMA_GGTT_WRITE_BIT,
				  __i915_vma_flags(vma));
}

void i915_vma_flush_writes(struct i915_vma *vma);

static inline bool i915_vma_is_map_and_fenceable(const struct i915_vma *vma)
{
	return test_bit(I915_VMA_CAN_FENCE_BIT, __i915_vma_flags(vma));
}

static inline bool i915_vma_set_userfault(struct i915_vma *vma)
{
	GEM_BUG_ON(!i915_vma_is_map_and_fenceable(vma));
	return test_and_set_bit(I915_VMA_USERFAULT_BIT, __i915_vma_flags(vma));
}

static inline void i915_vma_unset_userfault(struct i915_vma *vma)
{
	return clear_bit(I915_VMA_USERFAULT_BIT, __i915_vma_flags(vma));
}

static inline bool i915_vma_has_userfault(const struct i915_vma *vma)
{
	return test_bit(I915_VMA_USERFAULT_BIT, __i915_vma_flags(vma));
}

static inline bool i915_vma_is_closed(const struct i915_vma *vma)
{
	return !list_empty(&vma->closed_link);
}

static inline u32 i915_ggtt_offset(const struct i915_vma *vma)
{
	GEM_BUG_ON(!i915_vma_is_ggtt(vma));
	GEM_BUG_ON(!drm_mm_node_allocated(&vma->node));
	GEM_BUG_ON(upper_32_bits(vma->node.start));
	GEM_BUG_ON(upper_32_bits(vma->node.start + vma->node.size - 1));
	return lower_32_bits(vma->node.start);
}

static inline u32 i915_ggtt_pin_bias(struct i915_vma *vma)
{
	return i915_vm_to_ggtt(vma->vm)->pin_bias;
}

static inline struct i915_vma *i915_vma_get(struct i915_vma *vma)
{
	i915_gem_object_get(vma->obj);
	return vma;
}

static inline struct i915_vma *i915_vma_tryget(struct i915_vma *vma)
{
	if (likely(kref_get_unless_zero(&vma->obj->base.refcount)))
		return vma;

	return NULL;
}

static inline void i915_vma_put(struct i915_vma *vma)
{
	i915_gem_object_put(vma->obj);
}

static __always_inline ptrdiff_t ptrdiff(const void *a, const void *b)
{
	return a - b;
}

static inline long
i915_vma_compare(struct i915_vma *vma,
		 struct i915_address_space *vm,
		 const struct i915_ggtt_view *view)
{
	ptrdiff_t cmp;

	GEM_BUG_ON(view && !i915_is_ggtt(vm));

	cmp = ptrdiff(vma->vm, vm);
	if (cmp)
		return cmp;

	BUILD_BUG_ON(I915_GGTT_VIEW_NORMAL != 0);
	cmp = vma->ggtt_view.type;
	if (!view)
		return cmp;

	cmp -= view->type;
	if (cmp)
		return cmp;

	assert_i915_gem_gtt_types();

	/* ggtt_view.type also encodes its size so that we both distinguish
	 * different views using it as a "type" and also use a compact (no
	 * accessing of uninitialised padding bytes) memcmp without storing
	 * an extra parameter or adding more code.
	 *
	 * To ensure that the memcmp is valid for all branches of the union,
	 * even though the code looks like it is just comparing one branch,
	 * we assert above that all branches have the same address, and that
	 * each branch has a unique type/size.
	 */
	BUILD_BUG_ON(I915_GGTT_VIEW_NORMAL >= I915_GGTT_VIEW_PARTIAL);
	BUILD_BUG_ON(I915_GGTT_VIEW_PARTIAL >= I915_GGTT_VIEW_ROTATED);
	BUILD_BUG_ON(I915_GGTT_VIEW_ROTATED >= I915_GGTT_VIEW_REMAPPED);
	BUILD_BUG_ON(offsetof(typeof(*view), rotated) !=
		     offsetof(typeof(*view), partial));
	BUILD_BUG_ON(offsetof(typeof(*view), rotated) !=
		     offsetof(typeof(*view), remapped));
	return memcmp(&vma->ggtt_view.partial, &view->partial, view->type);
}

struct i915_vma_work *i915_vma_work(void);
int i915_vma_bind(struct i915_vma *vma,
		  enum i915_cache_level cache_level,
		  u32 flags,
		  struct i915_vma_work *work);

bool i915_gem_valid_gtt_space(struct i915_vma *vma, unsigned long color);
bool i915_vma_misplaced(const struct i915_vma *vma,
			u64 size, u64 alignment, u64 flags);
void __i915_vma_set_map_and_fenceable(struct i915_vma *vma);
void i915_vma_revoke_mmap(struct i915_vma *vma);
int __i915_vma_unbind(struct i915_vma *vma);
int __must_check i915_vma_unbind(struct i915_vma *vma);
void i915_vma_unlink_ctx(struct i915_vma *vma);
void i915_vma_close(struct i915_vma *vma);
void i915_vma_reopen(struct i915_vma *vma);

static inline struct i915_vma *__i915_vma_get(struct i915_vma *vma)
{
	if (kref_get_unless_zero(&vma->ref))
		return vma;

	return NULL;
}

void i915_vma_release(struct kref *ref);
static inline void __i915_vma_put(struct i915_vma *vma)
{
	kref_put(&vma->ref, i915_vma_release);
}

#define assert_vma_held(vma) dma_resv_assert_held((vma)->resv)

static inline void i915_vma_lock(struct i915_vma *vma)
{
	dma_resv_lock(vma->resv, NULL);
}

static inline void i915_vma_unlock(struct i915_vma *vma)
{
	dma_resv_unlock(vma->resv);
}

int __must_check
i915_vma_pin(struct i915_vma *vma, u64 size, u64 alignment, u64 flags);
int i915_ggtt_pin(struct i915_vma *vma, u32 align, unsigned int flags);

static inline int i915_vma_pin_count(const struct i915_vma *vma)
{
	return atomic_read(&vma->flags) & I915_VMA_PIN_MASK;
}

static inline bool i915_vma_is_pinned(const struct i915_vma *vma)
{
	return i915_vma_pin_count(vma);
}

static inline void __i915_vma_pin(struct i915_vma *vma)
{
	atomic_inc(&vma->flags);
	GEM_BUG_ON(!i915_vma_is_pinned(vma));
}

static inline void __i915_vma_unpin(struct i915_vma *vma)
{
	GEM_BUG_ON(!i915_vma_is_pinned(vma));
	atomic_dec(&vma->flags);
}

static inline void i915_vma_unpin(struct i915_vma *vma)
{
	GEM_BUG_ON(!drm_mm_node_allocated(&vma->node));
	__i915_vma_unpin(vma);
}

static inline bool i915_vma_is_bound(const struct i915_vma *vma,
				     unsigned int where)
{
	return atomic_read(&vma->flags) & where;
}

static inline bool i915_node_color_differs(const struct drm_mm_node *node,
					   unsigned long color)
{
	return drm_mm_node_allocated(node) && node->color != color;
}

/**
 * i915_vma_pin_iomap - calls ioremap_wc to map the GGTT VMA via the aperture
 * @vma: VMA to iomap
 *
 * The passed in VMA has to be pinned in the global GTT mappable region.
 * An extra pinning of the VMA is acquired for the return iomapping,
 * the caller must call i915_vma_unpin_iomap to relinquish the pinning
 * after the iomapping is no longer required.
 *
 * Returns a valid iomapped pointer or ERR_PTR.
 */
void __iomem *i915_vma_pin_iomap(struct i915_vma *vma);
#define IO_ERR_PTR(x) ((void __iomem *)ERR_PTR(x))

/**
 * i915_vma_unpin_iomap - unpins the mapping returned from i915_vma_iomap
 * @vma: VMA to unpin
 *
 * Unpins the previously iomapped VMA from i915_vma_pin_iomap().
 *
 * This function is only valid to be called on a VMA previously
 * iomapped by the caller with i915_vma_pin_iomap().
 */
void i915_vma_unpin_iomap(struct i915_vma *vma);

static inline struct page *i915_vma_first_page(struct i915_vma *vma)
{
	GEM_BUG_ON(!vma->pages);
	return sg_page(vma->pages->sgl);
}

/**
 * i915_vma_pin_fence - pin fencing state
 * @vma: vma to pin fencing for
 *
 * This pins the fencing state (whether tiled or untiled) to make sure the
 * vma (and its object) is ready to be used as a scanout target. Fencing
 * status must be synchronize first by calling i915_vma_get_fence():
 *
 * The resulting fence pin reference must be released again with
 * i915_vma_unpin_fence().
 *
 * Returns:
 *
 * True if the vma has a fence, false otherwise.
 */
int __must_check i915_vma_pin_fence(struct i915_vma *vma);
int __must_check i915_vma_revoke_fence(struct i915_vma *vma);

int __i915_vma_pin_fence(struct i915_vma *vma);

static inline void __i915_vma_unpin_fence(struct i915_vma *vma)
{
	GEM_BUG_ON(atomic_read(&vma->fence->pin_count) <= 0);
	atomic_dec(&vma->fence->pin_count);
}

/**
 * i915_vma_unpin_fence - unpin fencing state
 * @vma: vma to unpin fencing for
 *
 * This releases the fence pin reference acquired through
 * i915_vma_pin_fence. It will handle both objects with and without an
 * attached fence correctly, callers do not need to distinguish this.
 */
static inline void
i915_vma_unpin_fence(struct i915_vma *vma)
{
	if (vma->fence)
		__i915_vma_unpin_fence(vma);
}

void i915_vma_parked(struct intel_gt *gt);

#define for_each_until(cond) if (cond) break; else

/**
 * for_each_ggtt_vma - Iterate over the GGTT VMA belonging to an object.
 * @V: the #i915_vma iterator
 * @OBJ: the #drm_i915_gem_object
 *
 * GGTT VMA are placed at the being of the object's vma_list, see
 * vma_create(), so we can stop our walk as soon as we see a ppgtt VMA,
 * or the list is empty ofc.
 */
#define for_each_ggtt_vma(V, OBJ) \
	list_for_each_entry(V, &(OBJ)->vma.list, obj_link)		\
		for_each_until(!i915_vma_is_ggtt(V))

struct i915_vma *i915_vma_alloc(void);
void i915_vma_free(struct i915_vma *vma);

struct i915_vma *i915_vma_make_unshrinkable(struct i915_vma *vma);
void i915_vma_make_shrinkable(struct i915_vma *vma);
void i915_vma_make_purgeable(struct i915_vma *vma);

static inline int i915_vma_sync(struct i915_vma *vma)
{
	/* Wait for the asynchronous bindings and pending GPU reads */
	return i915_active_wait(&vma->active);
}

#endif
