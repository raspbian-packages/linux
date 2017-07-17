/*
 * Copyright © 2014 Intel Corporation
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
#include <linux/circ_buf.h>
#include "i915_drv.h"
#include "intel_uc.h"

/**
 * DOC: GuC-based command submission
 *
 * i915_guc_client:
 * We use the term client to avoid confusion with contexts. A i915_guc_client is
 * equivalent to GuC object guc_context_desc. This context descriptor is
 * allocated from a pool of 1024 entries. Kernel driver will allocate doorbell
 * and workqueue for it. Also the process descriptor (guc_process_desc), which
 * is mapped to client space. So the client can write Work Item then ring the
 * doorbell.
 *
 * To simplify the implementation, we allocate one gem object that contains all
 * pages for doorbell, process descriptor and workqueue.
 *
 * The Scratch registers:
 * There are 16 MMIO-based registers start from 0xC180. The kernel driver writes
 * a value to the action register (SOFT_SCRATCH_0) along with any data. It then
 * triggers an interrupt on the GuC via another register write (0xC4C8).
 * Firmware writes a success/fail code back to the action register after
 * processes the request. The kernel driver polls waiting for this update and
 * then proceeds.
 * See intel_guc_send()
 *
 * Doorbells:
 * Doorbells are interrupts to uKernel. A doorbell is a single cache line (QW)
 * mapped into process space.
 *
 * Work Items:
 * There are several types of work items that the host may place into a
 * workqueue, each with its own requirements and limitations. Currently only
 * WQ_TYPE_INORDER is needed to support legacy submission via GuC, which
 * represents in-order queue. The kernel driver packs ring tail pointer and an
 * ELSP context descriptor dword into Work Item.
 * See guc_wq_item_append()
 *
 */

/*
 * Tell the GuC to allocate or deallocate a specific doorbell
 */

static int guc_allocate_doorbell(struct intel_guc *guc,
				 struct i915_guc_client *client)
{
	u32 action[] = {
		INTEL_GUC_ACTION_ALLOCATE_DOORBELL,
		client->ctx_index
	};

	return intel_guc_send(guc, action, ARRAY_SIZE(action));
}

static int guc_release_doorbell(struct intel_guc *guc,
				struct i915_guc_client *client)
{
	u32 action[] = {
		INTEL_GUC_ACTION_DEALLOCATE_DOORBELL,
		client->ctx_index
	};

	return intel_guc_send(guc, action, ARRAY_SIZE(action));
}

/*
 * Initialise, update, or clear doorbell data shared with the GuC
 *
 * These functions modify shared data and so need access to the mapped
 * client object which contains the page being used for the doorbell
 */

static int guc_update_doorbell_id(struct intel_guc *guc,
				  struct i915_guc_client *client,
				  u16 new_id)
{
	struct sg_table *sg = guc->ctx_pool_vma->pages;
	void *doorbell_bitmap = guc->doorbell_bitmap;
	struct guc_doorbell_info *doorbell;
	struct guc_context_desc desc;
	size_t len;

	doorbell = client->vaddr + client->doorbell_offset;

	if (client->doorbell_id != GUC_INVALID_DOORBELL_ID &&
	    test_bit(client->doorbell_id, doorbell_bitmap)) {
		/* Deactivate the old doorbell */
		doorbell->db_status = GUC_DOORBELL_DISABLED;
		(void)guc_release_doorbell(guc, client);
		__clear_bit(client->doorbell_id, doorbell_bitmap);
	}

	/* Update the GuC's idea of the doorbell ID */
	len = sg_pcopy_to_buffer(sg->sgl, sg->nents, &desc, sizeof(desc),
			     sizeof(desc) * client->ctx_index);
	if (len != sizeof(desc))
		return -EFAULT;
	desc.db_id = new_id;
	len = sg_pcopy_from_buffer(sg->sgl, sg->nents, &desc, sizeof(desc),
			     sizeof(desc) * client->ctx_index);
	if (len != sizeof(desc))
		return -EFAULT;

	client->doorbell_id = new_id;
	if (new_id == GUC_INVALID_DOORBELL_ID)
		return 0;

	/* Activate the new doorbell */
	__set_bit(new_id, doorbell_bitmap);
	doorbell->db_status = GUC_DOORBELL_ENABLED;
	doorbell->cookie = client->doorbell_cookie;
	return guc_allocate_doorbell(guc, client);
}

static void guc_disable_doorbell(struct intel_guc *guc,
				 struct i915_guc_client *client)
{
	(void)guc_update_doorbell_id(guc, client, GUC_INVALID_DOORBELL_ID);

	/* XXX: wait for any interrupts */
	/* XXX: wait for workqueue to drain */
}

static uint16_t
select_doorbell_register(struct intel_guc *guc, uint32_t priority)
{
	/*
	 * The bitmap tracks which doorbell registers are currently in use.
	 * It is split into two halves; the first half is used for normal
	 * priority contexts, the second half for high-priority ones.
	 * Note that logically higher priorities are numerically less than
	 * normal ones, so the test below means "is it high-priority?"
	 */
	const bool hi_pri = (priority <= GUC_CTX_PRIORITY_HIGH);
	const uint16_t half = GUC_MAX_DOORBELLS / 2;
	const uint16_t start = hi_pri ? half : 0;
	const uint16_t end = start + half;
	uint16_t id;

	id = find_next_zero_bit(guc->doorbell_bitmap, end, start);
	if (id == end)
		id = GUC_INVALID_DOORBELL_ID;

	DRM_DEBUG_DRIVER("assigned %s priority doorbell id 0x%x\n",
			hi_pri ? "high" : "normal", id);

	return id;
}

/*
 * Select, assign and relase doorbell cachelines
 *
 * These functions track which doorbell cachelines are in use.
 * The data they manipulate is protected by the intel_guc_send lock.
 */

static uint32_t select_doorbell_cacheline(struct intel_guc *guc)
{
	const uint32_t cacheline_size = cache_line_size();
	uint32_t offset;

	/* Doorbell uses a single cache line within a page */
	offset = offset_in_page(guc->db_cacheline);

	/* Moving to next cache line to reduce contention */
	guc->db_cacheline += cacheline_size;

	DRM_DEBUG_DRIVER("selected doorbell cacheline 0x%x, next 0x%x, linesize %u\n",
			offset, guc->db_cacheline, cacheline_size);

	return offset;
}

/*
 * Initialise the process descriptor shared with the GuC firmware.
 */
static void guc_proc_desc_init(struct intel_guc *guc,
			       struct i915_guc_client *client)
{
	struct guc_process_desc *desc;

	desc = client->vaddr + client->proc_desc_offset;

	memset(desc, 0, sizeof(*desc));

	/*
	 * XXX: pDoorbell and WQVBaseAddress are pointers in process address
	 * space for ring3 clients (set them as in mmap_ioctl) or kernel
	 * space for kernel clients (map on demand instead? May make debug
	 * easier to have it mapped).
	 */
	desc->wq_base_addr = 0;
	desc->db_base_addr = 0;

	desc->context_id = client->ctx_index;
	desc->wq_size_bytes = client->wq_size;
	desc->wq_status = WQ_STATUS_ACTIVE;
	desc->priority = client->priority;
}

/*
 * Initialise/clear the context descriptor shared with the GuC firmware.
 *
 * This descriptor tells the GuC where (in GGTT space) to find the important
 * data structures relating to this client (doorbell, process descriptor,
 * write queue, etc).
 */

static void guc_ctx_desc_init(struct intel_guc *guc,
			      struct i915_guc_client *client)
{
	struct drm_i915_private *dev_priv = guc_to_i915(guc);
	struct intel_engine_cs *engine;
	struct i915_gem_context *ctx = client->owner;
	struct guc_context_desc desc;
	struct sg_table *sg;
	unsigned int tmp;
	u32 gfx_addr;

	memset(&desc, 0, sizeof(desc));

	desc.attribute = GUC_CTX_DESC_ATTR_ACTIVE | GUC_CTX_DESC_ATTR_KERNEL;
	desc.context_id = client->ctx_index;
	desc.priority = client->priority;
	desc.db_id = client->doorbell_id;

	for_each_engine_masked(engine, dev_priv, client->engines, tmp) {
		struct intel_context *ce = &ctx->engine[engine->id];
		uint32_t guc_engine_id = engine->guc_id;
		struct guc_execlist_context *lrc = &desc.lrc[guc_engine_id];

		/* TODO: We have a design issue to be solved here. Only when we
		 * receive the first batch, we know which engine is used by the
		 * user. But here GuC expects the lrc and ring to be pinned. It
		 * is not an issue for default context, which is the only one
		 * for now who owns a GuC client. But for future owner of GuC
		 * client, need to make sure lrc is pinned prior to enter here.
		 */
		if (!ce->state)
			break;	/* XXX: continue? */

		lrc->context_desc = lower_32_bits(ce->lrc_desc);

		/* The state page is after PPHWSP */
		lrc->ring_lcra =
			guc_ggtt_offset(ce->state) + LRC_STATE_PN * PAGE_SIZE;
		lrc->context_id = (client->ctx_index << GUC_ELC_CTXID_OFFSET) |
				(guc_engine_id << GUC_ELC_ENGINE_OFFSET);

		lrc->ring_begin = guc_ggtt_offset(ce->ring->vma);
		lrc->ring_end = lrc->ring_begin + ce->ring->size - 1;
		lrc->ring_next_free_location = lrc->ring_begin;
		lrc->ring_current_tail_pointer_value = 0;

		desc.engines_used |= (1 << guc_engine_id);
	}

	DRM_DEBUG_DRIVER("Host engines 0x%x => GuC engines used 0x%x\n",
			client->engines, desc.engines_used);
	WARN_ON(desc.engines_used == 0);

	/*
	 * The doorbell, process descriptor, and workqueue are all parts
	 * of the client object, which the GuC will reference via the GGTT
	 */
	gfx_addr = guc_ggtt_offset(client->vma);
	desc.db_trigger_phy = sg_dma_address(client->vma->pages->sgl) +
				client->doorbell_offset;
	desc.db_trigger_cpu =
		(uintptr_t)client->vaddr + client->doorbell_offset;
	desc.db_trigger_uk = gfx_addr + client->doorbell_offset;
	desc.process_desc = gfx_addr + client->proc_desc_offset;
	desc.wq_addr = gfx_addr + client->wq_offset;
	desc.wq_size = client->wq_size;

	/*
	 * XXX: Take LRCs from an existing context if this is not an
	 * IsKMDCreatedContext client
	 */
	desc.desc_private = (uintptr_t)client;

	/* Pool context is pinned already */
	sg = guc->ctx_pool_vma->pages;
	sg_pcopy_from_buffer(sg->sgl, sg->nents, &desc, sizeof(desc),
			     sizeof(desc) * client->ctx_index);
}

static void guc_ctx_desc_fini(struct intel_guc *guc,
			      struct i915_guc_client *client)
{
	struct guc_context_desc desc;
	struct sg_table *sg;

	memset(&desc, 0, sizeof(desc));

	sg = guc->ctx_pool_vma->pages;
	sg_pcopy_from_buffer(sg->sgl, sg->nents, &desc, sizeof(desc),
			     sizeof(desc) * client->ctx_index);
}

/**
 * i915_guc_wq_reserve() - reserve space in the GuC's workqueue
 * @request:	request associated with the commands
 *
 * Return:	0 if space is available
 *		-EAGAIN if space is not currently available
 *
 * This function must be called (and must return 0) before a request
 * is submitted to the GuC via i915_guc_submit() below. Once a result
 * of 0 has been returned, it must be balanced by a corresponding
 * call to submit().
 *
 * Reservation allows the caller to determine in advance that space
 * will be available for the next submission before committing resources
 * to it, and helps avoid late failures with complicated recovery paths.
 */
int i915_guc_wq_reserve(struct drm_i915_gem_request *request)
{
	const size_t wqi_size = sizeof(struct guc_wq_item);
	struct i915_guc_client *client = request->i915->guc.execbuf_client;
	struct guc_process_desc *desc = client->vaddr +
					client->proc_desc_offset;
	u32 freespace;
	int ret;

	spin_lock(&client->wq_lock);
	freespace = CIRC_SPACE(client->wq_tail, desc->head, client->wq_size);
	freespace -= client->wq_rsvd;
	if (likely(freespace >= wqi_size)) {
		client->wq_rsvd += wqi_size;
		ret = 0;
	} else {
		client->no_wq_space++;
		ret = -EAGAIN;
	}
	spin_unlock(&client->wq_lock);

	return ret;
}

void i915_guc_wq_unreserve(struct drm_i915_gem_request *request)
{
	const size_t wqi_size = sizeof(struct guc_wq_item);
	struct i915_guc_client *client = request->i915->guc.execbuf_client;

	GEM_BUG_ON(READ_ONCE(client->wq_rsvd) < wqi_size);

	spin_lock(&client->wq_lock);
	client->wq_rsvd -= wqi_size;
	spin_unlock(&client->wq_lock);
}

/* Construct a Work Item and append it to the GuC's Work Queue */
static void guc_wq_item_append(struct i915_guc_client *client,
			       struct drm_i915_gem_request *rq)
{
	/* wqi_len is in DWords, and does not include the one-word header */
	const size_t wqi_size = sizeof(struct guc_wq_item);
	const u32 wqi_len = wqi_size/sizeof(u32) - 1;
	struct intel_engine_cs *engine = rq->engine;
	struct guc_process_desc *desc;
	struct guc_wq_item *wqi;
	u32 freespace, tail, wq_off;

	desc = client->vaddr + client->proc_desc_offset;

	/* Free space is guaranteed, see i915_guc_wq_reserve() above */
	freespace = CIRC_SPACE(client->wq_tail, desc->head, client->wq_size);
	GEM_BUG_ON(freespace < wqi_size);

	/* The GuC firmware wants the tail index in QWords, not bytes */
	tail = rq->tail;
	GEM_BUG_ON(tail & 7);
	tail >>= 3;
	GEM_BUG_ON(tail > WQ_RING_TAIL_MAX);

	/* For now workqueue item is 4 DWs; workqueue buffer is 2 pages. So we
	 * should not have the case where structure wqi is across page, neither
	 * wrapped to the beginning. This simplifies the implementation below.
	 *
	 * XXX: if not the case, we need save data to a temp wqi and copy it to
	 * workqueue buffer dw by dw.
	 */
	BUILD_BUG_ON(wqi_size != 16);
	GEM_BUG_ON(client->wq_rsvd < wqi_size);

	/* postincrement WQ tail for next time */
	wq_off = client->wq_tail;
	GEM_BUG_ON(wq_off & (wqi_size - 1));
	client->wq_tail += wqi_size;
	client->wq_tail &= client->wq_size - 1;
	client->wq_rsvd -= wqi_size;

	/* WQ starts from the page after doorbell / process_desc */
	wqi = client->vaddr + wq_off + GUC_DB_SIZE;

	/* Now fill in the 4-word work queue item */
	wqi->header = WQ_TYPE_INORDER |
			(wqi_len << WQ_LEN_SHIFT) |
			(engine->guc_id << WQ_TARGET_SHIFT) |
			WQ_NO_WCFLUSH_WAIT;

	/* The GuC wants only the low-order word of the context descriptor */
	wqi->context_desc = (u32)intel_lr_context_descriptor(rq->ctx, engine);

	wqi->ring_tail = tail << WQ_RING_TAIL_SHIFT;
	wqi->fence_id = rq->global_seqno;
}

static int guc_ring_doorbell(struct i915_guc_client *client)
{
	struct guc_process_desc *desc;
	union guc_doorbell_qw db_cmp, db_exc, db_ret;
	union guc_doorbell_qw *db;
	int attempt = 2, ret = -EAGAIN;

	desc = client->vaddr + client->proc_desc_offset;

	/* Update the tail so it is visible to GuC */
	desc->tail = client->wq_tail;

	/* current cookie */
	db_cmp.db_status = GUC_DOORBELL_ENABLED;
	db_cmp.cookie = client->doorbell_cookie;

	/* cookie to be updated */
	db_exc.db_status = GUC_DOORBELL_ENABLED;
	db_exc.cookie = client->doorbell_cookie + 1;
	if (db_exc.cookie == 0)
		db_exc.cookie = 1;

	/* pointer of current doorbell cacheline */
	db = client->vaddr + client->doorbell_offset;

	while (attempt--) {
		/* lets ring the doorbell */
		db_ret.value_qw = atomic64_cmpxchg((atomic64_t *)db,
			db_cmp.value_qw, db_exc.value_qw);

		/* if the exchange was successfully executed */
		if (db_ret.value_qw == db_cmp.value_qw) {
			/* db was successfully rung */
			client->doorbell_cookie = db_exc.cookie;
			ret = 0;
			break;
		}

		/* XXX: doorbell was lost and need to acquire it again */
		if (db_ret.db_status == GUC_DOORBELL_DISABLED)
			break;

		DRM_WARN("Cookie mismatch. Expected %d, found %d\n",
			 db_cmp.cookie, db_ret.cookie);

		/* update the cookie to newly read cookie from GuC */
		db_cmp.cookie = db_ret.cookie;
		db_exc.cookie = db_ret.cookie + 1;
		if (db_exc.cookie == 0)
			db_exc.cookie = 1;
	}

	return ret;
}

/**
 * __i915_guc_submit() - Submit commands through GuC
 * @rq:		request associated with the commands
 *
 * The caller must have already called i915_guc_wq_reserve() above with
 * a result of 0 (success), guaranteeing that there is space in the work
 * queue for the new request, so enqueuing the item cannot fail.
 *
 * Bad Things Will Happen if the caller violates this protocol e.g. calls
 * submit() when _reserve() says there's no space, or calls _submit()
 * a different number of times from (successful) calls to _reserve().
 *
 * The only error here arises if the doorbell hardware isn't functioning
 * as expected, which really shouln't happen.
 */
static void __i915_guc_submit(struct drm_i915_gem_request *rq)
{
	struct drm_i915_private *dev_priv = rq->i915;
	struct intel_engine_cs *engine = rq->engine;
	unsigned int engine_id = engine->id;
	struct intel_guc *guc = &rq->i915->guc;
	struct i915_guc_client *client = guc->execbuf_client;
	int b_ret;

	spin_lock(&client->wq_lock);
	guc_wq_item_append(client, rq);

	/* WA to flush out the pending GMADR writes to ring buffer. */
	if (i915_vma_is_map_and_fenceable(rq->ring->vma))
		POSTING_READ_FW(GUC_STATUS);

	b_ret = guc_ring_doorbell(client);

	client->submissions[engine_id] += 1;
	client->retcode = b_ret;
	if (b_ret)
		client->b_fail += 1;

	guc->submissions[engine_id] += 1;
	guc->last_seqno[engine_id] = rq->global_seqno;
	spin_unlock(&client->wq_lock);
}

static void i915_guc_submit(struct drm_i915_gem_request *rq)
{
	i915_gem_request_submit(rq);
	__i915_guc_submit(rq);
}

/*
 * Everything below here is concerned with setup & teardown, and is
 * therefore not part of the somewhat time-critical batch-submission
 * path of i915_guc_submit() above.
 */

/**
 * intel_guc_allocate_vma() - Allocate a GGTT VMA for GuC usage
 * @guc:	the guc
 * @size:	size of area to allocate (both virtual space and memory)
 *
 * This is a wrapper to create an object for use with the GuC. In order to
 * use it inside the GuC, an object needs to be pinned lifetime, so we allocate
 * both some backing storage and a range inside the Global GTT. We must pin
 * it in the GGTT somewhere other than than [0, GUC_WOPCM_TOP) because that
 * range is reserved inside GuC.
 *
 * Return:	A i915_vma if successful, otherwise an ERR_PTR.
 */
struct i915_vma *intel_guc_allocate_vma(struct intel_guc *guc, u32 size)
{
	struct drm_i915_private *dev_priv = guc_to_i915(guc);
	struct drm_i915_gem_object *obj;
	struct i915_vma *vma;
	int ret;

	obj = i915_gem_object_create(dev_priv, size);
	if (IS_ERR(obj))
		return ERR_CAST(obj);

	vma = i915_vma_instance(obj, &dev_priv->ggtt.base, NULL);
	if (IS_ERR(vma))
		goto err;

	ret = i915_vma_pin(vma, 0, PAGE_SIZE,
			   PIN_GLOBAL | PIN_OFFSET_BIAS | GUC_WOPCM_TOP);
	if (ret) {
		vma = ERR_PTR(ret);
		goto err;
	}

	return vma;

err:
	i915_gem_object_put(obj);
	return vma;
}

static void
guc_client_free(struct drm_i915_private *dev_priv,
		struct i915_guc_client *client)
{
	struct intel_guc *guc = &dev_priv->guc;

	if (!client)
		return;

	/*
	 * XXX: wait for any outstanding submissions before freeing memory.
	 * Be sure to drop any locks
	 */

	if (client->vaddr) {
		/*
		 * If we got as far as setting up a doorbell, make sure we
		 * shut it down before unmapping & deallocating the memory.
		 */
		guc_disable_doorbell(guc, client);

		i915_gem_object_unpin_map(client->vma->obj);
	}

	i915_vma_unpin_and_release(&client->vma);

	if (client->ctx_index != GUC_INVALID_CTX_ID) {
		guc_ctx_desc_fini(guc, client);
		ida_simple_remove(&guc->ctx_ids, client->ctx_index);
	}

	kfree(client);
}

/* Check that a doorbell register is in the expected state */
static bool guc_doorbell_check(struct intel_guc *guc, uint16_t db_id)
{
	struct drm_i915_private *dev_priv = guc_to_i915(guc);
	i915_reg_t drbreg = GEN8_DRBREGL(db_id);
	uint32_t value = I915_READ(drbreg);
	bool enabled = (value & GUC_DOORBELL_ENABLED) != 0;
	bool expected = test_bit(db_id, guc->doorbell_bitmap);

	if (enabled == expected)
		return true;

	DRM_DEBUG_DRIVER("Doorbell %d (reg 0x%x) 0x%x, should be %s\n",
			 db_id, drbreg.reg, value,
			 expected ? "active" : "inactive");

	return false;
}

/*
 * Borrow the first client to set up & tear down each unused doorbell
 * in turn, to ensure that all doorbell h/w is (re)initialised.
 */
static void guc_init_doorbell_hw(struct intel_guc *guc)
{
	struct i915_guc_client *client = guc->execbuf_client;
	uint16_t db_id;
	int i, err;

	guc_disable_doorbell(guc, client);

	for (i = 0; i < GUC_MAX_DOORBELLS; ++i) {
		/* Skip if doorbell is OK */
		if (guc_doorbell_check(guc, i))
			continue;

		err = guc_update_doorbell_id(guc, client, i);
		if (err)
			DRM_DEBUG_DRIVER("Doorbell %d update failed, err %d\n",
					i, err);
	}

	db_id = select_doorbell_register(guc, client->priority);
	WARN_ON(db_id == GUC_INVALID_DOORBELL_ID);

	err = guc_update_doorbell_id(guc, client, db_id);
	if (err)
		DRM_WARN("Failed to restore doorbell to %d, err %d\n",
			 db_id, err);

	/* Read back & verify all doorbell registers */
	for (i = 0; i < GUC_MAX_DOORBELLS; ++i)
		(void)guc_doorbell_check(guc, i);
}

/**
 * guc_client_alloc() - Allocate an i915_guc_client
 * @dev_priv:	driver private data structure
 * @engines:	The set of engines to enable for this client
 * @priority:	four levels priority _CRITICAL, _HIGH, _NORMAL and _LOW
 * 		The kernel client to replace ExecList submission is created with
 * 		NORMAL priority. Priority of a client for scheduler can be HIGH,
 * 		while a preemption context can use CRITICAL.
 * @ctx:	the context that owns the client (we use the default render
 * 		context)
 *
 * Return:	An i915_guc_client object if success, else NULL.
 */
static struct i915_guc_client *
guc_client_alloc(struct drm_i915_private *dev_priv,
		 uint32_t engines,
		 uint32_t priority,
		 struct i915_gem_context *ctx)
{
	struct i915_guc_client *client;
	struct intel_guc *guc = &dev_priv->guc;
	struct i915_vma *vma;
	void *vaddr;
	uint16_t db_id;

	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return NULL;

	client->owner = ctx;
	client->guc = guc;
	client->engines = engines;
	client->priority = priority;
	client->doorbell_id = GUC_INVALID_DOORBELL_ID;

	client->ctx_index = (uint32_t)ida_simple_get(&guc->ctx_ids, 0,
			GUC_MAX_GPU_CONTEXTS, GFP_KERNEL);
	if (client->ctx_index >= GUC_MAX_GPU_CONTEXTS) {
		client->ctx_index = GUC_INVALID_CTX_ID;
		goto err;
	}

	/* The first page is doorbell/proc_desc. Two followed pages are wq. */
	vma = intel_guc_allocate_vma(guc, GUC_DB_SIZE + GUC_WQ_SIZE);
	if (IS_ERR(vma))
		goto err;

	/* We'll keep just the first (doorbell/proc) page permanently kmap'd. */
	client->vma = vma;

	vaddr = i915_gem_object_pin_map(vma->obj, I915_MAP_WB);
	if (IS_ERR(vaddr))
		goto err;

	client->vaddr = vaddr;

	spin_lock_init(&client->wq_lock);
	client->wq_offset = GUC_DB_SIZE;
	client->wq_size = GUC_WQ_SIZE;

	db_id = select_doorbell_register(guc, client->priority);
	if (db_id == GUC_INVALID_DOORBELL_ID)
		/* XXX: evict a doorbell instead? */
		goto err;

	client->doorbell_offset = select_doorbell_cacheline(guc);

	/*
	 * Since the doorbell only requires a single cacheline, we can save
	 * space by putting the application process descriptor in the same
	 * page. Use the half of the page that doesn't include the doorbell.
	 */
	if (client->doorbell_offset >= (GUC_DB_SIZE / 2))
		client->proc_desc_offset = 0;
	else
		client->proc_desc_offset = (GUC_DB_SIZE / 2);

	guc_proc_desc_init(guc, client);
	guc_ctx_desc_init(guc, client);

	/* For runtime client allocation we need to enable the doorbell. Not
	 * required yet for the static execbuf_client as this special kernel
	 * client is enabled from i915_guc_submission_enable().
	 *
	 * guc_update_doorbell_id(guc, client, db_id);
	 */

	DRM_DEBUG_DRIVER("new priority %u client %p for engine(s) 0x%x: ctx_index %u\n",
		priority, client, client->engines, client->ctx_index);
	DRM_DEBUG_DRIVER("doorbell id %u, cacheline offset 0x%x\n",
		client->doorbell_id, client->doorbell_offset);

	return client;

err:
	guc_client_free(dev_priv, client);
	return NULL;
}



static void guc_policies_init(struct guc_policies *policies)
{
	struct guc_policy *policy;
	u32 p, i;

	policies->dpc_promote_time = 500000;
	policies->max_num_work_items = POLICY_MAX_NUM_WI;

	for (p = 0; p < GUC_CTX_PRIORITY_NUM; p++) {
		for (i = GUC_RENDER_ENGINE; i < GUC_MAX_ENGINES_NUM; i++) {
			policy = &policies->policy[p][i];

			policy->execution_quantum = 1000000;
			policy->preemption_time = 500000;
			policy->fault_time = 250000;
			policy->policy_flags = 0;
		}
	}

	policies->is_valid = 1;
}

static void guc_addon_create(struct intel_guc *guc)
{
	struct drm_i915_private *dev_priv = guc_to_i915(guc);
	struct i915_vma *vma;
	struct guc_ads *ads;
	struct guc_policies *policies;
	struct guc_mmio_reg_state *reg_state;
	struct intel_engine_cs *engine;
	enum intel_engine_id id;
	struct page *page;
	u32 size;

	/* The ads obj includes the struct itself and buffers passed to GuC */
	size = sizeof(struct guc_ads) + sizeof(struct guc_policies) +
			sizeof(struct guc_mmio_reg_state) +
			GUC_S3_SAVE_SPACE_PAGES * PAGE_SIZE;

	vma = guc->ads_vma;
	if (!vma) {
		vma = intel_guc_allocate_vma(guc, PAGE_ALIGN(size));
		if (IS_ERR(vma))
			return;

		guc->ads_vma = vma;
	}

	page = i915_vma_first_page(vma);
	ads = kmap(page);

	/*
	 * The GuC requires a "Golden Context" when it reinitialises
	 * engines after a reset. Here we use the Render ring default
	 * context, which must already exist and be pinned in the GGTT,
	 * so its address won't change after we've told the GuC where
	 * to find it.
	 */
	engine = dev_priv->engine[RCS];
	ads->golden_context_lrca = engine->status_page.ggtt_offset;

	for_each_engine(engine, dev_priv, id)
		ads->eng_state_size[engine->guc_id] = intel_lr_context_size(engine);

	/* GuC scheduling policies */
	policies = (void *)ads + sizeof(struct guc_ads);
	guc_policies_init(policies);

	ads->scheduler_policies =
		guc_ggtt_offset(vma) + sizeof(struct guc_ads);

	/* MMIO reg state */
	reg_state = (void *)policies + sizeof(struct guc_policies);

	for_each_engine(engine, dev_priv, id) {
		reg_state->mmio_white_list[engine->guc_id].mmio_start =
			engine->mmio_base + GUC_MMIO_WHITE_LIST_START;

		/* Nothing to be saved or restored for now. */
		reg_state->mmio_white_list[engine->guc_id].count = 0;
	}

	ads->reg_state_addr = ads->scheduler_policies +
			sizeof(struct guc_policies);

	ads->reg_state_buffer = ads->reg_state_addr +
			sizeof(struct guc_mmio_reg_state);

	kunmap(page);
}

/*
 * Set up the memory resources to be shared with the GuC.  At this point,
 * we require just one object that can be mapped through the GGTT.
 */
int i915_guc_submission_init(struct drm_i915_private *dev_priv)
{
	const size_t ctxsize = sizeof(struct guc_context_desc);
	const size_t poolsize = GUC_MAX_GPU_CONTEXTS * ctxsize;
	const size_t gemsize = round_up(poolsize, PAGE_SIZE);
	struct intel_guc *guc = &dev_priv->guc;
	struct i915_vma *vma;

	if (!HAS_GUC_SCHED(dev_priv))
		return 0;

	/* Wipe bitmap & delete client in case of reinitialisation */
	bitmap_clear(guc->doorbell_bitmap, 0, GUC_MAX_DOORBELLS);
	i915_guc_submission_disable(dev_priv);

	if (!i915.enable_guc_submission)
		return 0; /* not enabled  */

	if (guc->ctx_pool_vma)
		return 0; /* already allocated */

	vma = intel_guc_allocate_vma(guc, gemsize);
	if (IS_ERR(vma))
		return PTR_ERR(vma);

	guc->ctx_pool_vma = vma;
	ida_init(&guc->ctx_ids);
	intel_guc_log_create(guc);
	guc_addon_create(guc);

	guc->execbuf_client = guc_client_alloc(dev_priv,
					       INTEL_INFO(dev_priv)->ring_mask,
					       GUC_CTX_PRIORITY_KMD_NORMAL,
					       dev_priv->kernel_context);
	if (!guc->execbuf_client) {
		DRM_ERROR("Failed to create GuC client for execbuf!\n");
		goto err;
	}

	return 0;

err:
	i915_guc_submission_fini(dev_priv);
	return -ENOMEM;
}

static void guc_reset_wq(struct i915_guc_client *client)
{
	struct guc_process_desc *desc = client->vaddr +
					client->proc_desc_offset;

	desc->head = 0;
	desc->tail = 0;

	client->wq_tail = 0;
}

int i915_guc_submission_enable(struct drm_i915_private *dev_priv)
{
	struct intel_guc *guc = &dev_priv->guc;
	struct i915_guc_client *client = guc->execbuf_client;
	struct intel_engine_cs *engine;
	enum intel_engine_id id;

	if (!client)
		return -ENODEV;

	intel_guc_sample_forcewake(guc);

	guc_reset_wq(client);
	guc_init_doorbell_hw(guc);

	/* Take over from manual control of ELSP (execlists) */
	for_each_engine(engine, dev_priv, id) {
		struct drm_i915_gem_request *rq;

		engine->submit_request = i915_guc_submit;
		engine->schedule = NULL;

		/* Replay the current set of previously submitted requests */
		list_for_each_entry(rq, &engine->timeline->requests, link) {
			client->wq_rsvd += sizeof(struct guc_wq_item);
			__i915_guc_submit(rq);
		}
	}

	return 0;
}

void i915_guc_submission_disable(struct drm_i915_private *dev_priv)
{
	struct intel_guc *guc = &dev_priv->guc;

	if (!guc->execbuf_client)
		return;

	/* Revert back to manual ELSP submission */
	intel_execlists_enable_submission(dev_priv);
}

void i915_guc_submission_fini(struct drm_i915_private *dev_priv)
{
	struct intel_guc *guc = &dev_priv->guc;
	struct i915_guc_client *client;

	client = fetch_and_zero(&guc->execbuf_client);
	if (!client)
		return;

	guc_client_free(dev_priv, client);

	i915_vma_unpin_and_release(&guc->ads_vma);
	i915_vma_unpin_and_release(&guc->log.vma);

	if (guc->ctx_pool_vma)
		ida_destroy(&guc->ctx_ids);
	i915_vma_unpin_and_release(&guc->ctx_pool_vma);
}

/**
 * intel_guc_suspend() - notify GuC entering suspend state
 * @dev_priv:	i915 device private
 */
int intel_guc_suspend(struct drm_i915_private *dev_priv)
{
	struct intel_guc *guc = &dev_priv->guc;
	struct i915_gem_context *ctx;
	u32 data[3];

	if (guc->fw.load_status != INTEL_UC_FIRMWARE_SUCCESS)
		return 0;

	gen9_disable_guc_interrupts(dev_priv);

	ctx = dev_priv->kernel_context;

	data[0] = INTEL_GUC_ACTION_ENTER_S_STATE;
	/* any value greater than GUC_POWER_D0 */
	data[1] = GUC_POWER_D1;
	/* first page is shared data with GuC */
	data[2] = guc_ggtt_offset(ctx->engine[RCS].state);

	return intel_guc_send(guc, data, ARRAY_SIZE(data));
}


/**
 * intel_guc_resume() - notify GuC resuming from suspend state
 * @dev_priv:	i915 device private
 */
int intel_guc_resume(struct drm_i915_private *dev_priv)
{
	struct intel_guc *guc = &dev_priv->guc;
	struct i915_gem_context *ctx;
	u32 data[3];

	if (guc->fw.load_status != INTEL_UC_FIRMWARE_SUCCESS)
		return 0;

	if (i915.guc_log_level >= 0)
		gen9_enable_guc_interrupts(dev_priv);

	ctx = dev_priv->kernel_context;

	data[0] = INTEL_GUC_ACTION_EXIT_S_STATE;
	data[1] = GUC_POWER_D0;
	/* first page is shared data with GuC */
	data[2] = guc_ggtt_offset(ctx->engine[RCS].state);

	return intel_guc_send(guc, data, ARRAY_SIZE(data));
}


