// SPDX-License-Identifier: MIT
/*
 * Copyright © 2016-2019 Intel Corporation
 */

#include "i915_drv.h"
#include "intel_guc_ct.h"
#include "gt/intel_gt.h"

#define CT_ERROR(_ct, _fmt, ...) \
	DRM_DEV_ERROR(ct_to_dev(_ct), "CT: " _fmt, ##__VA_ARGS__)
#ifdef CONFIG_DRM_I915_DEBUG_GUC
#define CT_DEBUG(_ct, _fmt, ...) \
	DRM_DEV_DEBUG_DRIVER(ct_to_dev(_ct), "CT: " _fmt, ##__VA_ARGS__)
#else
#define CT_DEBUG(...)	do { } while (0)
#endif

struct ct_request {
	struct list_head link;
	u32 fence;
	u32 status;
	u32 response_len;
	u32 *response_buf;
};

struct ct_incoming_request {
	struct list_head link;
	u32 msg[];
};

enum { CTB_SEND = 0, CTB_RECV = 1 };

enum { CTB_OWNER_HOST = 0 };

static void ct_incoming_request_worker_func(struct work_struct *w);

/**
 * intel_guc_ct_init_early - Initialize CT state without requiring device access
 * @ct: pointer to CT struct
 */
void intel_guc_ct_init_early(struct intel_guc_ct *ct)
{
	spin_lock_init(&ct->requests.lock);
	INIT_LIST_HEAD(&ct->requests.pending);
	INIT_LIST_HEAD(&ct->requests.incoming);
	INIT_WORK(&ct->requests.worker, ct_incoming_request_worker_func);
}

static inline struct intel_guc *ct_to_guc(struct intel_guc_ct *ct)
{
	return container_of(ct, struct intel_guc, ct);
}

static inline struct intel_gt *ct_to_gt(struct intel_guc_ct *ct)
{
	return guc_to_gt(ct_to_guc(ct));
}

static inline struct drm_i915_private *ct_to_i915(struct intel_guc_ct *ct)
{
	return ct_to_gt(ct)->i915;
}

static inline struct device *ct_to_dev(struct intel_guc_ct *ct)
{
	return ct_to_i915(ct)->drm.dev;
}

static inline const char *guc_ct_buffer_type_to_str(u32 type)
{
	switch (type) {
	case INTEL_GUC_CT_BUFFER_TYPE_SEND:
		return "SEND";
	case INTEL_GUC_CT_BUFFER_TYPE_RECV:
		return "RECV";
	default:
		return "<invalid>";
	}
}

static void guc_ct_buffer_desc_init(struct guc_ct_buffer_desc *desc,
				    u32 cmds_addr, u32 size)
{
	memset(desc, 0, sizeof(*desc));
	desc->addr = cmds_addr;
	desc->size = size;
	desc->owner = CTB_OWNER_HOST;
}

static void guc_ct_buffer_desc_reset(struct guc_ct_buffer_desc *desc)
{
	desc->head = 0;
	desc->tail = 0;
	desc->is_in_error = 0;
}

static int guc_action_register_ct_buffer(struct intel_guc *guc,
					 u32 desc_addr,
					 u32 type)
{
	u32 action[] = {
		INTEL_GUC_ACTION_REGISTER_COMMAND_TRANSPORT_BUFFER,
		desc_addr,
		sizeof(struct guc_ct_buffer_desc),
		type
	};

	/* Can't use generic send(), CT registration must go over MMIO */
	return intel_guc_send_mmio(guc, action, ARRAY_SIZE(action), NULL, 0);
}

static int ct_register_buffer(struct intel_guc_ct *ct, u32 desc_addr, u32 type)
{
	int err = guc_action_register_ct_buffer(ct_to_guc(ct), desc_addr, type);

	if (unlikely(err))
		CT_ERROR(ct, "Failed to register %s buffer (err=%d)\n",
			 guc_ct_buffer_type_to_str(type), err);
	return err;
}

static int guc_action_deregister_ct_buffer(struct intel_guc *guc, u32 type)
{
	u32 action[] = {
		INTEL_GUC_ACTION_DEREGISTER_COMMAND_TRANSPORT_BUFFER,
		CTB_OWNER_HOST,
		type
	};

	/* Can't use generic send(), CT deregistration must go over MMIO */
	return intel_guc_send_mmio(guc, action, ARRAY_SIZE(action), NULL, 0);
}

static int ct_deregister_buffer(struct intel_guc_ct *ct, u32 type)
{
	int err = guc_action_deregister_ct_buffer(ct_to_guc(ct), type);

	if (unlikely(err))
		CT_ERROR(ct, "Failed to deregister %s buffer (err=%d)\n",
			 guc_ct_buffer_type_to_str(type), err);
	return err;
}

/**
 * intel_guc_ct_init - Init buffer-based communication
 * @ct: pointer to CT struct
 *
 * Allocate memory required for buffer-based communication.
 *
 * Return: 0 on success, a negative errno code on failure.
 */
int intel_guc_ct_init(struct intel_guc_ct *ct)
{
	struct intel_guc *guc = ct_to_guc(ct);
	void *blob;
	int err;
	int i;

	GEM_BUG_ON(ct->vma);

	/* We allocate 1 page to hold both descriptors and both buffers.
	 *       ___________.....................
	 *      |desc (SEND)|                   :
	 *      |___________|                   PAGE/4
	 *      :___________....................:
	 *      |desc (RECV)|                   :
	 *      |___________|                   PAGE/4
	 *      :_______________________________:
	 *      |cmds (SEND)                    |
	 *      |                               PAGE/4
	 *      |_______________________________|
	 *      |cmds (RECV)                    |
	 *      |                               PAGE/4
	 *      |_______________________________|
	 *
	 * Each message can use a maximum of 32 dwords and we don't expect to
	 * have more than 1 in flight at any time, so we have enough space.
	 * Some logic further ahead will rely on the fact that there is only 1
	 * page and that it is always mapped, so if the size is changed the
	 * other code will need updating as well.
	 */

	err = intel_guc_allocate_and_map_vma(guc, PAGE_SIZE, &ct->vma, &blob);
	if (unlikely(err)) {
		CT_ERROR(ct, "Failed to allocate CT channel (err=%d)\n", err);
		return err;
	}

	CT_DEBUG(ct, "vma base=%#x\n", intel_guc_ggtt_offset(guc, ct->vma));

	/* store pointers to desc and cmds */
	for (i = 0; i < ARRAY_SIZE(ct->ctbs); i++) {
		GEM_BUG_ON((i !=  CTB_SEND) && (i != CTB_RECV));
		ct->ctbs[i].desc = blob + PAGE_SIZE/4 * i;
		ct->ctbs[i].cmds = blob + PAGE_SIZE/4 * i + PAGE_SIZE/2;
	}

	return 0;
}

/**
 * intel_guc_ct_fini - Fini buffer-based communication
 * @ct: pointer to CT struct
 *
 * Deallocate memory required for buffer-based communication.
 */
void intel_guc_ct_fini(struct intel_guc_ct *ct)
{
	GEM_BUG_ON(ct->enabled);

	i915_vma_unpin_and_release(&ct->vma, I915_VMA_RELEASE_MAP);
}

/**
 * intel_guc_ct_enable - Enable buffer based command transport.
 * @ct: pointer to CT struct
 *
 * Return: 0 on success, a negative errno code on failure.
 */
int intel_guc_ct_enable(struct intel_guc_ct *ct)
{
	struct intel_guc *guc = ct_to_guc(ct);
	u32 base, cmds, size;
	int err;
	int i;

	GEM_BUG_ON(ct->enabled);

	/* vma should be already allocated and map'ed */
	GEM_BUG_ON(!ct->vma);
	base = intel_guc_ggtt_offset(guc, ct->vma);

	/* (re)initialize descriptors
	 * cmds buffers are in the second half of the blob page
	 */
	for (i = 0; i < ARRAY_SIZE(ct->ctbs); i++) {
		GEM_BUG_ON((i != CTB_SEND) && (i != CTB_RECV));
		cmds = base + PAGE_SIZE / 4 * i + PAGE_SIZE / 2;
		size = PAGE_SIZE / 4;
		CT_DEBUG(ct, "%d: addr=%#x size=%u\n", i, cmds, size);
		guc_ct_buffer_desc_init(ct->ctbs[i].desc, cmds, size);
	}

	/*
	 * Register both CT buffers starting with RECV buffer.
	 * Descriptors are in first half of the blob.
	 */
	err = ct_register_buffer(ct, base + PAGE_SIZE / 4 * CTB_RECV,
				 INTEL_GUC_CT_BUFFER_TYPE_RECV);
	if (unlikely(err))
		goto err_out;

	err = ct_register_buffer(ct, base + PAGE_SIZE / 4 * CTB_SEND,
				 INTEL_GUC_CT_BUFFER_TYPE_SEND);
	if (unlikely(err))
		goto err_deregister;

	ct->enabled = true;

	return 0;

err_deregister:
	ct_deregister_buffer(ct, INTEL_GUC_CT_BUFFER_TYPE_RECV);
err_out:
	CT_ERROR(ct, "Failed to open open CT channel (err=%d)\n", err);
	return err;
}

/**
 * intel_guc_ct_disable - Disable buffer based command transport.
 * @ct: pointer to CT struct
 */
void intel_guc_ct_disable(struct intel_guc_ct *ct)
{
	struct intel_guc *guc = ct_to_guc(ct);

	GEM_BUG_ON(!ct->enabled);

	ct->enabled = false;

	if (intel_guc_is_fw_running(guc)) {
		ct_deregister_buffer(ct, INTEL_GUC_CT_BUFFER_TYPE_SEND);
		ct_deregister_buffer(ct, INTEL_GUC_CT_BUFFER_TYPE_RECV);
	}
}

static u32 ct_get_next_fence(struct intel_guc_ct *ct)
{
	/* For now it's trivial */
	return ++ct->requests.last_fence;
}

/**
 * DOC: CTB Host to GuC request
 *
 * Format of the CTB Host to GuC request message is as follows::
 *
 *      +------------+---------+---------+---------+---------+
 *      |   msg[0]   |   [1]   |   [2]   |   ...   |  [n-1]  |
 *      +------------+---------+---------+---------+---------+
 *      |   MESSAGE  |       MESSAGE PAYLOAD                 |
 *      +   HEADER   +---------+---------+---------+---------+
 *      |            |    0    |    1    |   ...   |    n    |
 *      +============+=========+=========+=========+=========+
 *      |  len >= 1  |  FENCE  |     request specific data   |
 *      +------+-----+---------+---------+---------+---------+
 *
 *                   ^-----------------len-------------------^
 */

static int ct_write(struct intel_guc_ct *ct,
		    const u32 *action,
		    u32 len /* in dwords */,
		    u32 fence,
		    bool want_response)
{
	struct intel_guc_ct_buffer *ctb = &ct->ctbs[CTB_SEND];
	struct guc_ct_buffer_desc *desc = ctb->desc;
	u32 head = desc->head;
	u32 tail = desc->tail;
	u32 size = desc->size;
	u32 used;
	u32 header;
	u32 *cmds = ctb->cmds;
	unsigned int i;

	if (unlikely(desc->is_in_error))
		return -EPIPE;

	if (unlikely(!IS_ALIGNED(head | tail | size, 4) ||
		     (tail | head) >= size))
		goto corrupted;

	/* later calculations will be done in dwords */
	head /= 4;
	tail /= 4;
	size /= 4;

	/*
	 * tail == head condition indicates empty. GuC FW does not support
	 * using up the entire buffer to get tail == head meaning full.
	 */
	if (tail < head)
		used = (size - head) + tail;
	else
		used = tail - head;

	/* make sure there is a space including extra dw for the fence */
	if (unlikely(used + len + 1 >= size))
		return -ENOSPC;

	/*
	 * Write the message. The format is the following:
	 * DW0: header (including action code)
	 * DW1: fence
	 * DW2+: action data
	 */
	header = (len << GUC_CT_MSG_LEN_SHIFT) |
		 (GUC_CT_MSG_WRITE_FENCE_TO_DESC) |
		 (want_response ? GUC_CT_MSG_SEND_STATUS : 0) |
		 (action[0] << GUC_CT_MSG_ACTION_SHIFT);

	CT_DEBUG(ct, "writing %*ph %*ph %*ph\n",
		 4, &header, 4, &fence, 4 * (len - 1), &action[1]);

	cmds[tail] = header;
	tail = (tail + 1) % size;

	cmds[tail] = fence;
	tail = (tail + 1) % size;

	for (i = 1; i < len; i++) {
		cmds[tail] = action[i];
		tail = (tail + 1) % size;
	}
	GEM_BUG_ON(tail > size);

	/* now update desc tail (back in bytes) */
	desc->tail = tail * 4;
	return 0;

corrupted:
	CT_ERROR(ct, "Corrupted descriptor addr=%#x head=%u tail=%u size=%u\n",
		 desc->addr, desc->head, desc->tail, desc->size);
	desc->is_in_error = 1;
	return -EPIPE;
}

/**
 * wait_for_ctb_desc_update - Wait for the CT buffer descriptor update.
 * @desc:	buffer descriptor
 * @fence:	response fence
 * @status:	placeholder for status
 *
 * Guc will update CT buffer descriptor with new fence and status
 * after processing the command identified by the fence. Wait for
 * specified fence and then read from the descriptor status of the
 * command.
 *
 * Return:
 * *	0 response received (status is valid)
 * *	-ETIMEDOUT no response within hardcoded timeout
 * *	-EPROTO no response, CT buffer is in error
 */
static int wait_for_ctb_desc_update(struct guc_ct_buffer_desc *desc,
				    u32 fence,
				    u32 *status)
{
	int err;

	/*
	 * Fast commands should complete in less than 10us, so sample quickly
	 * up to that length of time, then switch to a slower sleep-wait loop.
	 * No GuC command should ever take longer than 10ms.
	 */
#define done (READ_ONCE(desc->fence) == fence)
	err = wait_for_us(done, 10);
	if (err)
		err = wait_for(done, 10);
#undef done

	if (unlikely(err)) {
		DRM_ERROR("CT: fence %u failed; reported fence=%u\n",
			  fence, desc->fence);

		if (WARN_ON(desc->is_in_error)) {
			/* Something went wrong with the messaging, try to reset
			 * the buffer and hope for the best
			 */
			guc_ct_buffer_desc_reset(desc);
			err = -EPROTO;
		}
	}

	*status = desc->status;
	return err;
}

/**
 * wait_for_ct_request_update - Wait for CT request state update.
 * @req:	pointer to pending request
 * @status:	placeholder for status
 *
 * For each sent request, Guc shall send bac CT response message.
 * Our message handler will update status of tracked request once
 * response message with given fence is received. Wait here and
 * check for valid response status value.
 *
 * Return:
 * *	0 response received (status is valid)
 * *	-ETIMEDOUT no response within hardcoded timeout
 */
static int wait_for_ct_request_update(struct ct_request *req, u32 *status)
{
	int err;

	/*
	 * Fast commands should complete in less than 10us, so sample quickly
	 * up to that length of time, then switch to a slower sleep-wait loop.
	 * No GuC command should ever take longer than 10ms.
	 */
#define done INTEL_GUC_MSG_IS_RESPONSE(READ_ONCE(req->status))
	err = wait_for_us(done, 10);
	if (err)
		err = wait_for(done, 10);
#undef done

	if (unlikely(err))
		DRM_ERROR("CT: fence %u err %d\n", req->fence, err);

	*status = req->status;
	return err;
}

static int ct_send(struct intel_guc_ct *ct,
		   const u32 *action,
		   u32 len,
		   u32 *response_buf,
		   u32 response_buf_size,
		   u32 *status)
{
	struct intel_guc_ct_buffer *ctb = &ct->ctbs[CTB_SEND];
	struct guc_ct_buffer_desc *desc = ctb->desc;
	struct ct_request request;
	unsigned long flags;
	u32 fence;
	int err;

	GEM_BUG_ON(!ct->enabled);
	GEM_BUG_ON(!len);
	GEM_BUG_ON(len & ~GUC_CT_MSG_LEN_MASK);
	GEM_BUG_ON(!response_buf && response_buf_size);

	fence = ct_get_next_fence(ct);
	request.fence = fence;
	request.status = 0;
	request.response_len = response_buf_size;
	request.response_buf = response_buf;

	spin_lock_irqsave(&ct->requests.lock, flags);
	list_add_tail(&request.link, &ct->requests.pending);
	spin_unlock_irqrestore(&ct->requests.lock, flags);

	err = ct_write(ct, action, len, fence, !!response_buf);
	if (unlikely(err))
		goto unlink;

	intel_guc_notify(ct_to_guc(ct));

	if (response_buf)
		err = wait_for_ct_request_update(&request, status);
	else
		err = wait_for_ctb_desc_update(desc, fence, status);
	if (unlikely(err))
		goto unlink;

	if (!INTEL_GUC_MSG_IS_RESPONSE_SUCCESS(*status)) {
		err = -EIO;
		goto unlink;
	}

	if (response_buf) {
		/* There shall be no data in the status */
		WARN_ON(INTEL_GUC_MSG_TO_DATA(request.status));
		/* Return actual response len */
		err = request.response_len;
	} else {
		/* There shall be no response payload */
		WARN_ON(request.response_len);
		/* Return data decoded from the status dword */
		err = INTEL_GUC_MSG_TO_DATA(*status);
	}

unlink:
	spin_lock_irqsave(&ct->requests.lock, flags);
	list_del(&request.link);
	spin_unlock_irqrestore(&ct->requests.lock, flags);

	return err;
}

/*
 * Command Transport (CT) buffer based GuC send function.
 */
int intel_guc_ct_send(struct intel_guc_ct *ct, const u32 *action, u32 len,
		      u32 *response_buf, u32 response_buf_size)
{
	struct intel_guc *guc = ct_to_guc(ct);
	u32 status = ~0; /* undefined */
	int ret;

	if (unlikely(!ct->enabled)) {
		WARN(1, "Unexpected send: action=%#x\n", *action);
		return -ENODEV;
	}

	mutex_lock(&guc->send_mutex);

	ret = ct_send(ct, action, len, response_buf, response_buf_size, &status);
	if (unlikely(ret < 0)) {
		CT_ERROR(ct, "Sending action %#x failed (err=%d status=%#X)\n",
			 action[0], ret, status);
	} else if (unlikely(ret)) {
		CT_DEBUG(ct, "send action %#x returned %d (%#x)\n",
			 action[0], ret, ret);
	}

	mutex_unlock(&guc->send_mutex);
	return ret;
}

static inline unsigned int ct_header_get_len(u32 header)
{
	return (header >> GUC_CT_MSG_LEN_SHIFT) & GUC_CT_MSG_LEN_MASK;
}

static inline unsigned int ct_header_get_action(u32 header)
{
	return (header >> GUC_CT_MSG_ACTION_SHIFT) & GUC_CT_MSG_ACTION_MASK;
}

static inline bool ct_header_is_response(u32 header)
{
	return !!(header & GUC_CT_MSG_IS_RESPONSE);
}

static int ct_read(struct intel_guc_ct *ct, u32 *data)
{
	struct intel_guc_ct_buffer *ctb = &ct->ctbs[CTB_RECV];
	struct guc_ct_buffer_desc *desc = ctb->desc;
	u32 head = desc->head;
	u32 tail = desc->tail;
	u32 size = desc->size;
	u32 *cmds = ctb->cmds;
	s32 available;
	unsigned int len;
	unsigned int i;

	if (unlikely(desc->is_in_error))
		return -EPIPE;

	if (unlikely(!IS_ALIGNED(head | tail | size, 4) ||
		     (tail | head) >= size))
		goto corrupted;

	/* later calculations will be done in dwords */
	head /= 4;
	tail /= 4;
	size /= 4;

	/* tail == head condition indicates empty */
	available = tail - head;
	if (unlikely(available == 0))
		return -ENODATA;

	/* beware of buffer wrap case */
	if (unlikely(available < 0))
		available += size;
	CT_DEBUG(ct, "available %d (%u:%u)\n", available, head, tail);
	GEM_BUG_ON(available < 0);

	data[0] = cmds[head];
	head = (head + 1) % size;

	/* message len with header */
	len = ct_header_get_len(data[0]) + 1;
	if (unlikely(len > (u32)available)) {
		CT_ERROR(ct, "Incomplete message %*ph %*ph %*ph\n",
			 4, data,
			 4 * (head + available - 1 > size ?
			      size - head : available - 1), &cmds[head],
			 4 * (head + available - 1 > size ?
			      available - 1 - size + head : 0), &cmds[0]);
		goto corrupted;
	}

	for (i = 1; i < len; i++) {
		data[i] = cmds[head];
		head = (head + 1) % size;
	}
	CT_DEBUG(ct, "received %*ph\n", 4 * len, data);

	desc->head = head * 4;
	return 0;

corrupted:
	CT_ERROR(ct, "Corrupted descriptor addr=%#x head=%u tail=%u size=%u\n",
		 desc->addr, desc->head, desc->tail, desc->size);
	desc->is_in_error = 1;
	return -EPIPE;
}

/**
 * DOC: CTB GuC to Host response
 *
 * Format of the CTB GuC to Host response message is as follows::
 *
 *      +------------+---------+---------+---------+---------+---------+
 *      |   msg[0]   |   [1]   |   [2]   |   [3]   |   ...   |  [n-1]  |
 *      +------------+---------+---------+---------+---------+---------+
 *      |   MESSAGE  |       MESSAGE PAYLOAD                           |
 *      +   HEADER   +---------+---------+---------+---------+---------+
 *      |            |    0    |    1    |    2    |   ...   |    n    |
 *      +============+=========+=========+=========+=========+=========+
 *      |  len >= 2  |  FENCE  |  STATUS |   response specific data    |
 *      +------+-----+---------+---------+---------+---------+---------+
 *
 *                   ^-----------------------len-----------------------^
 */

static int ct_handle_response(struct intel_guc_ct *ct, const u32 *msg)
{
	u32 header = msg[0];
	u32 len = ct_header_get_len(header);
	u32 msgsize = (len + 1) * sizeof(u32); /* msg size in bytes w/header */
	u32 fence;
	u32 status;
	u32 datalen;
	struct ct_request *req;
	bool found = false;

	GEM_BUG_ON(!ct_header_is_response(header));
	GEM_BUG_ON(!in_irq());

	/* Response payload shall at least include fence and status */
	if (unlikely(len < 2)) {
		CT_ERROR(ct, "Corrupted response %*ph\n", msgsize, msg);
		return -EPROTO;
	}

	fence = msg[1];
	status = msg[2];
	datalen = len - 2;

	/* Format of the status follows RESPONSE message */
	if (unlikely(!INTEL_GUC_MSG_IS_RESPONSE(status))) {
		CT_ERROR(ct, "Corrupted response %*ph\n", msgsize, msg);
		return -EPROTO;
	}

	CT_DEBUG(ct, "response fence %u status %#x\n", fence, status);

	spin_lock(&ct->requests.lock);
	list_for_each_entry(req, &ct->requests.pending, link) {
		if (unlikely(fence != req->fence)) {
			CT_DEBUG(ct, "request %u awaits response\n",
				 req->fence);
			continue;
		}
		if (unlikely(datalen > req->response_len)) {
			CT_ERROR(ct, "Response for %u is too long %*ph\n",
				 req->fence, msgsize, msg);
			datalen = 0;
		}
		if (datalen)
			memcpy(req->response_buf, msg + 3, 4 * datalen);
		req->response_len = datalen;
		WRITE_ONCE(req->status, status);
		found = true;
		break;
	}
	spin_unlock(&ct->requests.lock);

	if (!found)
		CT_ERROR(ct, "Unsolicited response %*ph\n", msgsize, msg);
	return 0;
}

static void ct_process_request(struct intel_guc_ct *ct,
			       u32 action, u32 len, const u32 *payload)
{
	struct intel_guc *guc = ct_to_guc(ct);
	int ret;

	CT_DEBUG(ct, "request %x %*ph\n", action, 4 * len, payload);

	switch (action) {
	case INTEL_GUC_ACTION_DEFAULT:
		ret = intel_guc_to_host_process_recv_msg(guc, payload, len);
		if (unlikely(ret))
			goto fail_unexpected;
		break;

	default:
fail_unexpected:
		CT_ERROR(ct, "Unexpected request %x %*ph\n",
			 action, 4 * len, payload);
		break;
	}
}

static bool ct_process_incoming_requests(struct intel_guc_ct *ct)
{
	unsigned long flags;
	struct ct_incoming_request *request;
	u32 header;
	u32 *payload;
	bool done;

	spin_lock_irqsave(&ct->requests.lock, flags);
	request = list_first_entry_or_null(&ct->requests.incoming,
					   struct ct_incoming_request, link);
	if (request)
		list_del(&request->link);
	done = !!list_empty(&ct->requests.incoming);
	spin_unlock_irqrestore(&ct->requests.lock, flags);

	if (!request)
		return true;

	header = request->msg[0];
	payload = &request->msg[1];
	ct_process_request(ct,
			   ct_header_get_action(header),
			   ct_header_get_len(header),
			   payload);

	kfree(request);
	return done;
}

static void ct_incoming_request_worker_func(struct work_struct *w)
{
	struct intel_guc_ct *ct =
		container_of(w, struct intel_guc_ct, requests.worker);
	bool done;

	done = ct_process_incoming_requests(ct);
	if (!done)
		queue_work(system_unbound_wq, &ct->requests.worker);
}

/**
 * DOC: CTB GuC to Host request
 *
 * Format of the CTB GuC to Host request message is as follows::
 *
 *      +------------+---------+---------+---------+---------+---------+
 *      |   msg[0]   |   [1]   |   [2]   |   [3]   |   ...   |  [n-1]  |
 *      +------------+---------+---------+---------+---------+---------+
 *      |   MESSAGE  |       MESSAGE PAYLOAD                           |
 *      +   HEADER   +---------+---------+---------+---------+---------+
 *      |            |    0    |    1    |    2    |   ...   |    n    |
 *      +============+=========+=========+=========+=========+=========+
 *      |     len    |            request specific data                |
 *      +------+-----+---------+---------+---------+---------+---------+
 *
 *                   ^-----------------------len-----------------------^
 */

static int ct_handle_request(struct intel_guc_ct *ct, const u32 *msg)
{
	u32 header = msg[0];
	u32 len = ct_header_get_len(header);
	u32 msgsize = (len + 1) * sizeof(u32); /* msg size in bytes w/header */
	struct ct_incoming_request *request;
	unsigned long flags;

	GEM_BUG_ON(ct_header_is_response(header));

	request = kmalloc(sizeof(*request) + msgsize, GFP_ATOMIC);
	if (unlikely(!request)) {
		CT_ERROR(ct, "Dropping request %*ph\n", msgsize, msg);
		return 0; /* XXX: -ENOMEM ? */
	}
	memcpy(request->msg, msg, msgsize);

	spin_lock_irqsave(&ct->requests.lock, flags);
	list_add_tail(&request->link, &ct->requests.incoming);
	spin_unlock_irqrestore(&ct->requests.lock, flags);

	queue_work(system_unbound_wq, &ct->requests.worker);
	return 0;
}

/*
 * When we're communicating with the GuC over CT, GuC uses events
 * to notify us about new messages being posted on the RECV buffer.
 */
void intel_guc_ct_event_handler(struct intel_guc_ct *ct)
{
	u32 msg[GUC_CT_MSG_LEN_MASK + 1]; /* one extra dw for the header */
	int err = 0;

	if (unlikely(!ct->enabled)) {
		WARN(1, "Unexpected GuC event received while CT disabled!\n");
		return;
	}

	do {
		err = ct_read(ct, msg);
		if (err)
			break;

		if (ct_header_is_response(msg[0]))
			err = ct_handle_response(ct, msg);
		else
			err = ct_handle_request(ct, msg);
	} while (!err);
}
