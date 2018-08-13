/*
 * Copyright (c) 2017, Mellanox Technologies inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <rdma/uverbs_std_types.h>
#include "rdma_core.h"
#include "uverbs.h"

static int uverbs_free_cq(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	struct ib_cq *cq = uobject->object;
	struct ib_uverbs_event_queue *ev_queue = cq->cq_context;
	struct ib_ucq_object *ucq =
		container_of(uobject, struct ib_ucq_object, uobject);
	int ret;

	ret = ib_destroy_cq(cq);
	if (!ret || why != RDMA_REMOVE_DESTROY)
		ib_uverbs_release_ucq(uobject->context->ufile, ev_queue ?
				      container_of(ev_queue,
						   struct ib_uverbs_completion_event_file,
						   ev_queue) : NULL,
				      ucq);
	return ret;
}

static int UVERBS_HANDLER(UVERBS_METHOD_CQ_CREATE)(struct ib_device *ib_dev,
						   struct ib_uverbs_file *file,
						   struct uverbs_attr_bundle *attrs)
{
	struct ib_ucontext *ucontext = file->ucontext;
	struct ib_ucq_object           *obj;
	struct ib_udata uhw;
	int ret;
	u64 user_handle;
	struct ib_cq_init_attr attr = {};
	struct ib_cq                   *cq;
	struct ib_uverbs_completion_event_file    *ev_file = NULL;
	const struct uverbs_attr *ev_file_attr;
	struct ib_uobject *ev_file_uobj;

	if (!(ib_dev->uverbs_cmd_mask & 1ULL << IB_USER_VERBS_CMD_CREATE_CQ))
		return -EOPNOTSUPP;

	ret = uverbs_copy_from(&attr.comp_vector, attrs,
			       UVERBS_ATTR_CREATE_CQ_COMP_VECTOR);
	if (!ret)
		ret = uverbs_copy_from(&attr.cqe, attrs,
				       UVERBS_ATTR_CREATE_CQ_CQE);
	if (!ret)
		ret = uverbs_copy_from(&user_handle, attrs,
				       UVERBS_ATTR_CREATE_CQ_USER_HANDLE);
	if (ret)
		return ret;

	/* Optional param, if it doesn't exist, we get -ENOENT and skip it */
	if (IS_UVERBS_COPY_ERR(uverbs_copy_from(&attr.flags, attrs,
						UVERBS_ATTR_CREATE_CQ_FLAGS)))
		return -EFAULT;

	ev_file_attr = uverbs_attr_get(attrs, UVERBS_ATTR_CREATE_CQ_COMP_CHANNEL);
	if (!IS_ERR(ev_file_attr)) {
		ev_file_uobj = ev_file_attr->obj_attr.uobject;

		ev_file = container_of(ev_file_uobj,
				       struct ib_uverbs_completion_event_file,
				       uobj_file.uobj);
		uverbs_uobject_get(ev_file_uobj);
	}

	if (attr.comp_vector >= ucontext->ufile->device->num_comp_vectors) {
		ret = -EINVAL;
		goto err_event_file;
	}

	obj = container_of(uverbs_attr_get(attrs,
					   UVERBS_ATTR_CREATE_CQ_HANDLE)->obj_attr.uobject,
			   typeof(*obj), uobject);
	obj->uverbs_file	   = ucontext->ufile;
	obj->comp_events_reported  = 0;
	obj->async_events_reported = 0;
	INIT_LIST_HEAD(&obj->comp_list);
	INIT_LIST_HEAD(&obj->async_list);

	/* Temporary, only until drivers get the new uverbs_attr_bundle */
	create_udata(attrs, &uhw);

	cq = ib_dev->create_cq(ib_dev, &attr, ucontext, &uhw);
	if (IS_ERR(cq)) {
		ret = PTR_ERR(cq);
		goto err_event_file;
	}

	cq->device        = ib_dev;
	cq->uobject       = &obj->uobject;
	cq->comp_handler  = ib_uverbs_comp_handler;
	cq->event_handler = ib_uverbs_cq_event_handler;
	cq->cq_context    = ev_file ? &ev_file->ev_queue : NULL;
	obj->uobject.object = cq;
	obj->uobject.user_handle = user_handle;
	atomic_set(&cq->usecnt, 0);
	cq->res.type = RDMA_RESTRACK_CQ;
	rdma_restrack_add(&cq->res);

	ret = uverbs_copy_to(attrs, UVERBS_ATTR_CREATE_CQ_RESP_CQE, &cq->cqe,
			     sizeof(cq->cqe));
	if (ret)
		goto err_cq;

	return 0;
err_cq:
	ib_destroy_cq(cq);

err_event_file:
	if (ev_file)
		uverbs_uobject_put(ev_file_uobj);
	return ret;
};

static DECLARE_UVERBS_NAMED_METHOD(UVERBS_METHOD_CQ_CREATE,
	&UVERBS_ATTR_IDR(UVERBS_ATTR_CREATE_CQ_HANDLE, UVERBS_OBJECT_CQ,
			 UVERBS_ACCESS_NEW,
			 UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	&UVERBS_ATTR_PTR_IN(UVERBS_ATTR_CREATE_CQ_CQE,
			    UVERBS_ATTR_TYPE(u32),
			    UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	&UVERBS_ATTR_PTR_IN(UVERBS_ATTR_CREATE_CQ_USER_HANDLE,
			    UVERBS_ATTR_TYPE(u64),
			    UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	&UVERBS_ATTR_FD(UVERBS_ATTR_CREATE_CQ_COMP_CHANNEL,
			UVERBS_OBJECT_COMP_CHANNEL,
			UVERBS_ACCESS_READ),
	&UVERBS_ATTR_PTR_IN(UVERBS_ATTR_CREATE_CQ_COMP_VECTOR, UVERBS_ATTR_TYPE(u32),
			    UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	&UVERBS_ATTR_PTR_IN(UVERBS_ATTR_CREATE_CQ_FLAGS, UVERBS_ATTR_TYPE(u32)),
	&UVERBS_ATTR_PTR_OUT(UVERBS_ATTR_CREATE_CQ_RESP_CQE, UVERBS_ATTR_TYPE(u32),
			     UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	&uverbs_uhw_compat_in, &uverbs_uhw_compat_out);

static int UVERBS_HANDLER(UVERBS_METHOD_CQ_DESTROY)(struct ib_device *ib_dev,
						    struct ib_uverbs_file *file,
						    struct uverbs_attr_bundle *attrs)
{
	struct ib_uverbs_destroy_cq_resp resp;
	struct ib_uobject *uobj =
		uverbs_attr_get(attrs, UVERBS_ATTR_DESTROY_CQ_HANDLE)->obj_attr.uobject;
	struct ib_ucq_object *obj = container_of(uobj, struct ib_ucq_object,
						 uobject);
	int ret;

	if (!(ib_dev->uverbs_cmd_mask & 1ULL << IB_USER_VERBS_CMD_DESTROY_CQ))
		return -EOPNOTSUPP;

	ret = rdma_explicit_destroy(uobj);
	if (ret)
		return ret;

	resp.comp_events_reported  = obj->comp_events_reported;
	resp.async_events_reported = obj->async_events_reported;

	return uverbs_copy_to(attrs, UVERBS_ATTR_DESTROY_CQ_RESP, &resp,
			      sizeof(resp));
}

static DECLARE_UVERBS_NAMED_METHOD(UVERBS_METHOD_CQ_DESTROY,
	&UVERBS_ATTR_IDR(UVERBS_ATTR_DESTROY_CQ_HANDLE, UVERBS_OBJECT_CQ,
			 UVERBS_ACCESS_DESTROY,
			 UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	&UVERBS_ATTR_PTR_OUT(UVERBS_ATTR_DESTROY_CQ_RESP,
			     UVERBS_ATTR_TYPE(struct ib_uverbs_destroy_cq_resp),
			     UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

DECLARE_UVERBS_NAMED_OBJECT(UVERBS_OBJECT_CQ,
			    &UVERBS_TYPE_ALLOC_IDR_SZ(sizeof(struct ib_ucq_object), 0,
						      uverbs_free_cq),
#if IS_ENABLED(CONFIG_INFINIBAND_EXP_LEGACY_VERBS_NEW_UAPI)
			    &UVERBS_METHOD(UVERBS_METHOD_CQ_CREATE),
			    &UVERBS_METHOD(UVERBS_METHOD_CQ_DESTROY)
#endif
			   );

