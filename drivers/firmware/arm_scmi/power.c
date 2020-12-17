// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Management Interface (SCMI) Power Protocol
 *
 * Copyright (C) 2018 ARM Ltd.
 */

#define pr_fmt(fmt) "SCMI Notifications POWER - " fmt

#include <linux/scmi_protocol.h>

#include "common.h"
#include "notify.h"

enum scmi_power_protocol_cmd {
	POWER_DOMAIN_ATTRIBUTES = 0x3,
	POWER_STATE_SET = 0x4,
	POWER_STATE_GET = 0x5,
	POWER_STATE_NOTIFY = 0x6,
};

struct scmi_msg_resp_power_attributes {
	__le16 num_domains;
	__le16 reserved;
	__le32 stats_addr_low;
	__le32 stats_addr_high;
	__le32 stats_size;
};

struct scmi_msg_resp_power_domain_attributes {
	__le32 flags;
#define SUPPORTS_STATE_SET_NOTIFY(x)	((x) & BIT(31))
#define SUPPORTS_STATE_SET_ASYNC(x)	((x) & BIT(30))
#define SUPPORTS_STATE_SET_SYNC(x)	((x) & BIT(29))
	    u8 name[SCMI_MAX_STR_SIZE];
};

struct scmi_power_set_state {
	__le32 flags;
#define STATE_SET_ASYNC		BIT(0)
	__le32 domain;
	__le32 state;
};

struct scmi_power_state_notify {
	__le32 domain;
	__le32 notify_enable;
};

struct scmi_power_state_notify_payld {
	__le32 agent_id;
	__le32 domain_id;
	__le32 power_state;
};

struct power_dom_info {
	bool state_set_sync;
	bool state_set_async;
	bool state_set_notify;
	char name[SCMI_MAX_STR_SIZE];
};

struct scmi_power_info {
	u32 version;
	int num_domains;
	u64 stats_addr;
	u32 stats_size;
	struct power_dom_info *dom_info;
};

static int scmi_power_attributes_get(const struct scmi_handle *handle,
				     struct scmi_power_info *pi)
{
	int ret;
	struct scmi_xfer *t;
	struct scmi_msg_resp_power_attributes *attr;

	ret = scmi_xfer_get_init(handle, PROTOCOL_ATTRIBUTES,
				 SCMI_PROTOCOL_POWER, 0, sizeof(*attr), &t);
	if (ret)
		return ret;

	attr = t->rx.buf;

	ret = scmi_do_xfer(handle, t);
	if (!ret) {
		pi->num_domains = le16_to_cpu(attr->num_domains);
		pi->stats_addr = le32_to_cpu(attr->stats_addr_low) |
				(u64)le32_to_cpu(attr->stats_addr_high) << 32;
		pi->stats_size = le32_to_cpu(attr->stats_size);
	}

	scmi_xfer_put(handle, t);
	return ret;
}

static int
scmi_power_domain_attributes_get(const struct scmi_handle *handle, u32 domain,
				 struct power_dom_info *dom_info)
{
	int ret;
	struct scmi_xfer *t;
	struct scmi_msg_resp_power_domain_attributes *attr;

	ret = scmi_xfer_get_init(handle, POWER_DOMAIN_ATTRIBUTES,
				 SCMI_PROTOCOL_POWER, sizeof(domain),
				 sizeof(*attr), &t);
	if (ret)
		return ret;

	put_unaligned_le32(domain, t->tx.buf);
	attr = t->rx.buf;

	ret = scmi_do_xfer(handle, t);
	if (!ret) {
		u32 flags = le32_to_cpu(attr->flags);

		dom_info->state_set_notify = SUPPORTS_STATE_SET_NOTIFY(flags);
		dom_info->state_set_async = SUPPORTS_STATE_SET_ASYNC(flags);
		dom_info->state_set_sync = SUPPORTS_STATE_SET_SYNC(flags);
		strlcpy(dom_info->name, attr->name, SCMI_MAX_STR_SIZE);
	}

	scmi_xfer_put(handle, t);
	return ret;
}

static int
scmi_power_state_set(const struct scmi_handle *handle, u32 domain, u32 state)
{
	int ret;
	struct scmi_xfer *t;
	struct scmi_power_set_state *st;

	ret = scmi_xfer_get_init(handle, POWER_STATE_SET, SCMI_PROTOCOL_POWER,
				 sizeof(*st), 0, &t);
	if (ret)
		return ret;

	st = t->tx.buf;
	st->flags = cpu_to_le32(0);
	st->domain = cpu_to_le32(domain);
	st->state = cpu_to_le32(state);

	ret = scmi_do_xfer(handle, t);

	scmi_xfer_put(handle, t);
	return ret;
}

static int
scmi_power_state_get(const struct scmi_handle *handle, u32 domain, u32 *state)
{
	int ret;
	struct scmi_xfer *t;

	ret = scmi_xfer_get_init(handle, POWER_STATE_GET, SCMI_PROTOCOL_POWER,
				 sizeof(u32), sizeof(u32), &t);
	if (ret)
		return ret;

	put_unaligned_le32(domain, t->tx.buf);

	ret = scmi_do_xfer(handle, t);
	if (!ret)
		*state = get_unaligned_le32(t->rx.buf);

	scmi_xfer_put(handle, t);
	return ret;
}

static int scmi_power_num_domains_get(const struct scmi_handle *handle)
{
	struct scmi_power_info *pi = handle->power_priv;

	return pi->num_domains;
}

static char *scmi_power_name_get(const struct scmi_handle *handle, u32 domain)
{
	struct scmi_power_info *pi = handle->power_priv;
	struct power_dom_info *dom = pi->dom_info + domain;

	return dom->name;
}

static struct scmi_power_ops power_ops = {
	.num_domains_get = scmi_power_num_domains_get,
	.name_get = scmi_power_name_get,
	.state_set = scmi_power_state_set,
	.state_get = scmi_power_state_get,
};

static int scmi_power_request_notify(const struct scmi_handle *handle,
				     u32 domain, bool enable)
{
	int ret;
	struct scmi_xfer *t;
	struct scmi_power_state_notify *notify;

	ret = scmi_xfer_get_init(handle, POWER_STATE_NOTIFY,
				 SCMI_PROTOCOL_POWER, sizeof(*notify), 0, &t);
	if (ret)
		return ret;

	notify = t->tx.buf;
	notify->domain = cpu_to_le32(domain);
	notify->notify_enable = enable ? cpu_to_le32(BIT(0)) : 0;

	ret = scmi_do_xfer(handle, t);

	scmi_xfer_put(handle, t);
	return ret;
}

static int scmi_power_set_notify_enabled(const struct scmi_handle *handle,
					 u8 evt_id, u32 src_id, bool enable)
{
	int ret;

	ret = scmi_power_request_notify(handle, src_id, enable);
	if (ret)
		pr_debug("FAIL_ENABLE - evt[%X] dom[%d] - ret:%d\n",
			 evt_id, src_id, ret);

	return ret;
}

static void *scmi_power_fill_custom_report(const struct scmi_handle *handle,
					   u8 evt_id, ktime_t timestamp,
					   const void *payld, size_t payld_sz,
					   void *report, u32 *src_id)
{
	const struct scmi_power_state_notify_payld *p = payld;
	struct scmi_power_state_changed_report *r = report;

	if (evt_id != SCMI_EVENT_POWER_STATE_CHANGED || sizeof(*p) != payld_sz)
		return NULL;

	r->timestamp = timestamp;
	r->agent_id = le32_to_cpu(p->agent_id);
	r->domain_id = le32_to_cpu(p->domain_id);
	r->power_state = le32_to_cpu(p->power_state);
	*src_id = r->domain_id;

	return r;
}

static const struct scmi_event power_events[] = {
	{
		.id = SCMI_EVENT_POWER_STATE_CHANGED,
		.max_payld_sz = sizeof(struct scmi_power_state_notify_payld),
		.max_report_sz =
			sizeof(struct scmi_power_state_changed_report),
	},
};

static const struct scmi_event_ops power_event_ops = {
	.set_notify_enabled = scmi_power_set_notify_enabled,
	.fill_custom_report = scmi_power_fill_custom_report,
};

static int scmi_power_protocol_init(struct scmi_handle *handle)
{
	int domain;
	u32 version;
	struct scmi_power_info *pinfo;

	scmi_version_get(handle, SCMI_PROTOCOL_POWER, &version);

	dev_dbg(handle->dev, "Power Version %d.%d\n",
		PROTOCOL_REV_MAJOR(version), PROTOCOL_REV_MINOR(version));

	pinfo = devm_kzalloc(handle->dev, sizeof(*pinfo), GFP_KERNEL);
	if (!pinfo)
		return -ENOMEM;

	scmi_power_attributes_get(handle, pinfo);

	pinfo->dom_info = devm_kcalloc(handle->dev, pinfo->num_domains,
				       sizeof(*pinfo->dom_info), GFP_KERNEL);
	if (!pinfo->dom_info)
		return -ENOMEM;

	for (domain = 0; domain < pinfo->num_domains; domain++) {
		struct power_dom_info *dom = pinfo->dom_info + domain;

		scmi_power_domain_attributes_get(handle, domain, dom);
	}

	scmi_register_protocol_events(handle,
				      SCMI_PROTOCOL_POWER, SCMI_PROTO_QUEUE_SZ,
				      &power_event_ops, power_events,
				      ARRAY_SIZE(power_events),
				      pinfo->num_domains);

	pinfo->version = version;
	handle->power_ops = &power_ops;
	handle->power_priv = pinfo;

	return 0;
}

static int __init scmi_power_init(void)
{
	return scmi_protocol_register(SCMI_PROTOCOL_POWER,
				      &scmi_power_protocol_init);
}
subsys_initcall(scmi_power_init);
