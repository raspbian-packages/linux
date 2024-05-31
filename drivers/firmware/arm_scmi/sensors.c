// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Management Interface (SCMI) Sensor Protocol
 *
 * Copyright (C) 2018-2022 ARM Ltd.
 */

#define pr_fmt(fmt) "SCMI Notifications SENSOR - " fmt

#include <linux/bitfield.h>
#include <linux/module.h>
#include <linux/scmi_protocol.h>

#include "protocols.h"
#include "notify.h"

/* Updated only after ALL the mandatory features for that version are merged */
#define SCMI_PROTOCOL_SUPPORTED_VERSION		0x30000

#define SCMI_MAX_NUM_SENSOR_AXIS	63
#define	SCMIv2_SENSOR_PROTOCOL		0x10000

enum scmi_sensor_protocol_cmd {
	SENSOR_DESCRIPTION_GET = 0x3,
	SENSOR_TRIP_POINT_NOTIFY = 0x4,
	SENSOR_TRIP_POINT_CONFIG = 0x5,
	SENSOR_READING_GET = 0x6,
	SENSOR_AXIS_DESCRIPTION_GET = 0x7,
	SENSOR_LIST_UPDATE_INTERVALS = 0x8,
	SENSOR_CONFIG_GET = 0x9,
	SENSOR_CONFIG_SET = 0xA,
	SENSOR_CONTINUOUS_UPDATE_NOTIFY = 0xB,
	SENSOR_NAME_GET = 0xC,
	SENSOR_AXIS_NAME_GET = 0xD,
};

struct scmi_msg_resp_sensor_attributes {
	__le16 num_sensors;
	u8 max_requests;
	u8 reserved;
	__le32 reg_addr_low;
	__le32 reg_addr_high;
	__le32 reg_size;
};

/* v3 attributes_low macros */
#define SUPPORTS_UPDATE_NOTIFY(x)	FIELD_GET(BIT(30), (x))
#define SENSOR_TSTAMP_EXP(x)		FIELD_GET(GENMASK(14, 10), (x))
#define SUPPORTS_TIMESTAMP(x)		FIELD_GET(BIT(9), (x))
#define SUPPORTS_EXTEND_ATTRS(x)	FIELD_GET(BIT(8), (x))

/* v2 attributes_high macros */
#define SENSOR_UPDATE_BASE(x)		FIELD_GET(GENMASK(31, 27), (x))
#define SENSOR_UPDATE_SCALE(x)		FIELD_GET(GENMASK(26, 22), (x))

/* v3 attributes_high macros */
#define SENSOR_AXIS_NUMBER(x)		FIELD_GET(GENMASK(21, 16), (x))
#define SUPPORTS_AXIS(x)		FIELD_GET(BIT(8), (x))

/* v3 resolution macros */
#define SENSOR_RES(x)			FIELD_GET(GENMASK(26, 0), (x))
#define SENSOR_RES_EXP(x)		FIELD_GET(GENMASK(31, 27), (x))

struct scmi_msg_resp_attrs {
	__le32 min_range_low;
	__le32 min_range_high;
	__le32 max_range_low;
	__le32 max_range_high;
};

struct scmi_msg_sensor_description {
	__le32 desc_index;
};

struct scmi_msg_resp_sensor_description {
	__le16 num_returned;
	__le16 num_remaining;
	struct scmi_sensor_descriptor {
		__le32 id;
		__le32 attributes_low;
/* Common attributes_low macros */
#define SUPPORTS_ASYNC_READ(x)		FIELD_GET(BIT(31), (x))
#define SUPPORTS_EXTENDED_NAMES(x)	FIELD_GET(BIT(29), (x))
#define NUM_TRIP_POINTS(x)		FIELD_GET(GENMASK(7, 0), (x))
		__le32 attributes_high;
/* Common attributes_high macros */
#define SENSOR_SCALE(x)			FIELD_GET(GENMASK(15, 11), (x))
#define SENSOR_SCALE_SIGN		BIT(4)
#define SENSOR_SCALE_EXTEND		GENMASK(31, 5)
#define SENSOR_TYPE(x)			FIELD_GET(GENMASK(7, 0), (x))
		u8 name[SCMI_SHORT_NAME_MAX_SIZE];
		/* only for version > 2.0 */
		__le32 power;
		__le32 resolution;
		struct scmi_msg_resp_attrs scalar_attrs;
	} desc[];
};

/* Base scmi_sensor_descriptor size excluding extended attrs after name */
#define SCMI_MSG_RESP_SENS_DESCR_BASE_SZ	28

/* Sign extend to a full s32 */
#define	S32_EXT(v)							\
	({								\
		int __v = (v);						\
									\
		if (__v & SENSOR_SCALE_SIGN)				\
			__v |= SENSOR_SCALE_EXTEND;			\
		__v;							\
	})

struct scmi_msg_sensor_axis_description_get {
	__le32 id;
	__le32 axis_desc_index;
};

struct scmi_msg_resp_sensor_axis_description {
	__le32 num_axis_flags;
#define NUM_AXIS_RETURNED(x)		FIELD_GET(GENMASK(5, 0), (x))
#define NUM_AXIS_REMAINING(x)		FIELD_GET(GENMASK(31, 26), (x))
	struct scmi_axis_descriptor {
		__le32 id;
		__le32 attributes_low;
#define SUPPORTS_EXTENDED_AXIS_NAMES(x)	FIELD_GET(BIT(9), (x))
		__le32 attributes_high;
		u8 name[SCMI_SHORT_NAME_MAX_SIZE];
		__le32 resolution;
		struct scmi_msg_resp_attrs attrs;
	} desc[];
};

struct scmi_msg_resp_sensor_axis_names_description {
	__le32 num_axis_flags;
	struct scmi_sensor_axis_name_descriptor {
		__le32 axis_id;
		u8 name[SCMI_MAX_STR_SIZE];
	} desc[];
};

/* Base scmi_axis_descriptor size excluding extended attrs after name */
#define SCMI_MSG_RESP_AXIS_DESCR_BASE_SZ	28

struct scmi_msg_sensor_list_update_intervals {
	__le32 id;
	__le32 index;
};

struct scmi_msg_resp_sensor_list_update_intervals {
	__le32 num_intervals_flags;
#define NUM_INTERVALS_RETURNED(x)	FIELD_GET(GENMASK(11, 0), (x))
#define SEGMENTED_INTVL_FORMAT(x)	FIELD_GET(BIT(12), (x))
#define NUM_INTERVALS_REMAINING(x)	FIELD_GET(GENMASK(31, 16), (x))
	__le32 intervals[];
};

struct scmi_msg_sensor_request_notify {
	__le32 id;
	__le32 event_control;
#define SENSOR_NOTIFY_ALL	BIT(0)
};

struct scmi_msg_set_sensor_trip_point {
	__le32 id;
	__le32 event_control;
#define SENSOR_TP_EVENT_MASK	(0x3)
#define SENSOR_TP_DISABLED	0x0
#define SENSOR_TP_POSITIVE	0x1
#define SENSOR_TP_NEGATIVE	0x2
#define SENSOR_TP_BOTH		0x3
#define SENSOR_TP_ID(x)		(((x) & 0xff) << 4)
	__le32 value_low;
	__le32 value_high;
};

struct scmi_msg_sensor_config_set {
	__le32 id;
	__le32 sensor_config;
};

struct scmi_msg_sensor_reading_get {
	__le32 id;
	__le32 flags;
#define SENSOR_READ_ASYNC	BIT(0)
};

struct scmi_resp_sensor_reading_complete {
	__le32 id;
	__le32 readings_low;
	__le32 readings_high;
};

struct scmi_sensor_reading_resp {
	__le32 sensor_value_low;
	__le32 sensor_value_high;
	__le32 timestamp_low;
	__le32 timestamp_high;
};

struct scmi_resp_sensor_reading_complete_v3 {
	__le32 id;
	struct scmi_sensor_reading_resp readings[];
};

struct scmi_sensor_trip_notify_payld {
	__le32 agent_id;
	__le32 sensor_id;
	__le32 trip_point_desc;
};

struct scmi_sensor_update_notify_payld {
	__le32 agent_id;
	__le32 sensor_id;
	struct scmi_sensor_reading_resp readings[];
};

struct sensors_info {
	u32 version;
	int num_sensors;
	int max_requests;
	u64 reg_addr;
	u32 reg_size;
	struct scmi_sensor_info *sensors;
};

static int scmi_sensor_attributes_get(const struct scmi_protocol_handle *ph,
				      struct sensors_info *si)
{
	int ret;
	struct scmi_xfer *t;
	struct scmi_msg_resp_sensor_attributes *attr;

	ret = ph->xops->xfer_get_init(ph, PROTOCOL_ATTRIBUTES,
				      0, sizeof(*attr), &t);
	if (ret)
		return ret;

	attr = t->rx.buf;

	ret = ph->xops->do_xfer(ph, t);
	if (!ret) {
		si->num_sensors = le16_to_cpu(attr->num_sensors);
		si->max_requests = attr->max_requests;
		si->reg_addr = le32_to_cpu(attr->reg_addr_low) |
				(u64)le32_to_cpu(attr->reg_addr_high) << 32;
		si->reg_size = le32_to_cpu(attr->reg_size);
	}

	ph->xops->xfer_put(ph, t);
	return ret;
}

static inline void scmi_parse_range_attrs(struct scmi_range_attrs *out,
					  const struct scmi_msg_resp_attrs *in)
{
	out->min_range = get_unaligned_le64((void *)&in->min_range_low);
	out->max_range = get_unaligned_le64((void *)&in->max_range_low);
}

struct scmi_sens_ipriv {
	void *priv;
	struct device *dev;
};

static void iter_intervals_prepare_message(void *message,
					   unsigned int desc_index,
					   const void *p)
{
	struct scmi_msg_sensor_list_update_intervals *msg = message;
	const struct scmi_sensor_info *s;

	s = ((const struct scmi_sens_ipriv *)p)->priv;
	/* Set the number of sensors to be skipped/already read */
	msg->id = cpu_to_le32(s->id);
	msg->index = cpu_to_le32(desc_index);
}

static int iter_intervals_update_state(struct scmi_iterator_state *st,
				       const void *response, void *p)
{
	u32 flags;
	struct scmi_sensor_info *s = ((struct scmi_sens_ipriv *)p)->priv;
	struct device *dev = ((struct scmi_sens_ipriv *)p)->dev;
	const struct scmi_msg_resp_sensor_list_update_intervals *r = response;

	flags = le32_to_cpu(r->num_intervals_flags);
	st->num_returned = NUM_INTERVALS_RETURNED(flags);
	st->num_remaining = NUM_INTERVALS_REMAINING(flags);

	/*
	 * Max intervals is not declared previously anywhere so we
	 * assume it's returned+remaining on first call.
	 */
	if (!st->max_resources) {
		s->intervals.segmented = SEGMENTED_INTVL_FORMAT(flags);
		s->intervals.count = st->num_returned + st->num_remaining;
		/* segmented intervals are reported in one triplet */
		if (s->intervals.segmented &&
		    (st->num_remaining || st->num_returned != 3)) {
			dev_err(dev,
				"Sensor ID:%d advertises an invalid segmented interval (%d)\n",
				s->id, s->intervals.count);
			s->intervals.segmented = false;
			s->intervals.count = 0;
			return -EINVAL;
		}
		/* Direct allocation when exceeding pre-allocated */
		if (s->intervals.count >= SCMI_MAX_PREALLOC_POOL) {
			s->intervals.desc =
				devm_kcalloc(dev,
					     s->intervals.count,
					     sizeof(*s->intervals.desc),
					     GFP_KERNEL);
			if (!s->intervals.desc) {
				s->intervals.segmented = false;
				s->intervals.count = 0;
				return -ENOMEM;
			}
		}

		st->max_resources = s->intervals.count;
	}

	return 0;
}

static int
iter_intervals_process_response(const struct scmi_protocol_handle *ph,
				const void *response,
				struct scmi_iterator_state *st, void *p)
{
	const struct scmi_msg_resp_sensor_list_update_intervals *r = response;
	struct scmi_sensor_info *s = ((struct scmi_sens_ipriv *)p)->priv;

	s->intervals.desc[st->desc_index + st->loop_idx] =
		le32_to_cpu(r->intervals[st->loop_idx]);

	return 0;
}

static int scmi_sensor_update_intervals(const struct scmi_protocol_handle *ph,
					struct scmi_sensor_info *s)
{
	void *iter;
	struct scmi_iterator_ops ops = {
		.prepare_message = iter_intervals_prepare_message,
		.update_state = iter_intervals_update_state,
		.process_response = iter_intervals_process_response,
	};
	struct scmi_sens_ipriv upriv = {
		.priv = s,
		.dev = ph->dev,
	};

	iter = ph->hops->iter_response_init(ph, &ops, s->intervals.count,
					    SENSOR_LIST_UPDATE_INTERVALS,
					    sizeof(struct scmi_msg_sensor_list_update_intervals),
					    &upriv);
	if (IS_ERR(iter))
		return PTR_ERR(iter);

	return ph->hops->iter_response_run(iter);
}

struct scmi_apriv {
	bool any_axes_support_extended_names;
	struct scmi_sensor_info *s;
};

static void iter_axes_desc_prepare_message(void *message,
					   const unsigned int desc_index,
					   const void *priv)
{
	struct scmi_msg_sensor_axis_description_get *msg = message;
	const struct scmi_apriv *apriv = priv;

	/* Set the number of sensors to be skipped/already read */
	msg->id = cpu_to_le32(apriv->s->id);
	msg->axis_desc_index = cpu_to_le32(desc_index);
}

static int
iter_axes_desc_update_state(struct scmi_iterator_state *st,
			    const void *response, void *priv)
{
	u32 flags;
	const struct scmi_msg_resp_sensor_axis_description *r = response;

	flags = le32_to_cpu(r->num_axis_flags);
	st->num_returned = NUM_AXIS_RETURNED(flags);
	st->num_remaining = NUM_AXIS_REMAINING(flags);
	st->priv = (void *)&r->desc[0];

	return 0;
}

static int
iter_axes_desc_process_response(const struct scmi_protocol_handle *ph,
				const void *response,
				struct scmi_iterator_state *st, void *priv)
{
	u32 attrh, attrl;
	struct scmi_sensor_axis_info *a;
	size_t dsize = SCMI_MSG_RESP_AXIS_DESCR_BASE_SZ;
	struct scmi_apriv *apriv = priv;
	const struct scmi_axis_descriptor *adesc = st->priv;

	attrl = le32_to_cpu(adesc->attributes_low);
	if (SUPPORTS_EXTENDED_AXIS_NAMES(attrl))
		apriv->any_axes_support_extended_names = true;

	a = &apriv->s->axis[st->desc_index + st->loop_idx];
	a->id = le32_to_cpu(adesc->id);
	a->extended_attrs = SUPPORTS_EXTEND_ATTRS(attrl);

	attrh = le32_to_cpu(adesc->attributes_high);
	a->scale = S32_EXT(SENSOR_SCALE(attrh));
	a->type = SENSOR_TYPE(attrh);
	strscpy(a->name, adesc->name, SCMI_SHORT_NAME_MAX_SIZE);

	if (a->extended_attrs) {
		unsigned int ares = le32_to_cpu(adesc->resolution);

		a->resolution = SENSOR_RES(ares);
		a->exponent = S32_EXT(SENSOR_RES_EXP(ares));
		dsize += sizeof(adesc->resolution);

		scmi_parse_range_attrs(&a->attrs, &adesc->attrs);
		dsize += sizeof(adesc->attrs);
	}
	st->priv = ((u8 *)adesc + dsize);

	return 0;
}

static int
iter_axes_extended_name_update_state(struct scmi_iterator_state *st,
				     const void *response, void *priv)
{
	u32 flags;
	const struct scmi_msg_resp_sensor_axis_names_description *r = response;

	flags = le32_to_cpu(r->num_axis_flags);
	st->num_returned = NUM_AXIS_RETURNED(flags);
	st->num_remaining = NUM_AXIS_REMAINING(flags);
	st->priv = (void *)&r->desc[0];

	return 0;
}

static int
iter_axes_extended_name_process_response(const struct scmi_protocol_handle *ph,
					 const void *response,
					 struct scmi_iterator_state *st,
					 void *priv)
{
	struct scmi_sensor_axis_info *a;
	const struct scmi_apriv *apriv = priv;
	struct scmi_sensor_axis_name_descriptor *adesc = st->priv;
	u32 axis_id = le32_to_cpu(adesc->axis_id);

	if (axis_id >= st->max_resources)
		return -EPROTO;

	/*
	 * Pick the corresponding descriptor based on the axis_id embedded
	 * in the reply since the list of axes supporting extended names
	 * can be a subset of all the axes.
	 */
	a = &apriv->s->axis[axis_id];
	strscpy(a->name, adesc->name, SCMI_MAX_STR_SIZE);
	st->priv = ++adesc;

	return 0;
}

static int
scmi_sensor_axis_extended_names_get(const struct scmi_protocol_handle *ph,
				    struct scmi_sensor_info *s)
{
	int ret;
	void *iter;
	struct scmi_iterator_ops ops = {
		.prepare_message = iter_axes_desc_prepare_message,
		.update_state = iter_axes_extended_name_update_state,
		.process_response = iter_axes_extended_name_process_response,
	};
	struct scmi_apriv apriv = {
		.any_axes_support_extended_names = false,
		.s = s,
	};

	iter = ph->hops->iter_response_init(ph, &ops, s->num_axis,
					    SENSOR_AXIS_NAME_GET,
					    sizeof(struct scmi_msg_sensor_axis_description_get),
					    &apriv);
	if (IS_ERR(iter))
		return PTR_ERR(iter);

	/*
	 * Do not cause whole protocol initialization failure when failing to
	 * get extended names for axes.
	 */
	ret = ph->hops->iter_response_run(iter);
	if (ret)
		dev_warn(ph->dev,
			 "Failed to get axes extended names for %s (ret:%d).\n",
			 s->name, ret);

	return 0;
}

static int scmi_sensor_axis_description(const struct scmi_protocol_handle *ph,
					struct scmi_sensor_info *s,
					u32 version)
{
	int ret;
	void *iter;
	struct scmi_iterator_ops ops = {
		.prepare_message = iter_axes_desc_prepare_message,
		.update_state = iter_axes_desc_update_state,
		.process_response = iter_axes_desc_process_response,
	};
	struct scmi_apriv apriv = {
		.any_axes_support_extended_names = false,
		.s = s,
	};

	s->axis = devm_kcalloc(ph->dev, s->num_axis,
			       sizeof(*s->axis), GFP_KERNEL);
	if (!s->axis)
		return -ENOMEM;

	iter = ph->hops->iter_response_init(ph, &ops, s->num_axis,
					    SENSOR_AXIS_DESCRIPTION_GET,
					    sizeof(struct scmi_msg_sensor_axis_description_get),
					    &apriv);
	if (IS_ERR(iter))
		return PTR_ERR(iter);

	ret = ph->hops->iter_response_run(iter);
	if (ret)
		return ret;

	if (PROTOCOL_REV_MAJOR(version) >= 0x3 &&
	    apriv.any_axes_support_extended_names)
		ret = scmi_sensor_axis_extended_names_get(ph, s);

	return ret;
}

static void iter_sens_descr_prepare_message(void *message,
					    unsigned int desc_index,
					    const void *priv)
{
	struct scmi_msg_sensor_description *msg = message;

	msg->desc_index = cpu_to_le32(desc_index);
}

static int iter_sens_descr_update_state(struct scmi_iterator_state *st,
					const void *response, void *priv)
{
	const struct scmi_msg_resp_sensor_description *r = response;

	st->num_returned = le16_to_cpu(r->num_returned);
	st->num_remaining = le16_to_cpu(r->num_remaining);
	st->priv = (void *)&r->desc[0];

	return 0;
}

static int
iter_sens_descr_process_response(const struct scmi_protocol_handle *ph,
				 const void *response,
				 struct scmi_iterator_state *st, void *priv)

{
	int ret = 0;
	u32 attrh, attrl;
	size_t dsize = SCMI_MSG_RESP_SENS_DESCR_BASE_SZ;
	struct scmi_sensor_info *s;
	struct sensors_info *si = priv;
	const struct scmi_sensor_descriptor *sdesc = st->priv;

	s = &si->sensors[st->desc_index + st->loop_idx];
	s->id = le32_to_cpu(sdesc->id);

	attrl = le32_to_cpu(sdesc->attributes_low);
	/* common bitfields parsing */
	s->async = SUPPORTS_ASYNC_READ(attrl);
	s->num_trip_points = NUM_TRIP_POINTS(attrl);
	/**
	 * only SCMIv3.0 specific bitfield below.
	 * Such bitfields are assumed to be zeroed on non
	 * relevant fw versions...assuming fw not buggy !
	 */
	s->update = SUPPORTS_UPDATE_NOTIFY(attrl);
	s->timestamped = SUPPORTS_TIMESTAMP(attrl);
	if (s->timestamped)
		s->tstamp_scale = S32_EXT(SENSOR_TSTAMP_EXP(attrl));
	s->extended_scalar_attrs = SUPPORTS_EXTEND_ATTRS(attrl);

	attrh = le32_to_cpu(sdesc->attributes_high);
	/* common bitfields parsing */
	s->scale = S32_EXT(SENSOR_SCALE(attrh));
	s->type = SENSOR_TYPE(attrh);
	/* Use pre-allocated pool wherever possible */
	s->intervals.desc = s->intervals.prealloc_pool;
	if (si->version == SCMIv2_SENSOR_PROTOCOL) {
		s->intervals.segmented = false;
		s->intervals.count = 1;
		/*
		 * Convert SCMIv2.0 update interval format to
		 * SCMIv3.0 to be used as the common exposed
		 * descriptor, accessible via common macros.
		 */
		s->intervals.desc[0] = (SENSOR_UPDATE_BASE(attrh) << 5) |
					SENSOR_UPDATE_SCALE(attrh);
	} else {
		/*
		 * From SCMIv3.0 update intervals are retrieved
		 * via a dedicated (optional) command.
		 * Since the command is optional, on error carry
		 * on without any update interval.
		 */
		if (scmi_sensor_update_intervals(ph, s))
			dev_dbg(ph->dev,
				"Update Intervals not available for sensor ID:%d\n",
				s->id);
	}
	/**
	 * only > SCMIv2.0 specific bitfield below.
	 * Such bitfields are assumed to be zeroed on non
	 * relevant fw versions...assuming fw not buggy !
	 */
	s->num_axis = min_t(unsigned int,
			    SUPPORTS_AXIS(attrh) ?
			    SENSOR_AXIS_NUMBER(attrh) : 0,
			    SCMI_MAX_NUM_SENSOR_AXIS);
	strscpy(s->name, sdesc->name, SCMI_SHORT_NAME_MAX_SIZE);

	/*
	 * If supported overwrite short name with the extended
	 * one; on error just carry on and use already provided
	 * short name.
	 */
	if (PROTOCOL_REV_MAJOR(si->version) >= 0x3 &&
	    SUPPORTS_EXTENDED_NAMES(attrl))
		ph->hops->extended_name_get(ph, SENSOR_NAME_GET, s->id,
					    NULL, s->name, SCMI_MAX_STR_SIZE);

	if (s->extended_scalar_attrs) {
		s->sensor_power = le32_to_cpu(sdesc->power);
		dsize += sizeof(sdesc->power);

		/* Only for sensors reporting scalar values */
		if (s->num_axis == 0) {
			unsigned int sres = le32_to_cpu(sdesc->resolution);

			s->resolution = SENSOR_RES(sres);
			s->exponent = S32_EXT(SENSOR_RES_EXP(sres));
			dsize += sizeof(sdesc->resolution);

			scmi_parse_range_attrs(&s->scalar_attrs,
					       &sdesc->scalar_attrs);
			dsize += sizeof(sdesc->scalar_attrs);
		}
	}

	if (s->num_axis > 0)
		ret = scmi_sensor_axis_description(ph, s, si->version);

	st->priv = ((u8 *)sdesc + dsize);

	return ret;
}

static int scmi_sensor_description_get(const struct scmi_protocol_handle *ph,
				       struct sensors_info *si)
{
	void *iter;
	struct scmi_iterator_ops ops = {
		.prepare_message = iter_sens_descr_prepare_message,
		.update_state = iter_sens_descr_update_state,
		.process_response = iter_sens_descr_process_response,
	};

	iter = ph->hops->iter_response_init(ph, &ops, si->num_sensors,
					    SENSOR_DESCRIPTION_GET,
					    sizeof(__le32), si);
	if (IS_ERR(iter))
		return PTR_ERR(iter);

	return ph->hops->iter_response_run(iter);
}

static inline int
scmi_sensor_request_notify(const struct scmi_protocol_handle *ph, u32 sensor_id,
			   u8 message_id, bool enable)
{
	int ret;
	u32 evt_cntl = enable ? SENSOR_NOTIFY_ALL : 0;
	struct scmi_xfer *t;
	struct scmi_msg_sensor_request_notify *cfg;

	ret = ph->xops->xfer_get_init(ph, message_id, sizeof(*cfg), 0, &t);
	if (ret)
		return ret;

	cfg = t->tx.buf;
	cfg->id = cpu_to_le32(sensor_id);
	cfg->event_control = cpu_to_le32(evt_cntl);

	ret = ph->xops->do_xfer(ph, t);

	ph->xops->xfer_put(ph, t);
	return ret;
}

static int scmi_sensor_trip_point_notify(const struct scmi_protocol_handle *ph,
					 u32 sensor_id, bool enable)
{
	return scmi_sensor_request_notify(ph, sensor_id,
					  SENSOR_TRIP_POINT_NOTIFY,
					  enable);
}

static int
scmi_sensor_continuous_update_notify(const struct scmi_protocol_handle *ph,
				     u32 sensor_id, bool enable)
{
	return scmi_sensor_request_notify(ph, sensor_id,
					  SENSOR_CONTINUOUS_UPDATE_NOTIFY,
					  enable);
}

static int
scmi_sensor_trip_point_config(const struct scmi_protocol_handle *ph,
			      u32 sensor_id, u8 trip_id, u64 trip_value)
{
	int ret;
	u32 evt_cntl = SENSOR_TP_BOTH;
	struct scmi_xfer *t;
	struct scmi_msg_set_sensor_trip_point *trip;

	ret = ph->xops->xfer_get_init(ph, SENSOR_TRIP_POINT_CONFIG,
				      sizeof(*trip), 0, &t);
	if (ret)
		return ret;

	trip = t->tx.buf;
	trip->id = cpu_to_le32(sensor_id);
	trip->event_control = cpu_to_le32(evt_cntl | SENSOR_TP_ID(trip_id));
	trip->value_low = cpu_to_le32(trip_value & 0xffffffff);
	trip->value_high = cpu_to_le32(trip_value >> 32);

	ret = ph->xops->do_xfer(ph, t);

	ph->xops->xfer_put(ph, t);
	return ret;
}

static int scmi_sensor_config_get(const struct scmi_protocol_handle *ph,
				  u32 sensor_id, u32 *sensor_config)
{
	int ret;
	struct scmi_xfer *t;
	struct sensors_info *si = ph->get_priv(ph);

	if (sensor_id >= si->num_sensors)
		return -EINVAL;

	ret = ph->xops->xfer_get_init(ph, SENSOR_CONFIG_GET,
				      sizeof(__le32), sizeof(__le32), &t);
	if (ret)
		return ret;

	put_unaligned_le32(sensor_id, t->tx.buf);
	ret = ph->xops->do_xfer(ph, t);
	if (!ret) {
		struct scmi_sensor_info *s = si->sensors + sensor_id;

		*sensor_config = get_unaligned_le64(t->rx.buf);
		s->sensor_config = *sensor_config;
	}

	ph->xops->xfer_put(ph, t);
	return ret;
}

static int scmi_sensor_config_set(const struct scmi_protocol_handle *ph,
				  u32 sensor_id, u32 sensor_config)
{
	int ret;
	struct scmi_xfer *t;
	struct scmi_msg_sensor_config_set *msg;
	struct sensors_info *si = ph->get_priv(ph);

	if (sensor_id >= si->num_sensors)
		return -EINVAL;

	ret = ph->xops->xfer_get_init(ph, SENSOR_CONFIG_SET,
				      sizeof(*msg), 0, &t);
	if (ret)
		return ret;

	msg = t->tx.buf;
	msg->id = cpu_to_le32(sensor_id);
	msg->sensor_config = cpu_to_le32(sensor_config);

	ret = ph->xops->do_xfer(ph, t);
	if (!ret) {
		struct scmi_sensor_info *s = si->sensors + sensor_id;

		s->sensor_config = sensor_config;
	}

	ph->xops->xfer_put(ph, t);
	return ret;
}

/**
 * scmi_sensor_reading_get  - Read scalar sensor value
 * @ph: Protocol handle
 * @sensor_id: Sensor ID
 * @value: The 64bit value sensor reading
 *
 * This function returns a single 64 bit reading value representing the sensor
 * value; if the platform SCMI Protocol implementation and the sensor support
 * multiple axis and timestamped-reads, this just returns the first axis while
 * dropping the timestamp value.
 * Use instead the @scmi_sensor_reading_get_timestamped to retrieve the array of
 * timestamped multi-axis values.
 *
 * Return: 0 on Success
 */
static int scmi_sensor_reading_get(const struct scmi_protocol_handle *ph,
				   u32 sensor_id, u64 *value)
{
	int ret;
	struct scmi_xfer *t;
	struct scmi_msg_sensor_reading_get *sensor;
	struct scmi_sensor_info *s;
	struct sensors_info *si = ph->get_priv(ph);

	if (sensor_id >= si->num_sensors)
		return -EINVAL;

	ret = ph->xops->xfer_get_init(ph, SENSOR_READING_GET,
				      sizeof(*sensor), 0, &t);
	if (ret)
		return ret;

	sensor = t->tx.buf;
	sensor->id = cpu_to_le32(sensor_id);
	s = si->sensors + sensor_id;
	if (s->async) {
		sensor->flags = cpu_to_le32(SENSOR_READ_ASYNC);
		ret = ph->xops->do_xfer_with_response(ph, t);
		if (!ret) {
			struct scmi_resp_sensor_reading_complete *resp;

			resp = t->rx.buf;
			if (le32_to_cpu(resp->id) == sensor_id)
				*value =
					get_unaligned_le64(&resp->readings_low);
			else
				ret = -EPROTO;
		}
	} else {
		sensor->flags = cpu_to_le32(0);
		ret = ph->xops->do_xfer(ph, t);
		if (!ret)
			*value = get_unaligned_le64(t->rx.buf);
	}

	ph->xops->xfer_put(ph, t);
	return ret;
}

static inline void
scmi_parse_sensor_readings(struct scmi_sensor_reading *out,
			   const struct scmi_sensor_reading_resp *in)
{
	out->value = get_unaligned_le64((void *)&in->sensor_value_low);
	out->timestamp = get_unaligned_le64((void *)&in->timestamp_low);
}

/**
 * scmi_sensor_reading_get_timestamped  - Read multiple-axis timestamped values
 * @ph: Protocol handle
 * @sensor_id: Sensor ID
 * @count: The length of the provided @readings array
 * @readings: An array of elements each representing a timestamped per-axis
 *	      reading of type @struct scmi_sensor_reading.
 *	      Returned readings are ordered as the @axis descriptors array
 *	      included in @struct scmi_sensor_info and the max number of
 *	      returned elements is min(@count, @num_axis); ideally the provided
 *	      array should be of length @count equal to @num_axis.
 *
 * Return: 0 on Success
 */
static int
scmi_sensor_reading_get_timestamped(const struct scmi_protocol_handle *ph,
				    u32 sensor_id, u8 count,
				    struct scmi_sensor_reading *readings)
{
	int ret;
	struct scmi_xfer *t;
	struct scmi_msg_sensor_reading_get *sensor;
	struct scmi_sensor_info *s;
	struct sensors_info *si = ph->get_priv(ph);

	if (sensor_id >= si->num_sensors)
		return -EINVAL;

	s = si->sensors + sensor_id;
	if (!count || !readings ||
	    (!s->num_axis && count > 1) || (s->num_axis && count > s->num_axis))
		return -EINVAL;

	ret = ph->xops->xfer_get_init(ph, SENSOR_READING_GET,
				      sizeof(*sensor), 0, &t);
	if (ret)
		return ret;

	sensor = t->tx.buf;
	sensor->id = cpu_to_le32(sensor_id);
	if (s->async) {
		sensor->flags = cpu_to_le32(SENSOR_READ_ASYNC);
		ret = ph->xops->do_xfer_with_response(ph, t);
		if (!ret) {
			int i;
			struct scmi_resp_sensor_reading_complete_v3 *resp;

			resp = t->rx.buf;
			/* Retrieve only the number of requested axis anyway */
			if (le32_to_cpu(resp->id) == sensor_id)
				for (i = 0; i < count; i++)
					scmi_parse_sensor_readings(&readings[i],
								   &resp->readings[i]);
			else
				ret = -EPROTO;
		}
	} else {
		sensor->flags = cpu_to_le32(0);
		ret = ph->xops->do_xfer(ph, t);
		if (!ret) {
			int i;
			struct scmi_sensor_reading_resp *resp_readings;

			resp_readings = t->rx.buf;
			for (i = 0; i < count; i++)
				scmi_parse_sensor_readings(&readings[i],
							   &resp_readings[i]);
		}
	}

	ph->xops->xfer_put(ph, t);
	return ret;
}

static const struct scmi_sensor_info *
scmi_sensor_info_get(const struct scmi_protocol_handle *ph, u32 sensor_id)
{
	struct sensors_info *si = ph->get_priv(ph);

	if (sensor_id >= si->num_sensors)
		return NULL;

	return si->sensors + sensor_id;
}

static int scmi_sensor_count_get(const struct scmi_protocol_handle *ph)
{
	struct sensors_info *si = ph->get_priv(ph);

	return si->num_sensors;
}

static const struct scmi_sensor_proto_ops sensor_proto_ops = {
	.count_get = scmi_sensor_count_get,
	.info_get = scmi_sensor_info_get,
	.trip_point_config = scmi_sensor_trip_point_config,
	.reading_get = scmi_sensor_reading_get,
	.reading_get_timestamped = scmi_sensor_reading_get_timestamped,
	.config_get = scmi_sensor_config_get,
	.config_set = scmi_sensor_config_set,
};

static int scmi_sensor_set_notify_enabled(const struct scmi_protocol_handle *ph,
					  u8 evt_id, u32 src_id, bool enable)
{
	int ret;

	switch (evt_id) {
	case SCMI_EVENT_SENSOR_TRIP_POINT_EVENT:
		ret = scmi_sensor_trip_point_notify(ph, src_id, enable);
		break;
	case SCMI_EVENT_SENSOR_UPDATE:
		ret = scmi_sensor_continuous_update_notify(ph, src_id, enable);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (ret)
		pr_debug("FAIL_ENABLED - evt[%X] dom[%d] - ret:%d\n",
			 evt_id, src_id, ret);

	return ret;
}

static void *
scmi_sensor_fill_custom_report(const struct scmi_protocol_handle *ph,
			       u8 evt_id, ktime_t timestamp,
			       const void *payld, size_t payld_sz,
			       void *report, u32 *src_id)
{
	void *rep = NULL;

	switch (evt_id) {
	case SCMI_EVENT_SENSOR_TRIP_POINT_EVENT:
	{
		const struct scmi_sensor_trip_notify_payld *p = payld;
		struct scmi_sensor_trip_point_report *r = report;

		if (sizeof(*p) != payld_sz)
			break;

		r->timestamp = timestamp;
		r->agent_id = le32_to_cpu(p->agent_id);
		r->sensor_id = le32_to_cpu(p->sensor_id);
		r->trip_point_desc = le32_to_cpu(p->trip_point_desc);
		*src_id = r->sensor_id;
		rep = r;
		break;
	}
	case SCMI_EVENT_SENSOR_UPDATE:
	{
		int i;
		struct scmi_sensor_info *s;
		const struct scmi_sensor_update_notify_payld *p = payld;
		struct scmi_sensor_update_report *r = report;
		struct sensors_info *sinfo = ph->get_priv(ph);

		/* payld_sz is variable for this event */
		r->sensor_id = le32_to_cpu(p->sensor_id);
		if (r->sensor_id >= sinfo->num_sensors)
			break;
		r->timestamp = timestamp;
		r->agent_id = le32_to_cpu(p->agent_id);
		s = &sinfo->sensors[r->sensor_id];
		/*
		 * The generated report r (@struct scmi_sensor_update_report)
		 * was pre-allocated to contain up to SCMI_MAX_NUM_SENSOR_AXIS
		 * readings: here it is filled with the effective @num_axis
		 * readings defined for this sensor or 1 for scalar sensors.
		 */
		r->readings_count = s->num_axis ?: 1;
		for (i = 0; i < r->readings_count; i++)
			scmi_parse_sensor_readings(&r->readings[i],
						   &p->readings[i]);
		*src_id = r->sensor_id;
		rep = r;
		break;
	}
	default:
		break;
	}

	return rep;
}

static int scmi_sensor_get_num_sources(const struct scmi_protocol_handle *ph)
{
	struct sensors_info *si = ph->get_priv(ph);

	return si->num_sensors;
}

static const struct scmi_event sensor_events[] = {
	{
		.id = SCMI_EVENT_SENSOR_TRIP_POINT_EVENT,
		.max_payld_sz = sizeof(struct scmi_sensor_trip_notify_payld),
		.max_report_sz = sizeof(struct scmi_sensor_trip_point_report),
	},
	{
		.id = SCMI_EVENT_SENSOR_UPDATE,
		.max_payld_sz =
			sizeof(struct scmi_sensor_update_notify_payld) +
			 SCMI_MAX_NUM_SENSOR_AXIS *
			 sizeof(struct scmi_sensor_reading_resp),
		.max_report_sz = sizeof(struct scmi_sensor_update_report) +
				  SCMI_MAX_NUM_SENSOR_AXIS *
				  sizeof(struct scmi_sensor_reading),
	},
};

static const struct scmi_event_ops sensor_event_ops = {
	.get_num_sources = scmi_sensor_get_num_sources,
	.set_notify_enabled = scmi_sensor_set_notify_enabled,
	.fill_custom_report = scmi_sensor_fill_custom_report,
};

static const struct scmi_protocol_events sensor_protocol_events = {
	.queue_sz = SCMI_PROTO_QUEUE_SZ,
	.ops = &sensor_event_ops,
	.evts = sensor_events,
	.num_events = ARRAY_SIZE(sensor_events),
};

static int scmi_sensors_protocol_init(const struct scmi_protocol_handle *ph)
{
	u32 version;
	int ret;
	struct sensors_info *sinfo;

	ret = ph->xops->version_get(ph, &version);
	if (ret)
		return ret;

	dev_dbg(ph->dev, "Sensor Version %d.%d\n",
		PROTOCOL_REV_MAJOR(version), PROTOCOL_REV_MINOR(version));

	sinfo = devm_kzalloc(ph->dev, sizeof(*sinfo), GFP_KERNEL);
	if (!sinfo)
		return -ENOMEM;
	sinfo->version = version;

	ret = scmi_sensor_attributes_get(ph, sinfo);
	if (ret)
		return ret;
	sinfo->sensors = devm_kcalloc(ph->dev, sinfo->num_sensors,
				      sizeof(*sinfo->sensors), GFP_KERNEL);
	if (!sinfo->sensors)
		return -ENOMEM;

	ret = scmi_sensor_description_get(ph, sinfo);
	if (ret)
		return ret;

	return ph->set_priv(ph, sinfo, version);
}

static const struct scmi_protocol scmi_sensors = {
	.id = SCMI_PROTOCOL_SENSOR,
	.owner = THIS_MODULE,
	.instance_init = &scmi_sensors_protocol_init,
	.ops = &sensor_proto_ops,
	.events = &sensor_protocol_events,
	.supported_version = SCMI_PROTOCOL_SUPPORTED_VERSION,
};

DEFINE_SCMI_PROTOCOL_REGISTER_UNREGISTER(sensors, scmi_sensors)
