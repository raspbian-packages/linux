// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */

#include <drm/drm_device.h>
#include <linux/sysfs.h>
#include <linux/printk.h>

#include "i915_drv.h"
#include "i915_reg.h"
#include "i915_sysfs.h"
#include "intel_gt.h"
#include "intel_gt_regs.h"
#include "intel_gt_sysfs.h"
#include "intel_gt_sysfs_pm.h"
#include "intel_pcode.h"
#include "intel_rc6.h"
#include "intel_rps.h"

enum intel_gt_sysfs_op {
	INTEL_GT_SYSFS_MIN = 0,
	INTEL_GT_SYSFS_MAX,
};

static int
sysfs_gt_attribute_w_func(struct device *dev, struct device_attribute *attr,
			  int (func)(struct intel_gt *gt, u32 val), u32 val)
{
	struct intel_gt *gt;
	int ret;

	if (!is_object_gt(&dev->kobj)) {
		int i;
		struct drm_i915_private *i915 = kdev_minor_to_i915(dev);

		for_each_gt(gt, i915, i) {
			ret = func(gt, val);
			if (ret)
				break;
		}
	} else {
		gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
		ret = func(gt, val);
	}

	return ret;
}

static u32
sysfs_gt_attribute_r_func(struct device *dev, struct device_attribute *attr,
			  u32 (func)(struct intel_gt *gt),
			  enum intel_gt_sysfs_op op)
{
	struct intel_gt *gt;
	u32 ret;

	ret = (op == INTEL_GT_SYSFS_MAX) ? 0 : (u32) -1;

	if (!is_object_gt(&dev->kobj)) {
		int i;
		struct drm_i915_private *i915 = kdev_minor_to_i915(dev);

		for_each_gt(gt, i915, i) {
			u32 val = func(gt);

			switch (op) {
			case INTEL_GT_SYSFS_MIN:
				if (val < ret)
					ret = val;
				break;

			case INTEL_GT_SYSFS_MAX:
				if (val > ret)
					ret = val;
				break;
			}
		}
	} else {
		gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
		ret = func(gt);
	}

	return ret;
}

/* RC6 interfaces will show the minimum RC6 residency value */
#define sysfs_gt_attribute_r_min_func(d, a, f) \
		sysfs_gt_attribute_r_func(d, a, f, INTEL_GT_SYSFS_MIN)

/* Frequency interfaces will show the maximum frequency value */
#define sysfs_gt_attribute_r_max_func(d, a, f) \
		sysfs_gt_attribute_r_func(d, a, f, INTEL_GT_SYSFS_MAX)

#ifdef CONFIG_PM
static u32 get_residency(struct intel_gt *gt, i915_reg_t reg)
{
	intel_wakeref_t wakeref;
	u64 res = 0;

	with_intel_runtime_pm(gt->uncore->rpm, wakeref)
		res = intel_rc6_residency_us(&gt->rc6, reg);

	return DIV_ROUND_CLOSEST_ULL(res, 1000);
}

static ssize_t rc6_enable_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	u8 mask = 0;

	if (HAS_RC6(gt->i915))
		mask |= BIT(0);
	if (HAS_RC6p(gt->i915))
		mask |= BIT(1);
	if (HAS_RC6pp(gt->i915))
		mask |= BIT(2);

	return sysfs_emit(buff, "%x\n", mask);
}

static u32 __rc6_residency_ms_show(struct intel_gt *gt)
{
	return get_residency(gt, GEN6_GT_GFX_RC6);
}

static ssize_t rc6_residency_ms_show(struct device *dev,
				     struct device_attribute *attr,
				     char *buff)
{
	u32 rc6_residency = sysfs_gt_attribute_r_min_func(dev, attr,
						      __rc6_residency_ms_show);

	return sysfs_emit(buff, "%u\n", rc6_residency);
}

static u32 __rc6p_residency_ms_show(struct intel_gt *gt)
{
	return get_residency(gt, GEN6_GT_GFX_RC6p);
}

static ssize_t rc6p_residency_ms_show(struct device *dev,
				      struct device_attribute *attr,
				      char *buff)
{
	u32 rc6p_residency = sysfs_gt_attribute_r_min_func(dev, attr,
						__rc6p_residency_ms_show);

	return sysfs_emit(buff, "%u\n", rc6p_residency);
}

static u32 __rc6pp_residency_ms_show(struct intel_gt *gt)
{
	return get_residency(gt, GEN6_GT_GFX_RC6pp);
}

static ssize_t rc6pp_residency_ms_show(struct device *dev,
				       struct device_attribute *attr,
				       char *buff)
{
	u32 rc6pp_residency = sysfs_gt_attribute_r_min_func(dev, attr,
						__rc6pp_residency_ms_show);

	return sysfs_emit(buff, "%u\n", rc6pp_residency);
}

static u32 __media_rc6_residency_ms_show(struct intel_gt *gt)
{
	return get_residency(gt, VLV_GT_MEDIA_RC6);
}

static ssize_t media_rc6_residency_ms_show(struct device *dev,
					   struct device_attribute *attr,
					   char *buff)
{
	u32 rc6_residency = sysfs_gt_attribute_r_min_func(dev, attr,
						__media_rc6_residency_ms_show);

	return sysfs_emit(buff, "%u\n", rc6_residency);
}

static DEVICE_ATTR_RO(rc6_enable);
static DEVICE_ATTR_RO(rc6_residency_ms);
static DEVICE_ATTR_RO(rc6p_residency_ms);
static DEVICE_ATTR_RO(rc6pp_residency_ms);
static DEVICE_ATTR_RO(media_rc6_residency_ms);

static struct attribute *rc6_attrs[] = {
	&dev_attr_rc6_enable.attr,
	&dev_attr_rc6_residency_ms.attr,
	NULL
};

static struct attribute *rc6p_attrs[] = {
	&dev_attr_rc6p_residency_ms.attr,
	&dev_attr_rc6pp_residency_ms.attr,
	NULL
};

static struct attribute *media_rc6_attrs[] = {
	&dev_attr_media_rc6_residency_ms.attr,
	NULL
};

static const struct attribute_group rc6_attr_group[] = {
	{ .attrs = rc6_attrs, },
	{ .name = power_group_name, .attrs = rc6_attrs, },
};

static const struct attribute_group rc6p_attr_group[] = {
	{ .attrs = rc6p_attrs, },
	{ .name = power_group_name, .attrs = rc6p_attrs, },
};

static const struct attribute_group media_rc6_attr_group[] = {
	{ .attrs = media_rc6_attrs, },
	{ .name = power_group_name, .attrs = media_rc6_attrs, },
};

static int __intel_gt_sysfs_create_group(struct kobject *kobj,
					 const struct attribute_group *grp)
{
	return is_object_gt(kobj) ?
	       sysfs_create_group(kobj, &grp[0]) :
	       sysfs_merge_group(kobj, &grp[1]);
}

static void intel_sysfs_rc6_init(struct intel_gt *gt, struct kobject *kobj)
{
	int ret;

	if (!HAS_RC6(gt->i915))
		return;

	ret = __intel_gt_sysfs_create_group(kobj, rc6_attr_group);
	if (ret)
		drm_warn(&gt->i915->drm,
			 "failed to create gt%u RC6 sysfs files (%pe)\n",
			 gt->info.id, ERR_PTR(ret));

	/*
	 * cannot use the is_visible() attribute because
	 * the upper object inherits from the parent group.
	 */
	if (HAS_RC6p(gt->i915)) {
		ret = __intel_gt_sysfs_create_group(kobj, rc6p_attr_group);
		if (ret)
			drm_warn(&gt->i915->drm,
				 "failed to create gt%u RC6p sysfs files (%pe)\n",
				 gt->info.id, ERR_PTR(ret));
	}

	if (IS_VALLEYVIEW(gt->i915) || IS_CHERRYVIEW(gt->i915)) {
		ret = __intel_gt_sysfs_create_group(kobj, media_rc6_attr_group);
		if (ret)
			drm_warn(&gt->i915->drm,
				 "failed to create media %u RC6 sysfs files (%pe)\n",
				 gt->info.id, ERR_PTR(ret));
	}
}
#else
static void intel_sysfs_rc6_init(struct intel_gt *gt, struct kobject *kobj)
{
}
#endif /* CONFIG_PM */

static u32 __act_freq_mhz_show(struct intel_gt *gt)
{
	return intel_rps_read_actual_frequency(&gt->rps);
}

static ssize_t act_freq_mhz_show(struct device *dev,
				 struct device_attribute *attr, char *buff)
{
	u32 actual_freq = sysfs_gt_attribute_r_max_func(dev, attr,
						    __act_freq_mhz_show);

	return sysfs_emit(buff, "%u\n", actual_freq);
}

static u32 __cur_freq_mhz_show(struct intel_gt *gt)
{
	return intel_rps_get_requested_frequency(&gt->rps);
}

static ssize_t cur_freq_mhz_show(struct device *dev,
				 struct device_attribute *attr, char *buff)
{
	u32 cur_freq = sysfs_gt_attribute_r_max_func(dev, attr,
						 __cur_freq_mhz_show);

	return sysfs_emit(buff, "%u\n", cur_freq);
}

static u32 __boost_freq_mhz_show(struct intel_gt *gt)
{
	return intel_rps_get_boost_frequency(&gt->rps);
}

static ssize_t boost_freq_mhz_show(struct device *dev,
				   struct device_attribute *attr,
				   char *buff)
{
	u32 boost_freq = sysfs_gt_attribute_r_max_func(dev, attr,
						   __boost_freq_mhz_show);

	return sysfs_emit(buff, "%u\n", boost_freq);
}

static int __boost_freq_mhz_store(struct intel_gt *gt, u32 val)
{
	return intel_rps_set_boost_frequency(&gt->rps, val);
}

static ssize_t boost_freq_mhz_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buff, size_t count)
{
	ssize_t ret;
	u32 val;

	ret = kstrtou32(buff, 0, &val);
	if (ret)
		return ret;

	return sysfs_gt_attribute_w_func(dev, attr,
					 __boost_freq_mhz_store, val) ?: count;
}

static u32 __rp0_freq_mhz_show(struct intel_gt *gt)
{
	return intel_rps_get_rp0_frequency(&gt->rps);
}

static ssize_t RP0_freq_mhz_show(struct device *dev,
				 struct device_attribute *attr, char *buff)
{
	u32 rp0_freq = sysfs_gt_attribute_r_max_func(dev, attr,
						     __rp0_freq_mhz_show);

	return sysfs_emit(buff, "%u\n", rp0_freq);
}

static u32 __rp1_freq_mhz_show(struct intel_gt *gt)
{
	return intel_rps_get_rp1_frequency(&gt->rps);
}

static ssize_t RP1_freq_mhz_show(struct device *dev,
				 struct device_attribute *attr, char *buff)
{
	u32 rp1_freq = sysfs_gt_attribute_r_max_func(dev, attr,
						     __rp1_freq_mhz_show);

	return sysfs_emit(buff, "%u\n", rp1_freq);
}

static u32 __rpn_freq_mhz_show(struct intel_gt *gt)
{
	return intel_rps_get_rpn_frequency(&gt->rps);
}

static ssize_t RPn_freq_mhz_show(struct device *dev,
				 struct device_attribute *attr, char *buff)
{
	u32 rpn_freq = sysfs_gt_attribute_r_max_func(dev, attr,
						     __rpn_freq_mhz_show);

	return sysfs_emit(buff, "%u\n", rpn_freq);
}

static u32 __max_freq_mhz_show(struct intel_gt *gt)
{
	return intel_rps_get_max_frequency(&gt->rps);
}

static ssize_t max_freq_mhz_show(struct device *dev,
				 struct device_attribute *attr, char *buff)
{
	u32 max_freq = sysfs_gt_attribute_r_max_func(dev, attr,
						     __max_freq_mhz_show);

	return sysfs_emit(buff, "%u\n", max_freq);
}

static int __set_max_freq(struct intel_gt *gt, u32 val)
{
	return intel_rps_set_max_frequency(&gt->rps, val);
}

static ssize_t max_freq_mhz_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buff, size_t count)
{
	int ret;
	u32 val;

	ret = kstrtou32(buff, 0, &val);
	if (ret)
		return ret;

	ret = sysfs_gt_attribute_w_func(dev, attr, __set_max_freq, val);

	return ret ?: count;
}

static u32 __min_freq_mhz_show(struct intel_gt *gt)
{
	return intel_rps_get_min_frequency(&gt->rps);
}

static ssize_t min_freq_mhz_show(struct device *dev,
				 struct device_attribute *attr, char *buff)
{
	u32 min_freq = sysfs_gt_attribute_r_min_func(dev, attr,
						     __min_freq_mhz_show);

	return sysfs_emit(buff, "%u\n", min_freq);
}

static int __set_min_freq(struct intel_gt *gt, u32 val)
{
	return intel_rps_set_min_frequency(&gt->rps, val);
}

static ssize_t min_freq_mhz_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buff, size_t count)
{
	int ret;
	u32 val;

	ret = kstrtou32(buff, 0, &val);
	if (ret)
		return ret;

	ret = sysfs_gt_attribute_w_func(dev, attr, __set_min_freq, val);

	return ret ?: count;
}

static u32 __vlv_rpe_freq_mhz_show(struct intel_gt *gt)
{
	struct intel_rps *rps = &gt->rps;

	return intel_gpu_freq(rps, rps->efficient_freq);
}

static ssize_t vlv_rpe_freq_mhz_show(struct device *dev,
				     struct device_attribute *attr, char *buff)
{
	u32 rpe_freq = sysfs_gt_attribute_r_max_func(dev, attr,
						 __vlv_rpe_freq_mhz_show);

	return sysfs_emit(buff, "%u\n", rpe_freq);
}

#define INTEL_GT_RPS_SYSFS_ATTR(_name, _mode, _show, _store) \
	static struct device_attribute dev_attr_gt_##_name = __ATTR(gt_##_name, _mode, _show, _store); \
	static struct device_attribute dev_attr_rps_##_name = __ATTR(rps_##_name, _mode, _show, _store)

#define INTEL_GT_RPS_SYSFS_ATTR_RO(_name)				\
		INTEL_GT_RPS_SYSFS_ATTR(_name, 0444, _name##_show, NULL)
#define INTEL_GT_RPS_SYSFS_ATTR_RW(_name)				\
		INTEL_GT_RPS_SYSFS_ATTR(_name, 0644, _name##_show, _name##_store)

/* The below macros generate static structures */
INTEL_GT_RPS_SYSFS_ATTR_RO(act_freq_mhz);
INTEL_GT_RPS_SYSFS_ATTR_RO(cur_freq_mhz);
INTEL_GT_RPS_SYSFS_ATTR_RW(boost_freq_mhz);
INTEL_GT_RPS_SYSFS_ATTR_RO(RP0_freq_mhz);
INTEL_GT_RPS_SYSFS_ATTR_RO(RP1_freq_mhz);
INTEL_GT_RPS_SYSFS_ATTR_RO(RPn_freq_mhz);
INTEL_GT_RPS_SYSFS_ATTR_RW(max_freq_mhz);
INTEL_GT_RPS_SYSFS_ATTR_RW(min_freq_mhz);

static DEVICE_ATTR_RO(vlv_rpe_freq_mhz);

#define GEN6_ATTR(s) { \
		&dev_attr_##s##_act_freq_mhz.attr, \
		&dev_attr_##s##_cur_freq_mhz.attr, \
		&dev_attr_##s##_boost_freq_mhz.attr, \
		&dev_attr_##s##_max_freq_mhz.attr, \
		&dev_attr_##s##_min_freq_mhz.attr, \
		&dev_attr_##s##_RP0_freq_mhz.attr, \
		&dev_attr_##s##_RP1_freq_mhz.attr, \
		&dev_attr_##s##_RPn_freq_mhz.attr, \
		NULL, \
	}

#define GEN6_RPS_ATTR GEN6_ATTR(rps)
#define GEN6_GT_ATTR  GEN6_ATTR(gt)

static const struct attribute * const gen6_rps_attrs[] = GEN6_RPS_ATTR;
static const struct attribute * const gen6_gt_attrs[]  = GEN6_GT_ATTR;

static ssize_t punit_req_freq_mhz_show(struct device *dev,
				       struct device_attribute *attr,
				       char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	u32 preq = intel_rps_read_punit_req_frequency(&gt->rps);

	return sysfs_emit(buff, "%u\n", preq);
}

struct intel_gt_bool_throttle_attr {
	struct attribute attr;
	ssize_t (*show)(struct device *dev, struct device_attribute *attr,
			char *buf);
	i915_reg_t reg32;
	u32 mask;
};

static ssize_t throttle_reason_bool_show(struct device *dev,
					 struct device_attribute *attr,
					 char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	struct intel_gt_bool_throttle_attr *t_attr =
				(struct intel_gt_bool_throttle_attr *) attr;
	bool val = rps_read_mask_mmio(&gt->rps, t_attr->reg32, t_attr->mask);

	return sysfs_emit(buff, "%u\n", val);
}

#define INTEL_GT_RPS_BOOL_ATTR_RO(sysfs_func__, mask__) \
struct intel_gt_bool_throttle_attr attr_##sysfs_func__ = { \
	.attr = { .name = __stringify(sysfs_func__), .mode = 0444 }, \
	.show = throttle_reason_bool_show, \
	.reg32 = GT0_PERF_LIMIT_REASONS, \
	.mask = mask__, \
}

static DEVICE_ATTR_RO(punit_req_freq_mhz);
static INTEL_GT_RPS_BOOL_ATTR_RO(throttle_reason_status, GT0_PERF_LIMIT_REASONS_MASK);
static INTEL_GT_RPS_BOOL_ATTR_RO(throttle_reason_pl1, POWER_LIMIT_1_MASK);
static INTEL_GT_RPS_BOOL_ATTR_RO(throttle_reason_pl2, POWER_LIMIT_2_MASK);
static INTEL_GT_RPS_BOOL_ATTR_RO(throttle_reason_pl4, POWER_LIMIT_4_MASK);
static INTEL_GT_RPS_BOOL_ATTR_RO(throttle_reason_thermal, THERMAL_LIMIT_MASK);
static INTEL_GT_RPS_BOOL_ATTR_RO(throttle_reason_prochot, PROCHOT_MASK);
static INTEL_GT_RPS_BOOL_ATTR_RO(throttle_reason_ratl, RATL_MASK);
static INTEL_GT_RPS_BOOL_ATTR_RO(throttle_reason_vr_thermalert, VR_THERMALERT_MASK);
static INTEL_GT_RPS_BOOL_ATTR_RO(throttle_reason_vr_tdc, VR_TDC_MASK);

static const struct attribute *throttle_reason_attrs[] = {
	&attr_throttle_reason_status.attr,
	&attr_throttle_reason_pl1.attr,
	&attr_throttle_reason_pl2.attr,
	&attr_throttle_reason_pl4.attr,
	&attr_throttle_reason_thermal.attr,
	&attr_throttle_reason_prochot.attr,
	&attr_throttle_reason_ratl.attr,
	&attr_throttle_reason_vr_thermalert.attr,
	&attr_throttle_reason_vr_tdc.attr,
	NULL
};

/*
 * Scaling for multipliers (aka frequency factors).
 * The format of the value in the register is u8.8.
 *
 * The presentation to userspace is inspired by the perf event framework.
 * See:
 *   Documentation/ABI/testing/sysfs-bus-event_source-devices-events
 * for description of:
 *   /sys/bus/event_source/devices/<pmu>/events/<event>.scale
 *
 * Summary: Expose two sysfs files for each multiplier.
 *
 * 1. File <attr> contains a raw hardware value.
 * 2. File <attr>.scale contains the multiplicative scale factor to be
 *    used by userspace to compute the actual value.
 *
 * So userspace knows that to get the frequency_factor it multiplies the
 * provided value by the specified scale factor and vice-versa.
 *
 * That way there is no precision loss in the kernel interface and API
 * is future proof should one day the hardware register change to u16.u16,
 * on some platform. (Or any other fixed point representation.)
 *
 * Example:
 * File <attr> contains the value 2.5, represented as u8.8 0x0280, which
 * is comprised of:
 * - an integer part of 2
 * - a fractional part of 0x80 (representing 0x80 / 2^8 == 0x80 / 256).
 * File <attr>.scale contains a string representation of floating point
 * value 0.00390625 (which is (1 / 256)).
 * Userspace computes the actual value:
 *   0x0280 * 0.00390625 -> 2.5
 * or converts an actual value to the value to be written into <attr>:
 *   2.5 / 0.00390625 -> 0x0280
 */

#define U8_8_VAL_MASK           0xffff
#define U8_8_SCALE_TO_VALUE     "0.00390625"

static ssize_t freq_factor_scale_show(struct device *dev,
				      struct device_attribute *attr,
				      char *buff)
{
	return sysfs_emit(buff, "%s\n", U8_8_SCALE_TO_VALUE);
}

static u32 media_ratio_mode_to_factor(u32 mode)
{
	/* 0 -> 0, 1 -> 256, 2 -> 128 */
	return !mode ? mode : 256 / mode;
}

static ssize_t media_freq_factor_show(struct device *dev,
				      struct device_attribute *attr,
				      char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	struct intel_guc_slpc *slpc = &gt->uc.guc.slpc;
	intel_wakeref_t wakeref;
	u32 mode;

	/*
	 * Retrieve media_ratio_mode from GEN6_RPNSWREQ bit 13 set by
	 * GuC. GEN6_RPNSWREQ:13 value 0 represents 1:2 and 1 represents 1:1
	 */
	if (IS_XEHPSDV(gt->i915) &&
	    slpc->media_ratio_mode == SLPC_MEDIA_RATIO_MODE_DYNAMIC_CONTROL) {
		/*
		 * For XEHPSDV dynamic mode GEN6_RPNSWREQ:13 does not contain
		 * the media_ratio_mode, just return the cached media ratio
		 */
		mode = slpc->media_ratio_mode;
	} else {
		with_intel_runtime_pm(gt->uncore->rpm, wakeref)
			mode = intel_uncore_read(gt->uncore, GEN6_RPNSWREQ);
		mode = REG_FIELD_GET(GEN12_MEDIA_FREQ_RATIO, mode) ?
			SLPC_MEDIA_RATIO_MODE_FIXED_ONE_TO_ONE :
			SLPC_MEDIA_RATIO_MODE_FIXED_ONE_TO_TWO;
	}

	return sysfs_emit(buff, "%u\n", media_ratio_mode_to_factor(mode));
}

static ssize_t media_freq_factor_store(struct device *dev,
				       struct device_attribute *attr,
				       const char *buff, size_t count)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	struct intel_guc_slpc *slpc = &gt->uc.guc.slpc;
	u32 factor, mode;
	int err;

	err = kstrtou32(buff, 0, &factor);
	if (err)
		return err;

	for (mode = SLPC_MEDIA_RATIO_MODE_DYNAMIC_CONTROL;
	     mode <= SLPC_MEDIA_RATIO_MODE_FIXED_ONE_TO_TWO; mode++)
		if (factor == media_ratio_mode_to_factor(mode))
			break;

	if (mode > SLPC_MEDIA_RATIO_MODE_FIXED_ONE_TO_TWO)
		return -EINVAL;

	err = intel_guc_slpc_set_media_ratio_mode(slpc, mode);
	if (!err) {
		slpc->media_ratio_mode = mode;
		DRM_DEBUG("Set slpc->media_ratio_mode to %d", mode);
	}
	return err ?: count;
}

static ssize_t media_RP0_freq_mhz_show(struct device *dev,
				       struct device_attribute *attr,
				       char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	u32 val;
	int err;

	err = snb_pcode_read_p(gt->uncore, XEHP_PCODE_FREQUENCY_CONFIG,
			       PCODE_MBOX_FC_SC_READ_FUSED_P0,
			       PCODE_MBOX_DOMAIN_MEDIAFF, &val);

	if (err)
		return err;

	/* Fused media RP0 read from pcode is in units of 50 MHz */
	val *= GT_FREQUENCY_MULTIPLIER;

	return sysfs_emit(buff, "%u\n", val);
}

static ssize_t media_RPn_freq_mhz_show(struct device *dev,
				       struct device_attribute *attr,
				       char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	u32 val;
	int err;

	err = snb_pcode_read_p(gt->uncore, XEHP_PCODE_FREQUENCY_CONFIG,
			       PCODE_MBOX_FC_SC_READ_FUSED_PN,
			       PCODE_MBOX_DOMAIN_MEDIAFF, &val);

	if (err)
		return err;

	/* Fused media RPn read from pcode is in units of 50 MHz */
	val *= GT_FREQUENCY_MULTIPLIER;

	return sysfs_emit(buff, "%u\n", val);
}

static DEVICE_ATTR_RW(media_freq_factor);
static struct device_attribute dev_attr_media_freq_factor_scale =
	__ATTR(media_freq_factor.scale, 0444, freq_factor_scale_show, NULL);
static DEVICE_ATTR_RO(media_RP0_freq_mhz);
static DEVICE_ATTR_RO(media_RPn_freq_mhz);

static const struct attribute *media_perf_power_attrs[] = {
	&dev_attr_media_freq_factor.attr,
	&dev_attr_media_freq_factor_scale.attr,
	&dev_attr_media_RP0_freq_mhz.attr,
	&dev_attr_media_RPn_freq_mhz.attr,
	NULL
};

static int intel_sysfs_rps_init(struct intel_gt *gt, struct kobject *kobj,
				const struct attribute * const *attrs)
{
	int ret;

	if (GRAPHICS_VER(gt->i915) < 6)
		return 0;

	ret = sysfs_create_files(kobj, attrs);
	if (ret)
		return ret;

	if (IS_VALLEYVIEW(gt->i915) || IS_CHERRYVIEW(gt->i915))
		ret = sysfs_create_file(kobj, &dev_attr_vlv_rpe_freq_mhz.attr);

	return ret;
}

void intel_gt_sysfs_pm_init(struct intel_gt *gt, struct kobject *kobj)
{
	int ret;

	intel_sysfs_rc6_init(gt, kobj);

	ret = is_object_gt(kobj) ?
	      intel_sysfs_rps_init(gt, kobj, gen6_rps_attrs) :
	      intel_sysfs_rps_init(gt, kobj, gen6_gt_attrs);
	if (ret)
		drm_warn(&gt->i915->drm,
			 "failed to create gt%u RPS sysfs files (%pe)",
			 gt->info.id, ERR_PTR(ret));

	/* end of the legacy interfaces */
	if (!is_object_gt(kobj))
		return;

	ret = sysfs_create_file(kobj, &dev_attr_punit_req_freq_mhz.attr);
	if (ret)
		drm_warn(&gt->i915->drm,
			 "failed to create gt%u punit_req_freq_mhz sysfs (%pe)",
			 gt->info.id, ERR_PTR(ret));

	if (GRAPHICS_VER(gt->i915) >= 11) {
		ret = sysfs_create_files(kobj, throttle_reason_attrs);
		if (ret)
			drm_warn(&gt->i915->drm,
				 "failed to create gt%u throttle sysfs files (%pe)",
				 gt->info.id, ERR_PTR(ret));
	}

	if (HAS_MEDIA_RATIO_MODE(gt->i915) && intel_uc_uses_guc_slpc(&gt->uc)) {
		ret = sysfs_create_files(kobj, media_perf_power_attrs);
		if (ret)
			drm_warn(&gt->i915->drm,
				 "failed to create gt%u media_perf_power_attrs sysfs (%pe)\n",
				 gt->info.id, ERR_PTR(ret));
	}
}
