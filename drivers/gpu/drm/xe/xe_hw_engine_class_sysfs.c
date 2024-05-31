// SPDX-License-Identifier: MIT
/*
 * Copyright © 2023 Intel Corporation
 */

#include <drm/drm_managed.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

#include "xe_gt.h"
#include "xe_hw_engine_class_sysfs.h"

#define MAX_ENGINE_CLASS_NAME_LEN    16
static int xe_add_hw_engine_class_defaults(struct xe_device *xe,
					   struct kobject *parent);

/**
 * xe_hw_engine_timeout_in_range - Helper to check if timeout is in range
 * @timeout: timeout to validate
 * @min: min value of valid range
 * @max: max value of valid range
 *
 * This helper helps to validate if timeout is in min-max range of HW engine
 * scheduler.
 *
 * Returns: Returns false value for failure and true for success.
 */
bool xe_hw_engine_timeout_in_range(u64 timeout, u64 min, u64 max)
{
	return timeout >= min && timeout <= max;
}

static void kobj_xe_hw_engine_release(struct kobject *kobj)
{
	kfree(kobj);
}

static const struct kobj_type kobj_xe_hw_engine_type = {
	.release = kobj_xe_hw_engine_release,
	.sysfs_ops = &kobj_sysfs_ops
};

static ssize_t job_timeout_max_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj);
	u32 timeout;
	int err;

	err = kstrtou32(buf, 0, &timeout);
	if (err)
		return err;

	if (timeout < eclass->sched_props.job_timeout_min)
		return -EINVAL;

	if (!xe_hw_engine_timeout_in_range(timeout,
					   XE_HW_ENGINE_JOB_TIMEOUT_MIN,
					   XE_HW_ENGINE_JOB_TIMEOUT_MAX))
		return -EINVAL;

	WRITE_ONCE(eclass->sched_props.job_timeout_max, timeout);

	return count;
}

static ssize_t job_timeout_max_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj);

	return sprintf(buf, "%u\n", eclass->sched_props.job_timeout_max);
}

static struct kobj_attribute job_timeout_max_attr =
__ATTR(job_timeout_max, 0644, job_timeout_max_show, job_timeout_max_store);

static ssize_t job_timeout_min_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj);
	u32 timeout;
	int err;

	err = kstrtou32(buf, 0, &timeout);
	if (err)
		return err;

	if (timeout > eclass->sched_props.job_timeout_max)
		return -EINVAL;

	if (!xe_hw_engine_timeout_in_range(timeout,
					   XE_HW_ENGINE_JOB_TIMEOUT_MIN,
					   XE_HW_ENGINE_JOB_TIMEOUT_MAX))
		return -EINVAL;

	WRITE_ONCE(eclass->sched_props.job_timeout_min, timeout);

	return count;
}

static ssize_t job_timeout_min_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj);

	return sprintf(buf, "%u\n", eclass->sched_props.job_timeout_min);
}

static struct kobj_attribute job_timeout_min_attr =
__ATTR(job_timeout_min, 0644, job_timeout_min_show, job_timeout_min_store);

static ssize_t job_timeout_store(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buf, size_t count)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj);
	u32 min = eclass->sched_props.job_timeout_min;
	u32 max = eclass->sched_props.job_timeout_max;
	u32 timeout;
	int err;

	err = kstrtou32(buf, 0, &timeout);
	if (err)
		return err;

	if (!xe_hw_engine_timeout_in_range(timeout, min, max))
		return -EINVAL;

	WRITE_ONCE(eclass->sched_props.job_timeout_ms, timeout);

	return count;
}

static ssize_t job_timeout_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj);

	return sprintf(buf, "%u\n", eclass->sched_props.job_timeout_ms);
}

static struct kobj_attribute job_timeout_attr =
__ATTR(job_timeout_ms, 0644, job_timeout_show, job_timeout_store);

static ssize_t job_timeout_default(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj->parent);

	return sprintf(buf, "%u\n", eclass->defaults.job_timeout_ms);
}

static struct kobj_attribute job_timeout_def =
__ATTR(job_timeout_ms, 0444, job_timeout_default, NULL);

static ssize_t job_timeout_min_default(struct kobject *kobj,
				       struct kobj_attribute *attr, char *buf)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj->parent);

	return sprintf(buf, "%u\n", eclass->defaults.job_timeout_min);
}

static struct kobj_attribute job_timeout_min_def =
__ATTR(job_timeout_min, 0444, job_timeout_min_default, NULL);

static ssize_t job_timeout_max_default(struct kobject *kobj,
				       struct kobj_attribute *attr, char *buf)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj->parent);

	return sprintf(buf, "%u\n", eclass->defaults.job_timeout_max);
}

static struct kobj_attribute job_timeout_max_def =
__ATTR(job_timeout_max, 0444, job_timeout_max_default, NULL);

static ssize_t timeslice_duration_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj);
	u32 min = eclass->sched_props.timeslice_min;
	u32 max = eclass->sched_props.timeslice_max;
	u32 duration;
	int err;

	err = kstrtou32(buf, 0, &duration);
	if (err)
		return err;

	if (!xe_hw_engine_timeout_in_range(duration, min, max))
		return -EINVAL;

	WRITE_ONCE(eclass->sched_props.timeslice_us, duration);

	return count;
}

static ssize_t timeslice_duration_max_store(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    const char *buf, size_t count)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj);
	u32 duration;
	int err;

	err = kstrtou32(buf, 0, &duration);
	if (err)
		return err;

	if (duration < eclass->sched_props.timeslice_min)
		return -EINVAL;

	if (!xe_hw_engine_timeout_in_range(duration,
					   XE_HW_ENGINE_TIMESLICE_MIN,
					   XE_HW_ENGINE_TIMESLICE_MAX))
		return -EINVAL;

	WRITE_ONCE(eclass->sched_props.timeslice_max, duration);

	return count;
}

static ssize_t timeslice_duration_max_show(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj);

	return sprintf(buf, "%u\n", eclass->sched_props.timeslice_max);
}

static struct kobj_attribute timeslice_duration_max_attr =
	__ATTR(timeslice_duration_max, 0644, timeslice_duration_max_show,
	       timeslice_duration_max_store);

static ssize_t timeslice_duration_min_store(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    const char *buf, size_t count)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj);
	u32 duration;
	int err;

	err = kstrtou32(buf, 0, &duration);
	if (err)
		return err;

	if (duration > eclass->sched_props.timeslice_max)
		return -EINVAL;

	if (!xe_hw_engine_timeout_in_range(duration,
					   XE_HW_ENGINE_TIMESLICE_MIN,
					   XE_HW_ENGINE_TIMESLICE_MAX))
		return -EINVAL;

	WRITE_ONCE(eclass->sched_props.timeslice_min, duration);

	return count;
}

static ssize_t timeslice_duration_min_show(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj);

	return sprintf(buf, "%u\n", eclass->sched_props.timeslice_min);
}

static struct kobj_attribute timeslice_duration_min_attr =
	__ATTR(timeslice_duration_min, 0644, timeslice_duration_min_show,
	       timeslice_duration_min_store);

static ssize_t timeslice_duration_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *buf)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj);

	return sprintf(buf, "%u\n", eclass->sched_props.timeslice_us);
}

static struct kobj_attribute timeslice_duration_attr =
	__ATTR(timeslice_duration_us, 0644, timeslice_duration_show,
	       timeslice_duration_store);

static ssize_t timeslice_default(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj->parent);

	return sprintf(buf, "%u\n", eclass->defaults.timeslice_us);
}

static struct kobj_attribute timeslice_duration_def =
__ATTR(timeslice_duration_us, 0444, timeslice_default, NULL);

static ssize_t timeslice_min_default(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj->parent);

	return sprintf(buf, "%u\n", eclass->defaults.timeslice_min);
}

static struct kobj_attribute timeslice_duration_min_def =
__ATTR(timeslice_duration_min, 0444, timeslice_min_default, NULL);

static ssize_t timeslice_max_default(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj->parent);

	return sprintf(buf, "%u\n", eclass->defaults.timeslice_max);
}

static struct kobj_attribute timeslice_duration_max_def =
__ATTR(timeslice_duration_max, 0444, timeslice_max_default, NULL);

static ssize_t preempt_timeout_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj);
	u32 min = eclass->sched_props.preempt_timeout_min;
	u32 max = eclass->sched_props.preempt_timeout_max;
	u32 timeout;
	int err;

	err = kstrtou32(buf, 0, &timeout);
	if (err)
		return err;

	if (!xe_hw_engine_timeout_in_range(timeout, min, max))
		return -EINVAL;

	WRITE_ONCE(eclass->sched_props.preempt_timeout_us, timeout);

	return count;
}

static ssize_t preempt_timeout_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj);

	return sprintf(buf, "%u\n", eclass->sched_props.preempt_timeout_us);
}

static struct kobj_attribute preempt_timeout_attr =
__ATTR(preempt_timeout_us, 0644, preempt_timeout_show, preempt_timeout_store);

static ssize_t preempt_timeout_default(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       char *buf)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj->parent);

	return sprintf(buf, "%u\n", eclass->defaults.preempt_timeout_us);
}

static struct kobj_attribute preempt_timeout_def =
__ATTR(preempt_timeout_us, 0444, preempt_timeout_default, NULL);

static ssize_t preempt_timeout_min_default(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj->parent);

	return sprintf(buf, "%u\n", eclass->defaults.preempt_timeout_min);
}

static struct kobj_attribute preempt_timeout_min_def =
__ATTR(preempt_timeout_min, 0444, preempt_timeout_min_default, NULL);

static ssize_t preempt_timeout_max_default(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj->parent);

	return sprintf(buf, "%u\n", eclass->defaults.preempt_timeout_max);
}

static struct kobj_attribute preempt_timeout_max_def =
__ATTR(preempt_timeout_max, 0444, preempt_timeout_max_default, NULL);

static ssize_t preempt_timeout_max_store(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj);
	u32 timeout;
	int err;

	err = kstrtou32(buf, 0, &timeout);
	if (err)
		return err;

	if (timeout < eclass->sched_props.preempt_timeout_min)
		return -EINVAL;

	if (!xe_hw_engine_timeout_in_range(timeout,
					   XE_HW_ENGINE_PREEMPT_TIMEOUT_MIN,
					   XE_HW_ENGINE_PREEMPT_TIMEOUT_MAX))
		return -EINVAL;

	WRITE_ONCE(eclass->sched_props.preempt_timeout_max, timeout);

	return count;
}

static ssize_t preempt_timeout_max_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj);

	return sprintf(buf, "%u\n", eclass->sched_props.preempt_timeout_max);
}

static struct kobj_attribute preempt_timeout_max_attr =
	__ATTR(preempt_timeout_max, 0644, preempt_timeout_max_show,
	       preempt_timeout_max_store);

static ssize_t preempt_timeout_min_store(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj);
	u32 timeout;
	int err;

	err = kstrtou32(buf, 0, &timeout);
	if (err)
		return err;

	if (timeout > eclass->sched_props.preempt_timeout_max)
		return -EINVAL;

	if (!xe_hw_engine_timeout_in_range(timeout,
					   XE_HW_ENGINE_PREEMPT_TIMEOUT_MIN,
					   XE_HW_ENGINE_PREEMPT_TIMEOUT_MAX))
		return -EINVAL;

	WRITE_ONCE(eclass->sched_props.preempt_timeout_min, timeout);

	return count;
}

static ssize_t preempt_timeout_min_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	struct xe_hw_engine_class_intf *eclass = kobj_to_eclass(kobj);

	return sprintf(buf, "%u\n", eclass->sched_props.preempt_timeout_min);
}

static struct kobj_attribute preempt_timeout_min_attr =
	__ATTR(preempt_timeout_min, 0644, preempt_timeout_min_show,
	       preempt_timeout_min_store);

static const struct attribute *defaults[] = {
	&job_timeout_def.attr,
	&job_timeout_min_def.attr,
	&job_timeout_max_def.attr,
	&timeslice_duration_def.attr,
	&timeslice_duration_min_def.attr,
	&timeslice_duration_max_def.attr,
	&preempt_timeout_def.attr,
	&preempt_timeout_min_def.attr,
	&preempt_timeout_max_def.attr,
	NULL
};

static const struct attribute *files[] = {
	&job_timeout_attr.attr,
	&job_timeout_min_attr.attr,
	&job_timeout_max_attr.attr,
	&timeslice_duration_attr.attr,
	&timeslice_duration_min_attr.attr,
	&timeslice_duration_max_attr.attr,
	&preempt_timeout_attr.attr,
	&preempt_timeout_min_attr.attr,
	&preempt_timeout_max_attr.attr,
	NULL
};

static void kobj_xe_hw_engine_class_fini(struct drm_device *drm, void *arg)
{
	struct kobject *kobj = arg;

	sysfs_remove_files(kobj, files);
	kobject_put(kobj);
}

	static struct kobj_eclass *
kobj_xe_hw_engine_class(struct xe_device *xe, struct kobject *parent, char *name)
{
	struct kobj_eclass *keclass;
	int err = 0;

	keclass = kzalloc(sizeof(*keclass), GFP_KERNEL);
	if (!keclass)
		return NULL;

	kobject_init(&keclass->base, &kobj_xe_hw_engine_type);
	if (kobject_add(&keclass->base, parent, "%s", name)) {
		kobject_put(&keclass->base);
		return NULL;
	}

	err = drmm_add_action_or_reset(&xe->drm, kobj_xe_hw_engine_class_fini,
				       &keclass->base);
	if (err)
		drm_warn(&xe->drm,
			 "%s: drmm_add_action_or_reset failed, err: %d\n",
			 __func__, err);
	return keclass;
}

static void hw_engine_class_defaults_fini(struct drm_device *drm, void *arg)
{
	struct kobject *kobj = arg;

	sysfs_remove_files(kobj, defaults);
	kobject_put(kobj);
}

static int xe_add_hw_engine_class_defaults(struct xe_device *xe,
					   struct kobject *parent)
{
	struct kobject *kobj;
	int err = 0;

	kobj = kzalloc(sizeof(*kobj), GFP_KERNEL);
	if (!kobj)
		return -ENOMEM;

	kobject_init(kobj, &kobj_xe_hw_engine_type);
	err = kobject_add(kobj, parent, "%s", ".defaults");
	if (err)
		goto err_object;

	err = sysfs_create_files(kobj, defaults);
	if (err)
		goto err_object;

	err = drmm_add_action_or_reset(&xe->drm, hw_engine_class_defaults_fini,
				       kobj);
	if (err)
		drm_warn(&xe->drm,
			 "%s: drmm_add_action_or_reset failed, err: %d\n",
			 __func__, err);
	return err;
err_object:
	kobject_put(kobj);
	return err;
}

static void xe_hw_engine_sysfs_kobj_release(struct kobject *kobj)
{
	kfree(kobj);
}

static const struct kobj_type xe_hw_engine_sysfs_kobj_type = {
	.release = xe_hw_engine_sysfs_kobj_release,
	.sysfs_ops = &kobj_sysfs_ops,
};

static void hw_engine_class_sysfs_fini(struct drm_device *drm, void *arg)
{
	struct kobject *kobj = arg;

	kobject_put(kobj);
}

/**
 * xe_hw_engine_class_sysfs_init - Init HW engine classes on GT.
 * @gt: Xe GT.
 *
 * This routine creates sysfs for HW engine classes and adds methods
 * to get/set different scheduling properties for HW engines class.
 *
 * Returns: Returns error value for failure and 0 for success.
 */
int xe_hw_engine_class_sysfs_init(struct xe_gt *gt)
{
	struct xe_device *xe = gt_to_xe(gt);
	struct xe_hw_engine *hwe;
	enum xe_hw_engine_id id;
	struct kobject *kobj;
	u16 class_mask = 0;
	int err = 0;

	kobj = kzalloc(sizeof(*kobj), GFP_KERNEL);
	if (!kobj)
		return -ENOMEM;

	kobject_init(kobj, &xe_hw_engine_sysfs_kobj_type);

	err = kobject_add(kobj, gt->sysfs, "engines");
	if (err)
		goto err_object;

	for_each_hw_engine(hwe, gt, id) {
		char name[MAX_ENGINE_CLASS_NAME_LEN];
		struct kobj_eclass *keclass;

		if (hwe->class == XE_ENGINE_CLASS_OTHER ||
		    hwe->class == XE_ENGINE_CLASS_MAX)
			continue;

		if ((class_mask >> hwe->class) & 1)
			continue;

		class_mask |= 1 << hwe->class;

		switch (hwe->class) {
		case XE_ENGINE_CLASS_RENDER:
			strcpy(name, "rcs");
			break;
		case XE_ENGINE_CLASS_VIDEO_DECODE:
			strcpy(name, "vcs");
			break;
		case XE_ENGINE_CLASS_VIDEO_ENHANCE:
			strcpy(name, "vecs");
			break;
		case XE_ENGINE_CLASS_COPY:
			strcpy(name, "bcs");
			break;
		case XE_ENGINE_CLASS_COMPUTE:
			strcpy(name, "ccs");
			break;
		default:
			err = -EINVAL;
			goto err_object;
		}

		keclass = kobj_xe_hw_engine_class(xe, kobj, name);
		if (!keclass) {
			err = -EINVAL;
			goto err_object;
		}

		keclass->eclass = hwe->eclass;
		err = xe_add_hw_engine_class_defaults(xe, &keclass->base);
		if (err) {
			drm_warn(&xe->drm,
				 "Add .defaults to engines failed!, err: %d\n",
				 err);
			goto err_object;
		}

		err = sysfs_create_files(&keclass->base, files);
		if (err)
			goto err_object;
	}

	err = drmm_add_action_or_reset(&xe->drm, hw_engine_class_sysfs_fini,
				       kobj);
	if (err)
		drm_warn(&xe->drm,
			 "%s: drmm_add_action_or_reset failed, err: %d\n",
			 __func__, err);

	return err;
err_object:
	kobject_put(kobj);
	return err;
}
