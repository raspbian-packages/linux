/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2023 Intel Corporation
 */

#ifndef _XE_SRIOV_H_
#define _XE_SRIOV_H_

#include "xe_assert.h"
#include "xe_device_types.h"
#include "xe_sriov_types.h"

const char *xe_sriov_mode_to_string(enum xe_sriov_mode mode);

void xe_sriov_probe_early(struct xe_device *xe, bool has_sriov);

static inline enum xe_sriov_mode xe_device_sriov_mode(struct xe_device *xe)
{
	xe_assert(xe, xe->sriov.__mode);
	return xe->sriov.__mode;
}

static inline bool xe_device_is_sriov_pf(struct xe_device *xe)
{
	return xe_device_sriov_mode(xe) == XE_SRIOV_MODE_PF;
}

static inline bool xe_device_is_sriov_vf(struct xe_device *xe)
{
	return xe_device_sriov_mode(xe) == XE_SRIOV_MODE_VF;
}

#ifdef CONFIG_PCI_IOV
#define IS_SRIOV_PF(xe) xe_device_is_sriov_pf(xe)
#else
#define IS_SRIOV_PF(xe) (typecheck(struct xe_device *, (xe)) && false)
#endif
#define IS_SRIOV_VF(xe) xe_device_is_sriov_vf(xe)

#define IS_SRIOV(xe) (IS_SRIOV_PF(xe) || IS_SRIOV_VF(xe))

#endif
