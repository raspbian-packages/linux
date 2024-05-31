/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */

#ifndef _XE_GUC_LOG_H_
#define _XE_GUC_LOG_H_

#include "xe_guc_log_types.h"

struct drm_printer;

#if IS_ENABLED(CONFIG_DRM_XE_LARGE_GUC_BUFFER)
#define CRASH_BUFFER_SIZE       SZ_1M
#define DEBUG_BUFFER_SIZE       SZ_8M
#define CAPTURE_BUFFER_SIZE     SZ_2M
#else
#define CRASH_BUFFER_SIZE	SZ_8K
#define DEBUG_BUFFER_SIZE	SZ_64K
#define CAPTURE_BUFFER_SIZE	SZ_16K
#endif
/*
 * While we're using plain log level in i915, GuC controls are much more...
 * "elaborate"? We have a couple of bits for verbosity, separate bit for actual
 * log enabling, and separate bit for default logging - which "conveniently"
 * ignores the enable bit.
 */
#define GUC_LOG_LEVEL_DISABLED		0
#define GUC_LOG_LEVEL_NON_VERBOSE	1
#define GUC_LOG_LEVEL_IS_ENABLED(x)	((x) > GUC_LOG_LEVEL_DISABLED)
#define GUC_LOG_LEVEL_IS_VERBOSE(x)	((x) > GUC_LOG_LEVEL_NON_VERBOSE)
#define GUC_LOG_LEVEL_TO_VERBOSITY(x) ({		\
	typeof(x) _x = (x);				\
	GUC_LOG_LEVEL_IS_VERBOSE(_x) ? _x - 2 : 0;	\
})
#define GUC_VERBOSITY_TO_LOG_LEVEL(x)	((x) + 2)
#define GUC_LOG_LEVEL_MAX GUC_VERBOSITY_TO_LOG_LEVEL(GUC_LOG_VERBOSITY_MAX)

int xe_guc_log_init(struct xe_guc_log *log);
void xe_guc_log_print(struct xe_guc_log *log, struct drm_printer *p);

static inline u32
xe_guc_log_get_level(struct xe_guc_log *log)
{
	return log->level;
}

#endif
