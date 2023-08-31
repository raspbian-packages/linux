// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2012-2014 Broadcom Corporation


#include <linux/init.h>
#include <linux/printk.h>
#include <asm/hardware/cache-l2x0.h>

#include "bcm_kona_smc.h"
#include "kona_l2_cache.h"

void __init kona_l2_cache_init(void)
{
	unsigned int result;
	int ret;

	ret = bcm_kona_smc_init();
	if (ret) {
		pr_info("Secure API not available (%d). Skipping L2 init.\n",
			ret);
		return;
	}

	result = bcm_kona_smc(SSAPI_ENABLE_L2_CACHE, 0, 0, 0, 0);
	if (result != SEC_ROM_RET_OK) {
		pr_err("Secure Monitor call failed (%u)! Skipping L2 init.\n",
			result);
		return;
	}

	/*
	 * The aux_val and aux_mask have no effect since L2 cache is already
	 * enabled.  Pass 0s for aux_val and 1s for aux_mask for default value.
	 */
	ret = l2x0_of_init(0, ~0);
	if (ret)
		pr_err("Couldn't enable L2 cache: %d\n", ret);
}
