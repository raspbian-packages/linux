/******************************************************************************
 *
 * Copyright(c) 2007 - 2011 Realtek Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 ******************************************************************************/
#ifndef __DRV_TYPES_SDIO_H__
#define __DRV_TYPES_SDIO_H__

/*  SDIO Header Files */
	#include <linux/mmc/sdio_func.h>
	#include <linux/mmc/sdio_ids.h>

#if defined(CONFIG_WOWLAN) || defined(CONFIG_AP_WOWLAN)
	#include <linux/mmc/host.h>
	#include <linux/mmc/card.h>
#endif

typedef struct sdio_data
{
	u8  func_number;

	u8  tx_block_mode;
	u8  rx_block_mode;
	u32 block_transfer_len;

	struct sdio_func	 *func;
	void *sys_sdio_irq_thd;
} SDIO_DATA, *PSDIO_DATA;

#endif
