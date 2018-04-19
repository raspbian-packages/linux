/******************************************************************************
 *
 * Copyright(c) 2007 - 2016  Realtek Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in the
 * file called LICENSE.
 *
 * Contact Information:
 * wlanfae <wlanfae@realtek.com>
 * Realtek Corporation, No. 2, Innovation Road II, Hsinchu Science Park,
 * Hsinchu 300, Taiwan.
 *
 * Larry Finger <Larry.Finger@lwfinger.net>
 *
 *****************************************************************************/

#ifndef __PHYDMEDCATURBOCHECK_H__
#define __PHYDMEDCATURBOCHECK_H__

/*#define EDCATURBO_VERSION	"2.1"*/
#define EDCATURBO_VERSION "2.3" /*2015.07.29 by YuChen*/

struct edca_turbo {
	bool is_current_turbo_edca;
	bool is_cur_rdl_state;

	u32 prv_traffic_idx; /* edca turbo */
};

void odm_edca_turbo_check(void *dm_void);
void odm_edca_turbo_init(void *dm_void);

void odm_edca_turbo_check_ce(void *dm_void);

#endif
