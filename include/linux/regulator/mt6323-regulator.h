/*
 * Copyright (c) 2016 MediaTek Inc.
 * Author: Chen Zhong <chen.zhong@mediatek.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __LINUX_REGULATOR_MT6323_H
#define __LINUX_REGULATOR_MT6323_H

enum {
	MT6323_ID_VPROC = 0,
	MT6323_ID_VSYS,
	MT6323_ID_VPA,
	MT6323_ID_VTCXO,
	MT6323_ID_VCN28,
	MT6323_ID_VCN33_BT,
	MT6323_ID_VCN33_WIFI,
	MT6323_ID_VA,
	MT6323_ID_VCAMA,
	MT6323_ID_VIO28 = 9,
	MT6323_ID_VUSB,
	MT6323_ID_VMC,
	MT6323_ID_VMCH,
	MT6323_ID_VEMC3V3,
	MT6323_ID_VGP1,
	MT6323_ID_VGP2,
	MT6323_ID_VGP3,
	MT6323_ID_VCN18,
	MT6323_ID_VSIM1,
	MT6323_ID_VSIM2,
	MT6323_ID_VRTC,
	MT6323_ID_VCAMAF,
	MT6323_ID_VIBR,
	MT6323_ID_VRF18,
	MT6323_ID_VM,
	MT6323_ID_VIO18,
	MT6323_ID_VCAMD,
	MT6323_ID_VCAMIO,
	MT6323_ID_RG_MAX,
};

#define MT6323_MAX_REGULATOR	MT6323_ID_RG_MAX

#endif /* __LINUX_REGULATOR_MT6323_H */
