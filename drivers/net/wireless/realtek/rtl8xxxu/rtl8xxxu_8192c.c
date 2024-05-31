// SPDX-License-Identifier: GPL-2.0-only
/*
 * RTL8XXXU mac80211 USB driver - 8188c/8188r/8192c specific subdriver
 *
 * Copyright (c) 2014 - 2017 Jes Sorensen <Jes.Sorensen@gmail.com>
 *
 * Portions, notably calibration code:
 * Copyright(c) 2007 - 2011 Realtek Corporation. All rights reserved.
 *
 * This driver was written as a replacement for the vendor provided
 * rtl8723au driver. As the Realtek 8xxx chips are very similar in
 * their programming interface, I have started adding support for
 * additional 8xxx chips like the 8192cu, 8188cus, etc.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/usb.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/wireless.h>
#include <linux/firmware.h>
#include <linux/moduleparam.h>
#include <net/mac80211.h>
#include "rtl8xxxu.h"
#include "rtl8xxxu_regs.h"

#ifdef CONFIG_RTL8XXXU_UNTESTED
static struct rtl8xxxu_power_base rtl8192c_power_base = {
	.reg_0e00 = 0x07090c0c,
	.reg_0e04 = 0x01020405,
	.reg_0e08 = 0x00000000,
	.reg_086c = 0x00000000,

	.reg_0e10 = 0x0b0c0c0e,
	.reg_0e14 = 0x01030506,
	.reg_0e18 = 0x0b0c0d0e,
	.reg_0e1c = 0x01030509,

	.reg_0830 = 0x07090c0c,
	.reg_0834 = 0x01020405,
	.reg_0838 = 0x00000000,
	.reg_086c_2 = 0x00000000,

	.reg_083c = 0x0b0c0d0e,
	.reg_0848 = 0x01030509,
	.reg_084c = 0x0b0c0d0e,
	.reg_0868 = 0x01030509,
};

static struct rtl8xxxu_power_base rtl8188r_power_base = {
	.reg_0e00 = 0x06080808,
	.reg_0e04 = 0x00040406,
	.reg_0e08 = 0x00000000,
	.reg_086c = 0x00000000,

	.reg_0e10 = 0x04060608,
	.reg_0e14 = 0x00020204,
	.reg_0e18 = 0x04060608,
	.reg_0e1c = 0x00020204,

	.reg_0830 = 0x06080808,
	.reg_0834 = 0x00040406,
	.reg_0838 = 0x00000000,
	.reg_086c_2 = 0x00000000,

	.reg_083c = 0x04060608,
	.reg_0848 = 0x00020204,
	.reg_084c = 0x04060608,
	.reg_0868 = 0x00020204,
};

static const struct rtl8xxxu_rfregval rtl8192cu_radioa_2t_init_table[] = {
	{0x00, 0x00030159}, {0x01, 0x00031284},
	{0x02, 0x00098000}, {0x03, 0x00018c63},
	{0x04, 0x000210e7}, {0x09, 0x0002044f},
	{0x0a, 0x0001adb1}, {0x0b, 0x00054867},
	{0x0c, 0x0008992e}, {0x0d, 0x0000e52c},
	{0x0e, 0x00039ce7}, {0x0f, 0x00000451},
	{0x19, 0x00000000}, {0x1a, 0x00010255},
	{0x1b, 0x00060a00}, {0x1c, 0x000fc378},
	{0x1d, 0x000a1250}, {0x1e, 0x0004445f},
	{0x1f, 0x00080001}, {0x20, 0x0000b614},
	{0x21, 0x0006c000}, {0x22, 0x00000000},
	{0x23, 0x00001558}, {0x24, 0x00000060},
	{0x25, 0x00000483}, {0x26, 0x0004f000},
	{0x27, 0x000ec7d9}, {0x28, 0x000577c0},
	{0x29, 0x00004783}, {0x2a, 0x00000001},
	{0x2b, 0x00021334}, {0x2a, 0x00000000},
	{0x2b, 0x00000054}, {0x2a, 0x00000001},
	{0x2b, 0x00000808}, {0x2b, 0x00053333},
	{0x2c, 0x0000000c}, {0x2a, 0x00000002},
	{0x2b, 0x00000808}, {0x2b, 0x0005b333},
	{0x2c, 0x0000000d}, {0x2a, 0x00000003},
	{0x2b, 0x00000808}, {0x2b, 0x00063333},
	{0x2c, 0x0000000d}, {0x2a, 0x00000004},
	{0x2b, 0x00000808}, {0x2b, 0x0006b333},
	{0x2c, 0x0000000d}, {0x2a, 0x00000005},
	{0x2b, 0x00000808}, {0x2b, 0x00073333},
	{0x2c, 0x0000000d}, {0x2a, 0x00000006},
	{0x2b, 0x00000709}, {0x2b, 0x0005b333},
	{0x2c, 0x0000000d}, {0x2a, 0x00000007},
	{0x2b, 0x00000709}, {0x2b, 0x00063333},
	{0x2c, 0x0000000d}, {0x2a, 0x00000008},
	{0x2b, 0x0000060a}, {0x2b, 0x0004b333},
	{0x2c, 0x0000000d}, {0x2a, 0x00000009},
	{0x2b, 0x0000060a}, {0x2b, 0x00053333},
	{0x2c, 0x0000000d}, {0x2a, 0x0000000a},
	{0x2b, 0x0000060a}, {0x2b, 0x0005b333},
	{0x2c, 0x0000000d}, {0x2a, 0x0000000b},
	{0x2b, 0x0000060a}, {0x2b, 0x00063333},
	{0x2c, 0x0000000d}, {0x2a, 0x0000000c},
	{0x2b, 0x0000060a}, {0x2b, 0x0006b333},
	{0x2c, 0x0000000d}, {0x2a, 0x0000000d},
	{0x2b, 0x0000060a}, {0x2b, 0x00073333},
	{0x2c, 0x0000000d}, {0x2a, 0x0000000e},
	{0x2b, 0x0000050b}, {0x2b, 0x00066666},
	{0x2c, 0x0000001a}, {0x2a, 0x000e0000},
	{0x10, 0x0004000f}, {0x11, 0x000e31fc},
	{0x10, 0x0006000f}, {0x11, 0x000ff9f8},
	{0x10, 0x0002000f}, {0x11, 0x000203f9},
	{0x10, 0x0003000f}, {0x11, 0x000ff500},
	{0x10, 0x00000000}, {0x11, 0x00000000},
	{0x10, 0x0008000f}, {0x11, 0x0003f100},
	{0x10, 0x0009000f}, {0x11, 0x00023100},
	{0x12, 0x00032000}, {0x12, 0x00071000},
	{0x12, 0x000b0000}, {0x12, 0x000fc000},
	{0x13, 0x000287b3}, {0x13, 0x000244b7},
	{0x13, 0x000204ab}, {0x13, 0x0001c49f},
	{0x13, 0x00018493}, {0x13, 0x0001429b},
	{0x13, 0x00010299}, {0x13, 0x0000c29c},
	{0x13, 0x000081a0}, {0x13, 0x000040ac},
	{0x13, 0x00000020}, {0x14, 0x0001944c},
	{0x14, 0x00059444}, {0x14, 0x0009944c},
	{0x14, 0x000d9444}, {0x15, 0x0000f424},
	{0x15, 0x0004f424}, {0x15, 0x0008f424},
	{0x15, 0x000cf424}, {0x16, 0x000e0330},
	{0x16, 0x000a0330}, {0x16, 0x00060330},
	{0x16, 0x00020330}, {0x00, 0x00010159},
	{0x18, 0x0000f401}, {0xfe, 0x00000000},
	{0xfe, 0x00000000}, {0x1f, 0x00080003},
	{0xfe, 0x00000000}, {0xfe, 0x00000000},
	{0x1e, 0x00044457}, {0x1f, 0x00080000},
	{0x00, 0x00030159},
	{0xff, 0xffffffff}
};

static const struct rtl8xxxu_rfregval rtl8192cu_radiob_2t_init_table[] = {
	{0x00, 0x00030159}, {0x01, 0x00031284},
	{0x02, 0x00098000}, {0x03, 0x00018c63},
	{0x04, 0x000210e7}, {0x09, 0x0002044f},
	{0x0a, 0x0001adb1}, {0x0b, 0x00054867},
	{0x0c, 0x0008992e}, {0x0d, 0x0000e52c},
	{0x0e, 0x00039ce7}, {0x0f, 0x00000451},
	{0x12, 0x00032000}, {0x12, 0x00071000},
	{0x12, 0x000b0000}, {0x12, 0x000fc000},
	{0x13, 0x000287af}, {0x13, 0x000244b7},
	{0x13, 0x000204ab}, {0x13, 0x0001c49f},
	{0x13, 0x00018493}, {0x13, 0x00014297},
	{0x13, 0x00010295}, {0x13, 0x0000c298},
	{0x13, 0x0000819c}, {0x13, 0x000040a8},
	{0x13, 0x0000001c}, {0x14, 0x0001944c},
	{0x14, 0x00059444}, {0x14, 0x0009944c},
	{0x14, 0x000d9444}, {0x15, 0x0000f424},
	{0x15, 0x0004f424}, {0x15, 0x0008f424},
	{0x15, 0x000cf424}, {0x16, 0x000e0330},
	{0x16, 0x000a0330}, {0x16, 0x00060330},
	{0x16, 0x00020330},
	{0xff, 0xffffffff}
};

static const struct rtl8xxxu_rfregval rtl8192cu_radioa_1t_init_table[] = {
	{0x00, 0x00030159}, {0x01, 0x00031284},
	{0x02, 0x00098000}, {0x03, 0x00018c63},
	{0x04, 0x000210e7}, {0x09, 0x0002044f},
	{0x0a, 0x0001adb1}, {0x0b, 0x00054867},
	{0x0c, 0x0008992e}, {0x0d, 0x0000e52c},
	{0x0e, 0x00039ce7}, {0x0f, 0x00000451},
	{0x19, 0x00000000}, {0x1a, 0x00010255},
	{0x1b, 0x00060a00}, {0x1c, 0x000fc378},
	{0x1d, 0x000a1250}, {0x1e, 0x0004445f},
	{0x1f, 0x00080001}, {0x20, 0x0000b614},
	{0x21, 0x0006c000}, {0x22, 0x00000000},
	{0x23, 0x00001558}, {0x24, 0x00000060},
	{0x25, 0x00000483}, {0x26, 0x0004f000},
	{0x27, 0x000ec7d9}, {0x28, 0x000577c0},
	{0x29, 0x00004783}, {0x2a, 0x00000001},
	{0x2b, 0x00021334}, {0x2a, 0x00000000},
	{0x2b, 0x00000054}, {0x2a, 0x00000001},
	{0x2b, 0x00000808}, {0x2b, 0x00053333},
	{0x2c, 0x0000000c}, {0x2a, 0x00000002},
	{0x2b, 0x00000808}, {0x2b, 0x0005b333},
	{0x2c, 0x0000000d}, {0x2a, 0x00000003},
	{0x2b, 0x00000808}, {0x2b, 0x00063333},
	{0x2c, 0x0000000d}, {0x2a, 0x00000004},
	{0x2b, 0x00000808}, {0x2b, 0x0006b333},
	{0x2c, 0x0000000d}, {0x2a, 0x00000005},
	{0x2b, 0x00000808}, {0x2b, 0x00073333},
	{0x2c, 0x0000000d}, {0x2a, 0x00000006},
	{0x2b, 0x00000709}, {0x2b, 0x0005b333},
	{0x2c, 0x0000000d}, {0x2a, 0x00000007},
	{0x2b, 0x00000709}, {0x2b, 0x00063333},
	{0x2c, 0x0000000d}, {0x2a, 0x00000008},
	{0x2b, 0x0000060a}, {0x2b, 0x0004b333},
	{0x2c, 0x0000000d}, {0x2a, 0x00000009},
	{0x2b, 0x0000060a}, {0x2b, 0x00053333},
	{0x2c, 0x0000000d}, {0x2a, 0x0000000a},
	{0x2b, 0x0000060a}, {0x2b, 0x0005b333},
	{0x2c, 0x0000000d}, {0x2a, 0x0000000b},
	{0x2b, 0x0000060a}, {0x2b, 0x00063333},
	{0x2c, 0x0000000d}, {0x2a, 0x0000000c},
	{0x2b, 0x0000060a}, {0x2b, 0x0006b333},
	{0x2c, 0x0000000d}, {0x2a, 0x0000000d},
	{0x2b, 0x0000060a}, {0x2b, 0x00073333},
	{0x2c, 0x0000000d}, {0x2a, 0x0000000e},
	{0x2b, 0x0000050b}, {0x2b, 0x00066666},
	{0x2c, 0x0000001a}, {0x2a, 0x000e0000},
	{0x10, 0x0004000f}, {0x11, 0x000e31fc},
	{0x10, 0x0006000f}, {0x11, 0x000ff9f8},
	{0x10, 0x0002000f}, {0x11, 0x000203f9},
	{0x10, 0x0003000f}, {0x11, 0x000ff500},
	{0x10, 0x00000000}, {0x11, 0x00000000},
	{0x10, 0x0008000f}, {0x11, 0x0003f100},
	{0x10, 0x0009000f}, {0x11, 0x00023100},
	{0x12, 0x00032000}, {0x12, 0x00071000},
	{0x12, 0x000b0000}, {0x12, 0x000fc000},
	{0x13, 0x000287b3}, {0x13, 0x000244b7},
	{0x13, 0x000204ab}, {0x13, 0x0001c49f},
	{0x13, 0x00018493}, {0x13, 0x0001429b},
	{0x13, 0x00010299}, {0x13, 0x0000c29c},
	{0x13, 0x000081a0}, {0x13, 0x000040ac},
	{0x13, 0x00000020}, {0x14, 0x0001944c},
	{0x14, 0x00059444}, {0x14, 0x0009944c},
	{0x14, 0x000d9444}, {0x15, 0x0000f405},
	{0x15, 0x0004f405}, {0x15, 0x0008f405},
	{0x15, 0x000cf405}, {0x16, 0x000e0330},
	{0x16, 0x000a0330}, {0x16, 0x00060330},
	{0x16, 0x00020330}, {0x00, 0x00010159},
	{0x18, 0x0000f401}, {0xfe, 0x00000000},
	{0xfe, 0x00000000}, {0x1f, 0x00080003},
	{0xfe, 0x00000000}, {0xfe, 0x00000000},
	{0x1e, 0x00044457}, {0x1f, 0x00080000},
	{0x00, 0x00030159},
	{0xff, 0xffffffff}
};

static const struct rtl8xxxu_rfregval rtl8188ru_radioa_1t_highpa_table[] = {
	{0x00, 0x00030159}, {0x01, 0x00031284},
	{0x02, 0x00098000}, {0x03, 0x00018c63},
	{0x04, 0x000210e7}, {0x09, 0x0002044f},
	{0x0a, 0x0001adb0}, {0x0b, 0x00054867},
	{0x0c, 0x0008992e}, {0x0d, 0x0000e529},
	{0x0e, 0x00039ce7}, {0x0f, 0x00000451},
	{0x19, 0x00000000}, {0x1a, 0x00000255},
	{0x1b, 0x00060a00}, {0x1c, 0x000fc378},
	{0x1d, 0x000a1250}, {0x1e, 0x0004445f},
	{0x1f, 0x00080001}, {0x20, 0x0000b614},
	{0x21, 0x0006c000}, {0x22, 0x0000083c},
	{0x23, 0x00001558}, {0x24, 0x00000060},
	{0x25, 0x00000483}, {0x26, 0x0004f000},
	{0x27, 0x000ec7d9}, {0x28, 0x000977c0},
	{0x29, 0x00004783}, {0x2a, 0x00000001},
	{0x2b, 0x00021334}, {0x2a, 0x00000000},
	{0x2b, 0x00000054}, {0x2a, 0x00000001},
	{0x2b, 0x00000808}, {0x2b, 0x00053333},
	{0x2c, 0x0000000c}, {0x2a, 0x00000002},
	{0x2b, 0x00000808}, {0x2b, 0x0005b333},
	{0x2c, 0x0000000d}, {0x2a, 0x00000003},
	{0x2b, 0x00000808}, {0x2b, 0x00063333},
	{0x2c, 0x0000000d}, {0x2a, 0x00000004},
	{0x2b, 0x00000808}, {0x2b, 0x0006b333},
	{0x2c, 0x0000000d}, {0x2a, 0x00000005},
	{0x2b, 0x00000808}, {0x2b, 0x00073333},
	{0x2c, 0x0000000d}, {0x2a, 0x00000006},
	{0x2b, 0x00000709}, {0x2b, 0x0005b333},
	{0x2c, 0x0000000d}, {0x2a, 0x00000007},
	{0x2b, 0x00000709}, {0x2b, 0x00063333},
	{0x2c, 0x0000000d}, {0x2a, 0x00000008},
	{0x2b, 0x0000060a}, {0x2b, 0x0004b333},
	{0x2c, 0x0000000d}, {0x2a, 0x00000009},
	{0x2b, 0x0000060a}, {0x2b, 0x00053333},
	{0x2c, 0x0000000d}, {0x2a, 0x0000000a},
	{0x2b, 0x0000060a}, {0x2b, 0x0005b333},
	{0x2c, 0x0000000d}, {0x2a, 0x0000000b},
	{0x2b, 0x0000060a}, {0x2b, 0x00063333},
	{0x2c, 0x0000000d}, {0x2a, 0x0000000c},
	{0x2b, 0x0000060a}, {0x2b, 0x0006b333},
	{0x2c, 0x0000000d}, {0x2a, 0x0000000d},
	{0x2b, 0x0000060a}, {0x2b, 0x00073333},
	{0x2c, 0x0000000d}, {0x2a, 0x0000000e},
	{0x2b, 0x0000050b}, {0x2b, 0x00066666},
	{0x2c, 0x0000001a}, {0x2a, 0x000e0000},
	{0x10, 0x0004000f}, {0x11, 0x000e31fc},
	{0x10, 0x0006000f}, {0x11, 0x000ff9f8},
	{0x10, 0x0002000f}, {0x11, 0x000203f9},
	{0x10, 0x0003000f}, {0x11, 0x000ff500},
	{0x10, 0x00000000}, {0x11, 0x00000000},
	{0x10, 0x0008000f}, {0x11, 0x0003f100},
	{0x10, 0x0009000f}, {0x11, 0x00023100},
	{0x12, 0x000d8000}, {0x12, 0x00090000},
	{0x12, 0x00051000}, {0x12, 0x00012000},
	{0x13, 0x00028fb4}, {0x13, 0x00024fa8},
	{0x13, 0x000207a4}, {0x13, 0x0001c3b0},
	{0x13, 0x000183a4}, {0x13, 0x00014398},
	{0x13, 0x000101a4}, {0x13, 0x0000c198},
	{0x13, 0x000080a4}, {0x13, 0x00004098},
	{0x13, 0x00000000}, {0x14, 0x0001944c},
	{0x14, 0x00059444}, {0x14, 0x0009944c},
	{0x14, 0x000d9444}, {0x15, 0x0000f405},
	{0x15, 0x0004f405}, {0x15, 0x0008f405},
	{0x15, 0x000cf405}, {0x16, 0x000e0330},
	{0x16, 0x000a0330}, {0x16, 0x00060330},
	{0x16, 0x00020330}, {0x00, 0x00010159},
	{0x18, 0x0000f401}, {0xfe, 0x00000000},
	{0xfe, 0x00000000}, {0x1f, 0x00080003},
	{0xfe, 0x00000000}, {0xfe, 0x00000000},
	{0x1e, 0x00044457}, {0x1f, 0x00080000},
	{0x00, 0x00030159},
	{0xff, 0xffffffff}
};

static int rtl8192cu_identify_chip(struct rtl8xxxu_priv *priv)
{
	struct device *dev = &priv->udev->dev;
	u32 val32, bonding, sys_cfg, vendor;
	int ret = 0;

	sys_cfg = rtl8xxxu_read32(priv, REG_SYS_CFG);
	priv->chip_cut = u32_get_bits(sys_cfg, SYS_CFG_CHIP_VERSION_MASK);
	if (sys_cfg & SYS_CFG_TRP_VAUX_EN) {
		dev_info(dev, "Unsupported test chip\n");
		ret = -ENOTSUPP;
		goto out;
	}

	if (sys_cfg & SYS_CFG_TYPE_ID) {
		bonding = rtl8xxxu_read32(priv, REG_HPON_FSM);
		bonding &= HPON_FSM_BONDING_MASK;
		if (bonding == HPON_FSM_BONDING_1T2R) {
			strscpy(priv->chip_name, "8191CU", sizeof(priv->chip_name));
			priv->tx_paths = 1;
			priv->usb_interrupts = 1;
			priv->rtl_chip = RTL8191C;
		} else {
			strscpy(priv->chip_name, "8192CU", sizeof(priv->chip_name));
			priv->tx_paths = 2;
			priv->usb_interrupts = 0;
			priv->rtl_chip = RTL8192C;
		}
		priv->rf_paths = 2;
		priv->rx_paths = 2;
	} else {
		strscpy(priv->chip_name, "8188CU", sizeof(priv->chip_name));
		priv->rf_paths = 1;
		priv->rx_paths = 1;
		priv->tx_paths = 1;
		priv->rtl_chip = RTL8188C;
		priv->usb_interrupts = 0;
	}
	priv->has_wifi = 1;

	vendor = sys_cfg & SYS_CFG_VENDOR_ID;
	rtl8xxxu_identify_vendor_1bit(priv, vendor);

	val32 = rtl8xxxu_read32(priv, REG_GPIO_OUTSTS);
	priv->rom_rev = u32_get_bits(val32, GPIO_RF_RL_ID);

	rtl8xxxu_config_endpoints_sie(priv);

	/*
	 * Fallback for devices that do not provide REG_NORMAL_SIE_EP_TX
	 */
	if (!priv->ep_tx_count)
		ret = rtl8xxxu_config_endpoints_no_sie(priv);

out:
	return ret;
}

static int rtl8192cu_load_firmware(struct rtl8xxxu_priv *priv)
{
	const char *fw_name;
	int ret;

	if (!priv->vendor_umc)
		fw_name = "rtlwifi/rtl8192cufw_TMSC.bin";
	else if (priv->chip_cut || priv->rtl_chip == RTL8192C)
		fw_name = "rtlwifi/rtl8192cufw_B.bin";
	else
		fw_name = "rtlwifi/rtl8192cufw_A.bin";

	ret = rtl8xxxu_load_firmware(priv, fw_name);

	return ret;
}

static int rtl8192cu_parse_efuse(struct rtl8xxxu_priv *priv)
{
	struct rtl8192cu_efuse *efuse = &priv->efuse_wifi.efuse8192;

	if (efuse->rtl_id != cpu_to_le16(0x8129))
		return -EINVAL;

	ether_addr_copy(priv->mac_addr, efuse->mac_addr);

	memcpy(priv->cck_tx_power_index_A,
	       efuse->cck_tx_power_index_A,
	       sizeof(efuse->cck_tx_power_index_A));
	memcpy(priv->cck_tx_power_index_B,
	       efuse->cck_tx_power_index_B,
	       sizeof(efuse->cck_tx_power_index_B));

	memcpy(priv->ht40_1s_tx_power_index_A,
	       efuse->ht40_1s_tx_power_index_A,
	       sizeof(efuse->ht40_1s_tx_power_index_A));
	memcpy(priv->ht40_1s_tx_power_index_B,
	       efuse->ht40_1s_tx_power_index_B,
	       sizeof(efuse->ht40_1s_tx_power_index_B));
	memcpy(priv->ht40_2s_tx_power_index_diff,
	       efuse->ht40_2s_tx_power_index_diff,
	       sizeof(efuse->ht40_2s_tx_power_index_diff));

	memcpy(priv->ht20_tx_power_index_diff,
	       efuse->ht20_tx_power_index_diff,
	       sizeof(efuse->ht20_tx_power_index_diff));
	memcpy(priv->ofdm_tx_power_index_diff,
	       efuse->ofdm_tx_power_index_diff,
	       sizeof(efuse->ofdm_tx_power_index_diff));

	memcpy(priv->ht40_max_power_offset,
	       efuse->ht40_max_power_offset,
	       sizeof(efuse->ht40_max_power_offset));
	memcpy(priv->ht20_max_power_offset,
	       efuse->ht20_max_power_offset,
	       sizeof(efuse->ht20_max_power_offset));

	priv->power_base = &rtl8192c_power_base;

	if (efuse->rf_regulatory & 0x20) {
		strscpy(priv->chip_name, "8188RU", sizeof(priv->chip_name));
		priv->rtl_chip = RTL8188R;
		priv->hi_pa = 1;
		priv->no_pape = 1;
		priv->power_base = &rtl8188r_power_base;
	}

	return 0;
}

static int rtl8192cu_init_phy_rf(struct rtl8xxxu_priv *priv)
{
	const struct rtl8xxxu_rfregval *rftable;
	int ret;

	if (priv->rtl_chip == RTL8188R) {
		rftable = rtl8188ru_radioa_1t_highpa_table;
		ret = rtl8xxxu_init_phy_rf(priv, rftable, RF_A);
	} else if (priv->rf_paths == 1) {
		rftable = rtl8192cu_radioa_1t_init_table;
		ret = rtl8xxxu_init_phy_rf(priv, rftable, RF_A);
	} else {
		rftable = rtl8192cu_radioa_2t_init_table;
		ret = rtl8xxxu_init_phy_rf(priv, rftable, RF_A);
		if (ret)
			goto exit;
		rftable = rtl8192cu_radiob_2t_init_table;
		ret = rtl8xxxu_init_phy_rf(priv, rftable, RF_B);
	}

exit:
	return ret;
}

static int rtl8192cu_power_on(struct rtl8xxxu_priv *priv)
{
	u8 val8;
	u16 val16;
	u32 val32;
	int i;

	for (i = 100; i; i--) {
		val8 = rtl8xxxu_read8(priv, REG_APS_FSMCO);
		if (val8 & APS_FSMCO_PFM_ALDN)
			break;
	}

	if (!i) {
		pr_info("%s: Poll failed\n", __func__);
		return -ENODEV;
	}

	/*
	 * RSV_CTRL 0x001C[7:0] = 0x00, unlock ISO/CLK/Power control register
	 */
	rtl8xxxu_write8(priv, REG_RSV_CTRL, 0x0);
	rtl8xxxu_write8(priv, REG_SPS0_CTRL, 0x2b);
	udelay(100);

	val8 = rtl8xxxu_read8(priv, REG_LDOV12D_CTRL);
	if (!(val8 & LDOV12D_ENABLE)) {
		pr_info("%s: Enabling LDOV12D (%02x)\n", __func__, val8);
		val8 |= LDOV12D_ENABLE;
		rtl8xxxu_write8(priv, REG_LDOV12D_CTRL, val8);

		udelay(100);

		val8 = rtl8xxxu_read8(priv, REG_SYS_ISO_CTRL);
		val8 &= ~SYS_ISO_MD2PP;
		rtl8xxxu_write8(priv, REG_SYS_ISO_CTRL, val8);
	}

	/*
	 * Auto enable WLAN
	 */
	val16 = rtl8xxxu_read16(priv, REG_APS_FSMCO);
	val16 |= APS_FSMCO_MAC_ENABLE;
	rtl8xxxu_write16(priv, REG_APS_FSMCO, val16);

	for (i = 1000; i; i--) {
		val16 = rtl8xxxu_read16(priv, REG_APS_FSMCO);
		if (!(val16 & APS_FSMCO_MAC_ENABLE))
			break;
	}
	if (!i) {
		pr_info("%s: FSMCO_MAC_ENABLE poll failed\n", __func__);
		return -EBUSY;
	}

	/*
	 * Enable radio, GPIO, LED
	 */
	val16 = APS_FSMCO_HW_SUSPEND | APS_FSMCO_ENABLE_POWERDOWN |
		APS_FSMCO_PFM_ALDN;
	rtl8xxxu_write16(priv, REG_APS_FSMCO, val16);

	/*
	 * Release RF digital isolation
	 */
	val16 = rtl8xxxu_read16(priv, REG_SYS_ISO_CTRL);
	val16 &= ~SYS_ISO_DIOR;
	rtl8xxxu_write16(priv, REG_SYS_ISO_CTRL, val16);

	val8 = rtl8xxxu_read8(priv, REG_APSD_CTRL);
	val8 &= ~APSD_CTRL_OFF;
	rtl8xxxu_write8(priv, REG_APSD_CTRL, val8);
	for (i = 200; i; i--) {
		val8 = rtl8xxxu_read8(priv, REG_APSD_CTRL);
		if (!(val8 & APSD_CTRL_OFF_STATUS))
			break;
	}

	if (!i) {
		pr_info("%s: APSD_CTRL poll failed\n", __func__);
		return -EBUSY;
	}

	/*
	 * Enable MAC DMA/WMAC/SCHEDULE/SEC block
	 */
	val16 = rtl8xxxu_read16(priv, REG_CR);
	val16 |= CR_HCI_TXDMA_ENABLE | CR_HCI_RXDMA_ENABLE |
		CR_TXDMA_ENABLE | CR_RXDMA_ENABLE | CR_PROTOCOL_ENABLE |
		CR_SCHEDULE_ENABLE | CR_MAC_TX_ENABLE | CR_MAC_RX_ENABLE;
	rtl8xxxu_write16(priv, REG_CR, val16);

	rtl8xxxu_write8(priv, 0xfe10, 0x19);

	/*
	 * Workaround for 8188RU LNA power leakage problem.
	 */
	if (priv->rtl_chip == RTL8188R) {
		val32 = rtl8xxxu_read32(priv, REG_FPGA0_XCD_RF_PARM);
		val32 &= ~BIT(1);
		rtl8xxxu_write32(priv, REG_FPGA0_XCD_RF_PARM, val32);
	}
	return 0;
}

struct rtl8xxxu_fileops rtl8192cu_fops = {
	.identify_chip = rtl8192cu_identify_chip,
	.parse_efuse = rtl8192cu_parse_efuse,
	.load_firmware = rtl8192cu_load_firmware,
	.power_on = rtl8192cu_power_on,
	.power_off = rtl8xxxu_power_off,
	.read_efuse = rtl8xxxu_read_efuse,
	.reset_8051 = rtl8xxxu_reset_8051,
	.llt_init = rtl8xxxu_init_llt_table,
	.init_phy_bb = rtl8xxxu_gen1_init_phy_bb,
	.init_phy_rf = rtl8192cu_init_phy_rf,
	.phy_lc_calibrate = rtl8723a_phy_lc_calibrate,
	.phy_iq_calibrate = rtl8xxxu_gen1_phy_iq_calibrate,
	.config_channel = rtl8xxxu_gen1_config_channel,
	.parse_rx_desc = rtl8xxxu_parse_rxdesc16,
	.parse_phystats = rtl8723au_rx_parse_phystats,
	.init_aggregation = rtl8xxxu_gen1_init_aggregation,
	.enable_rf = rtl8xxxu_gen1_enable_rf,
	.disable_rf = rtl8xxxu_gen1_disable_rf,
	.usb_quirks = rtl8xxxu_gen1_usb_quirks,
	.set_tx_power = rtl8xxxu_gen1_set_tx_power,
	.update_rate_mask = rtl8xxxu_update_rate_mask,
	.report_connect = rtl8xxxu_gen1_report_connect,
	.report_rssi = rtl8xxxu_gen1_report_rssi,
	.fill_txdesc = rtl8xxxu_fill_txdesc_v1,
	.cck_rssi = rtl8723a_cck_rssi,
	.writeN_block_size = 128,
	.rx_agg_buf_size = 16000,
	.tx_desc_size = sizeof(struct rtl8xxxu_txdesc32),
	.rx_desc_size = sizeof(struct rtl8xxxu_rxdesc16),
	.adda_1t_init = 0x0b1b25a0,
	.adda_1t_path_on = 0x0bdb25a0,
	.adda_2t_path_on_a = 0x04db25a4,
	.adda_2t_path_on_b = 0x0b1b25a4,
	.trxff_boundary = 0x27ff,
	.pbp_rx = PBP_PAGE_SIZE_128,
	.pbp_tx = PBP_PAGE_SIZE_128,
	.mactable = rtl8xxxu_gen1_mac_init_table,
	.total_page_num = TX_TOTAL_PAGE_NUM,
	.page_num_hi = TX_PAGE_NUM_HI_PQ,
	.page_num_lo = TX_PAGE_NUM_LO_PQ,
	.page_num_norm = TX_PAGE_NUM_NORM_PQ,
};
#endif
