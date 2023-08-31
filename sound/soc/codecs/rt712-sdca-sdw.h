/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * rt712-sdca-sdw.h -- RT712 SDCA ALSA SoC audio driver header
 *
 * Copyright(c) 2023 Realtek Semiconductor Corp.
 */

#ifndef __RT712_SDW_H__
#define __RT712_SDW_H__

#include <linux/regmap.h>
#include <linux/soundwire/sdw_registers.h>

static const struct reg_default rt712_sdca_reg_defaults[] = {
	{ 0x201a, 0x00 },
	{ 0x201b, 0x00 },
	{ 0x201c, 0x00 },
	{ 0x201d, 0x00 },
	{ 0x201e, 0x00 },
	{ 0x201f, 0x00 },
	{ 0x2029, 0x00 },
	{ 0x202a, 0x00 },
	{ 0x202d, 0x00 },
	{ 0x202e, 0x00 },
	{ 0x202f, 0x00 },
	{ 0x2030, 0x00 },
	{ 0x2031, 0x00 },
	{ 0x2032, 0x00 },
	{ 0x2033, 0x00 },
	{ 0x2034, 0x00 },
	{ 0x2230, 0x00 },
	{ 0x2231, 0x2f },
	{ 0x2232, 0x80 },
	{ 0x2f01, 0x00 },
	{ 0x2f02, 0x09 },
	{ 0x2f03, 0x00 },
	{ 0x2f04, 0x00 },
	{ 0x2f05, 0x0b },
	{ 0x2f06, 0x01 },
	{ 0x2f08, 0x00 },
	{ 0x2f09, 0x00 },
	{ 0x2f0a, 0x01 },
	{ 0x2f35, 0x01 },
	{ 0x2f36, 0xcf },
	{ 0x2f50, 0x0f },
	{ 0x2f54, 0x01 },
	{ 0x2f58, 0x07 },
	{ 0x2f59, 0x09 },
	{ 0x2f5a, 0x01 },
	{ 0x2f5b, 0x07 },
	{ 0x2f5c, 0x05 },
	{ 0x2f5d, 0x05 },
	{ 0x3201, 0x01 },
	{ 0x320c, 0x00 },
	{ 0x3301, 0x01 },
	{ 0x3302, 0x00 },
	{ 0x3303, 0x1f },
	{ SDW_SDCA_CTL(FUNC_NUM_JACK_CODEC, RT712_SDCA_ENT_CS01, RT712_SDCA_CTL_SAMPLE_FREQ_INDEX, 0), 0x09 },
	{ SDW_SDCA_CTL(FUNC_NUM_JACK_CODEC, RT712_SDCA_ENT_CS11, RT712_SDCA_CTL_SAMPLE_FREQ_INDEX, 0), 0x09 },
	{ SDW_SDCA_CTL(FUNC_NUM_JACK_CODEC, RT712_SDCA_ENT_USER_FU05, RT712_SDCA_CTL_FU_MUTE, CH_L), 0x01 },
	{ SDW_SDCA_CTL(FUNC_NUM_JACK_CODEC, RT712_SDCA_ENT_USER_FU05, RT712_SDCA_CTL_FU_MUTE, CH_R), 0x01 },
	{ SDW_SDCA_CTL(FUNC_NUM_JACK_CODEC, RT712_SDCA_ENT_USER_FU0F, RT712_SDCA_CTL_FU_MUTE, CH_L), 0x01 },
	{ SDW_SDCA_CTL(FUNC_NUM_JACK_CODEC, RT712_SDCA_ENT_USER_FU0F, RT712_SDCA_CTL_FU_MUTE, CH_R), 0x01 },
	{ SDW_SDCA_CTL(FUNC_NUM_JACK_CODEC, RT712_SDCA_ENT_PDE40, RT712_SDCA_CTL_REQ_POWER_STATE, 0), 0x03 },
	{ SDW_SDCA_CTL(FUNC_NUM_JACK_CODEC, RT712_SDCA_ENT_PDE12, RT712_SDCA_CTL_REQ_POWER_STATE, 0), 0x03 },
	{ SDW_SDCA_CTL(FUNC_NUM_AMP, RT712_SDCA_ENT_CS31, RT712_SDCA_CTL_SAMPLE_FREQ_INDEX, 0), 0x09 },
	{ SDW_SDCA_CTL(FUNC_NUM_AMP, RT712_SDCA_ENT_PDE23, RT712_SDCA_CTL_REQ_POWER_STATE, 0), 0x03 },
	{ SDW_SDCA_CTL(FUNC_NUM_AMP, RT712_SDCA_ENT_USER_FU06, RT712_SDCA_CTL_FU_MUTE, CH_L), 0x01 },
	{ SDW_SDCA_CTL(FUNC_NUM_AMP, RT712_SDCA_ENT_USER_FU06, RT712_SDCA_CTL_FU_MUTE, CH_R), 0x01 },
	{ SDW_SDCA_CTL(FUNC_NUM_AMP, RT712_SDCA_ENT_OT23, RT712_SDCA_CTL_VENDOR_DEF, 0), 0x00 },
};

static const struct reg_default rt712_sdca_mbq_defaults[] = {
	{ 0x2000004, 0xaa01 },
	{ 0x200000e, 0x21e0 },
	{ 0x2000024, 0x01ba },
	{ 0x200004a, 0x8830 },
	{ 0x2000067, 0xf100 },
	{ 0x5800000, 0x1893 },
	{ 0x5b00000, 0x0407 },
	{ 0x5b00005, 0x0000 },
	{ 0x5b00029, 0x3fff },
	{ 0x5b0002a, 0xf000 },
	{ 0x5f00008, 0x7000 },
	{ 0x610000e, 0x0007 },
	{ 0x6100022, 0x2828 },
	{ 0x6100023, 0x2929 },
	{ 0x6100026, 0x2c29 },
	{ 0x610002c, 0x4150 },
	{ 0x6100045, 0x0860 },
	{ 0x6100046, 0x0029 },
	{ 0x6100053, 0x3fff },
	{ 0x6100055, 0x0000 },
	{ 0x6100060, 0x0000 },
	{ 0x6100064, 0x8000 },
	{ 0x6100065, 0x0000 },
	{ 0x6100067, 0xff12 },
	{ SDW_SDCA_CTL(FUNC_NUM_JACK_CODEC, RT712_SDCA_ENT_USER_FU05, RT712_SDCA_CTL_FU_VOLUME, CH_L), 0x0000 },
	{ SDW_SDCA_CTL(FUNC_NUM_JACK_CODEC, RT712_SDCA_ENT_USER_FU05, RT712_SDCA_CTL_FU_VOLUME, CH_R), 0x0000 },
	{ SDW_SDCA_CTL(FUNC_NUM_JACK_CODEC, RT712_SDCA_ENT_USER_FU0F, RT712_SDCA_CTL_FU_VOLUME, CH_L), 0x0000 },
	{ SDW_SDCA_CTL(FUNC_NUM_JACK_CODEC, RT712_SDCA_ENT_USER_FU0F, RT712_SDCA_CTL_FU_VOLUME, CH_R), 0x0000 },
	{ SDW_SDCA_CTL(FUNC_NUM_JACK_CODEC, RT712_SDCA_ENT_PLATFORM_FU44, RT712_SDCA_CTL_FU_CH_GAIN, CH_L), 0x0000 },
	{ SDW_SDCA_CTL(FUNC_NUM_JACK_CODEC, RT712_SDCA_ENT_PLATFORM_FU44, RT712_SDCA_CTL_FU_CH_GAIN, CH_R), 0x0000 },
	{ SDW_SDCA_CTL(FUNC_NUM_AMP, RT712_SDCA_ENT_USER_FU06, RT712_SDCA_CTL_FU_VOLUME, CH_L), 0x0000 },
	{ SDW_SDCA_CTL(FUNC_NUM_AMP, RT712_SDCA_ENT_USER_FU06, RT712_SDCA_CTL_FU_VOLUME, CH_R), 0x0000 },
};

#endif /* __RT712_SDW_H__ */
