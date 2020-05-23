/* SPDX-License-Identifier: GPL-2.0 */
/*
 * rt1308-sdw.h -- RT1308 ALSA SoC audio driver header
 *
 * Copyright(c) 2019 Realtek Semiconductor Corp.
 */

#ifndef __RT1308_SDW_H__
#define __RT1308_SDW_H__

static const struct reg_default rt1308_reg_defaults[] = {
	{ 0x0000, 0x00 },
	{ 0x0001, 0x00 },
	{ 0x0002, 0x00 },
	{ 0x0003, 0x00 },
	{ 0x0004, 0x00 },
	{ 0x0005, 0x01 },
	{ 0x0020, 0x00 },
	{ 0x0022, 0x00 },
	{ 0x0023, 0x00 },
	{ 0x0024, 0x00 },
	{ 0x0025, 0x00 },
	{ 0x0026, 0x00 },
	{ 0x0030, 0x00 },
	{ 0x0032, 0x00 },
	{ 0x0033, 0x00 },
	{ 0x0034, 0x00 },
	{ 0x0035, 0x00 },
	{ 0x0036, 0x00 },
	{ 0x0040, 0x00 },
	{ 0x0041, 0x00 },
	{ 0x0042, 0x00 },
	{ 0x0043, 0x00 },
	{ 0x0044, 0x20 },
	{ 0x0045, 0x01 },
	{ 0x0046, 0x01 },
	{ 0x0048, 0x00 },
	{ 0x0049, 0x00 },
	{ 0x0050, 0x20 },
	{ 0x0051, 0x02 },
	{ 0x0052, 0x5D },
	{ 0x0053, 0x13 },
	{ 0x0054, 0x08 },
	{ 0x0055, 0x00 },
	{ 0x0060, 0x00 },
	{ 0x0070, 0x00 },
	{ 0x00E0, 0x00 },
	{ 0x00F0, 0x00 },
	{ 0x0100, 0x00 },
	{ 0x0101, 0x00 },
	{ 0x0102, 0x20 },
	{ 0x0103, 0x00 },
	{ 0x0104, 0x00 },
	{ 0x0105, 0x03 },
	{ 0x0120, 0x00 },
	{ 0x0122, 0x00 },
	{ 0x0123, 0x00 },
	{ 0x0124, 0x00 },
	{ 0x0125, 0x00 },
	{ 0x0126, 0x00 },
	{ 0x0127, 0x00 },
	{ 0x0130, 0x00 },
	{ 0x0132, 0x00 },
	{ 0x0133, 0x00 },
	{ 0x0134, 0x00 },
	{ 0x0135, 0x00 },
	{ 0x0136, 0x00 },
	{ 0x0137, 0x00 },
	{ 0x0200, 0x00 },
	{ 0x0201, 0x00 },
	{ 0x0202, 0x00 },
	{ 0x0203, 0x00 },
	{ 0x0204, 0x00 },
	{ 0x0205, 0x03 },
	{ 0x0220, 0x00 },
	{ 0x0222, 0x00 },
	{ 0x0223, 0x00 },
	{ 0x0224, 0x00 },
	{ 0x0225, 0x00 },
	{ 0x0226, 0x00 },
	{ 0x0227, 0x00 },
	{ 0x0230, 0x00 },
	{ 0x0232, 0x00 },
	{ 0x0233, 0x00 },
	{ 0x0234, 0x00 },
	{ 0x0235, 0x00 },
	{ 0x0236, 0x00 },
	{ 0x0237, 0x00 },
	{ 0x0400, 0x00 },
	{ 0x0401, 0x00 },
	{ 0x0402, 0x00 },
	{ 0x0403, 0x00 },
	{ 0x0404, 0x00 },
	{ 0x0405, 0x03 },
	{ 0x0420, 0x00 },
	{ 0x0422, 0x00 },
	{ 0x0423, 0x00 },
	{ 0x0424, 0x00 },
	{ 0x0425, 0x00 },
	{ 0x0426, 0x00 },
	{ 0x0427, 0x00 },
	{ 0x0430, 0x00 },
	{ 0x0432, 0x00 },
	{ 0x0433, 0x00 },
	{ 0x0434, 0x00 },
	{ 0x0435, 0x00 },
	{ 0x0436, 0x00 },
	{ 0x0437, 0x00 },
	{ 0x0f00, 0x00 },
	{ 0x0f01, 0x00 },
	{ 0x0f02, 0x00 },
	{ 0x0f03, 0x00 },
	{ 0x0f04, 0x00 },
	{ 0x0f05, 0x00 },
	{ 0x0f20, 0x00 },
	{ 0x0f22, 0x00 },
	{ 0x0f23, 0x00 },
	{ 0x0f24, 0x00 },
	{ 0x0f25, 0x00 },
	{ 0x0f26, 0x00 },
	{ 0x0f27, 0x00 },
	{ 0x0f30, 0x00 },
	{ 0x0f32, 0x00 },
	{ 0x0f33, 0x00 },
	{ 0x0f34, 0x00 },
	{ 0x0f35, 0x00 },
	{ 0x0f36, 0x00 },
	{ 0x0f37, 0x00 },
	{ 0x2f01, 0x01 },
	{ 0x2f02, 0x09 },
	{ 0x2f03, 0x00 },
	{ 0x2f04, 0x0f },
	{ 0x2f05, 0x0b },
	{ 0x2f06, 0x01 },
	{ 0x2f07, 0x8e },
	{ 0x3000, 0x00 },
	{ 0x3001, 0x00 },
	{ 0x3004, 0x01 },
	{ 0x3005, 0x23 },
	{ 0x3008, 0x02 },
	{ 0x300a, 0x00 },
	{ 0xc003 | (RT1308_DAC_SET << 4), 0x00 },
	{ 0xc001 | (RT1308_POWER << 4), 0x00 },
	{ 0xc002 | (RT1308_POWER << 4), 0x00 },
};

#define RT1308_SDW_OFFSET 0xc000
#define RT1308_SDW_OFFSET_BYTE0 0xc000
#define RT1308_SDW_OFFSET_BYTE1 0xc001
#define RT1308_SDW_OFFSET_BYTE2 0xc002
#define RT1308_SDW_OFFSET_BYTE3 0xc003

#define RT1308_SDW_RESET (RT1308_SDW_OFFSET | (RT1308_RESET << 4))

struct rt1308_sdw_priv {
	struct snd_soc_component *component;
	struct regmap *regmap;
	struct sdw_slave *sdw_slave;
	enum sdw_slave_status status;
	struct sdw_bus_params params;
	bool hw_init;
	bool first_hw_init;
};

struct sdw_stream_data {
	struct sdw_stream_runtime *sdw_stream;
};

#endif /* __RT1308_SDW_H__ */
