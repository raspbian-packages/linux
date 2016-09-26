/*
 * Montage Technology M88DS3103/M88RS6000 demodulator driver
 *
 * Copyright (C) 2013 Antti Palosaari <crope@iki.fi>
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 */

#ifndef M88DS3103_PRIV_H
#define M88DS3103_PRIV_H

#include "dvb_frontend.h"
#include "m88ds3103.h"
#include "dvb_math.h"
#include <linux/firmware.h>
#include <linux/i2c-mux.h>
#include <linux/regmap.h>
#include <linux/math64.h>

#define M88DS3103_FIRMWARE "dvb-demod-m88ds3103.fw"
#define M88RS6000_FIRMWARE "dvb-demod-m88rs6000.fw"
#define M88DS3103_MCLK_KHZ 96000
#define M88RS6000_CHIP_ID 0x74
#define M88DS3103_CHIP_ID 0x70

struct m88ds3103_dev {
	struct i2c_client *client;
	struct regmap_config regmap_config;
	struct regmap *regmap;
	struct m88ds3103_config config;
	const struct m88ds3103_config *cfg;
	struct dvb_frontend fe;
	enum fe_delivery_system delivery_system;
	enum fe_status fe_status;
	u32 dvbv3_ber; /* for old DVBv3 API read_ber */
	bool warm; /* FW running */
	struct i2c_mux_core *muxc;
	/* auto detect chip id to do different config */
	u8 chip_id;
	/* main mclk is calculated for M88RS6000 dynamically */
	s32 mclk_khz;
	u64 post_bit_error;
	u64 post_bit_count;
};

struct m88ds3103_reg_val {
	u8 reg;
	u8 val;
};

static const struct m88ds3103_reg_val m88ds3103_dvbs_init_reg_vals[] = {
	{0x23, 0x07},
	{0x08, 0x03},
	{0x0c, 0x02},
	{0x21, 0x54},
	{0x25, 0x8a},
	{0x27, 0x31},
	{0x30, 0x08},
	{0x31, 0x40},
	{0x32, 0x32},
	{0x35, 0xff},
	{0x3a, 0x00},
	{0x37, 0x10},
	{0x38, 0x10},
	{0x39, 0x02},
	{0x42, 0x60},
	{0x4a, 0x80},
	{0x4b, 0x04},
	{0x4d, 0x91},
	{0x5d, 0xc8},
	{0x50, 0x36},
	{0x51, 0x36},
	{0x52, 0x36},
	{0x53, 0x36},
	{0x56, 0x01},
	{0x63, 0x0f},
	{0x64, 0x30},
	{0x65, 0x40},
	{0x68, 0x26},
	{0x69, 0x4c},
	{0x70, 0x20},
	{0x71, 0x70},
	{0x72, 0x04},
	{0x73, 0x00},
	{0x70, 0x40},
	{0x71, 0x70},
	{0x72, 0x04},
	{0x73, 0x00},
	{0x70, 0x60},
	{0x71, 0x70},
	{0x72, 0x04},
	{0x73, 0x00},
	{0x70, 0x80},
	{0x71, 0x70},
	{0x72, 0x04},
	{0x73, 0x00},
	{0x70, 0xa0},
	{0x71, 0x70},
	{0x72, 0x04},
	{0x73, 0x00},
	{0x70, 0x1f},
	{0x76, 0x38},
	{0x77, 0xa6},
	{0x78, 0x0c},
	{0x79, 0x80},
	{0x7f, 0x14},
	{0x7c, 0x00},
	{0xae, 0x82},
	{0x80, 0x64},
	{0x81, 0x66},
	{0x82, 0x44},
	{0x85, 0x04},
	{0xcd, 0xf4},
	{0x90, 0x33},
	{0xa0, 0x44},
	{0xc0, 0x08},
	{0xc3, 0x10},
	{0xc4, 0x08},
	{0xc5, 0xf0},
	{0xc6, 0xff},
	{0xc7, 0x00},
	{0xc8, 0x1a},
	{0xc9, 0x80},
	{0xe0, 0xf8},
	{0xe6, 0x8b},
	{0xd0, 0x40},
	{0xf8, 0x20},
	{0xfa, 0x0f},
	{0x00, 0x00},
	{0xbd, 0x01},
	{0xb8, 0x00},
};

static const struct m88ds3103_reg_val m88ds3103_dvbs2_init_reg_vals[] = {
	{0x23, 0x07},
	{0x08, 0x07},
	{0x0c, 0x02},
	{0x21, 0x54},
	{0x25, 0x8a},
	{0x27, 0x31},
	{0x30, 0x08},
	{0x32, 0x32},
	{0x35, 0xff},
	{0x3a, 0x00},
	{0x37, 0x10},
	{0x38, 0x10},
	{0x39, 0x02},
	{0x42, 0x60},
	{0x4a, 0x80},
	{0x4b, 0x04},
	{0x4d, 0x91},
	{0x5d, 0xc8},
	{0x50, 0x36},
	{0x51, 0x36},
	{0x52, 0x36},
	{0x53, 0x36},
	{0x56, 0x01},
	{0x63, 0x0f},
	{0x64, 0x10},
	{0x65, 0x20},
	{0x68, 0x46},
	{0x69, 0xcd},
	{0x70, 0x20},
	{0x71, 0x70},
	{0x72, 0x04},
	{0x73, 0x00},
	{0x70, 0x40},
	{0x71, 0x70},
	{0x72, 0x04},
	{0x73, 0x00},
	{0x70, 0x60},
	{0x71, 0x70},
	{0x72, 0x04},
	{0x73, 0x00},
	{0x70, 0x80},
	{0x71, 0x70},
	{0x72, 0x04},
	{0x73, 0x00},
	{0x70, 0xa0},
	{0x71, 0x70},
	{0x72, 0x04},
	{0x73, 0x00},
	{0x70, 0x1f},
	{0x76, 0x38},
	{0x77, 0xa6},
	{0x78, 0x0c},
	{0x79, 0x80},
	{0x7f, 0x14},
	{0x85, 0x08},
	{0xcd, 0xf4},
	{0x90, 0x33},
	{0x86, 0x00},
	{0x87, 0x0f},
	{0x89, 0x00},
	{0x8b, 0x44},
	{0x8c, 0x66},
	{0x9d, 0xc1},
	{0x8a, 0x10},
	{0xad, 0x40},
	{0xa0, 0x44},
	{0xc0, 0x08},
	{0xc1, 0x10},
	{0xc2, 0x08},
	{0xc3, 0x10},
	{0xc4, 0x08},
	{0xc5, 0xf0},
	{0xc6, 0xff},
	{0xc7, 0x00},
	{0xc8, 0x1a},
	{0xc9, 0x80},
	{0xca, 0x23},
	{0xcb, 0x24},
	{0xcc, 0xf4},
	{0xce, 0x74},
	{0x00, 0x00},
	{0xbd, 0x01},
	{0xb8, 0x00},
};

static const struct m88ds3103_reg_val m88rs6000_dvbs_init_reg_vals[] = {
	{0x23, 0x07},
	{0x08, 0x03},
	{0x0c, 0x02},
	{0x20, 0x00},
	{0x21, 0x54},
	{0x25, 0x82},
	{0x27, 0x31},
	{0x30, 0x08},
	{0x31, 0x40},
	{0x32, 0x32},
	{0x33, 0x35},
	{0x35, 0xff},
	{0x3a, 0x00},
	{0x37, 0x10},
	{0x38, 0x10},
	{0x39, 0x02},
	{0x42, 0x60},
	{0x4a, 0x80},
	{0x4b, 0x04},
	{0x4d, 0x91},
	{0x5d, 0xc8},
	{0x50, 0x36},
	{0x51, 0x36},
	{0x52, 0x36},
	{0x53, 0x36},
	{0x63, 0x0f},
	{0x64, 0x30},
	{0x65, 0x40},
	{0x68, 0x26},
	{0x69, 0x4c},
	{0x70, 0x20},
	{0x71, 0x70},
	{0x72, 0x04},
	{0x73, 0x00},
	{0x70, 0x40},
	{0x71, 0x70},
	{0x72, 0x04},
	{0x73, 0x00},
	{0x70, 0x60},
	{0x71, 0x70},
	{0x72, 0x04},
	{0x73, 0x00},
	{0x70, 0x80},
	{0x71, 0x70},
	{0x72, 0x04},
	{0x73, 0x00},
	{0x70, 0xa0},
	{0x71, 0x70},
	{0x72, 0x04},
	{0x73, 0x00},
	{0x70, 0x1f},
	{0x76, 0x38},
	{0x77, 0xa6},
	{0x78, 0x0c},
	{0x79, 0x80},
	{0x7f, 0x14},
	{0x7c, 0x00},
	{0xae, 0x82},
	{0x80, 0x64},
	{0x81, 0x66},
	{0x82, 0x44},
	{0x85, 0x04},
	{0xcd, 0xf4},
	{0x90, 0x33},
	{0xa0, 0x44},
	{0xbe, 0x00},
	{0xc0, 0x08},
	{0xc3, 0x10},
	{0xc4, 0x08},
	{0xc5, 0xf0},
	{0xc6, 0xff},
	{0xc7, 0x00},
	{0xc8, 0x1a},
	{0xc9, 0x80},
	{0xe0, 0xf8},
	{0xe6, 0x8b},
	{0xd0, 0x40},
	{0xf8, 0x20},
	{0xfa, 0x0f},
	{0x00, 0x00},
	{0xbd, 0x01},
	{0xb8, 0x00},
	{0x29, 0x11},
};

static const struct m88ds3103_reg_val m88rs6000_dvbs2_init_reg_vals[] = {
	{0x23, 0x07},
	{0x08, 0x07},
	{0x0c, 0x02},
	{0x20, 0x00},
	{0x21, 0x54},
	{0x25, 0x82},
	{0x27, 0x31},
	{0x30, 0x08},
	{0x32, 0x32},
	{0x33, 0x35},
	{0x35, 0xff},
	{0x3a, 0x00},
	{0x37, 0x10},
	{0x38, 0x10},
	{0x39, 0x02},
	{0x42, 0x60},
	{0x4a, 0x80},
	{0x4b, 0x04},
	{0x4d, 0x91},
	{0x5d, 0xc8},
	{0x50, 0x36},
	{0x51, 0x36},
	{0x52, 0x36},
	{0x53, 0x36},
	{0x63, 0x0f},
	{0x64, 0x10},
	{0x65, 0x20},
	{0x68, 0x46},
	{0x69, 0xcd},
	{0x70, 0x20},
	{0x71, 0x70},
	{0x72, 0x04},
	{0x73, 0x00},
	{0x70, 0x40},
	{0x71, 0x70},
	{0x72, 0x04},
	{0x73, 0x00},
	{0x70, 0x60},
	{0x71, 0x70},
	{0x72, 0x04},
	{0x73, 0x00},
	{0x70, 0x80},
	{0x71, 0x70},
	{0x72, 0x04},
	{0x73, 0x00},
	{0x70, 0xa0},
	{0x71, 0x70},
	{0x72, 0x04},
	{0x73, 0x00},
	{0x70, 0x1f},
	{0x76, 0x38},
	{0x77, 0xa6},
	{0x78, 0x0c},
	{0x79, 0x80},
	{0x7f, 0x14},
	{0x85, 0x08},
	{0xcd, 0xf4},
	{0x90, 0x33},
	{0x86, 0x00},
	{0x87, 0x0f},
	{0x89, 0x00},
	{0x8b, 0x44},
	{0x8c, 0x66},
	{0x9d, 0xc1},
	{0x8a, 0x10},
	{0xad, 0x40},
	{0xa0, 0x44},
	{0xbe, 0x00},
	{0xc0, 0x08},
	{0xc1, 0x10},
	{0xc2, 0x08},
	{0xc3, 0x10},
	{0xc4, 0x08},
	{0xc5, 0xf0},
	{0xc6, 0xff},
	{0xc7, 0x00},
	{0xc8, 0x1a},
	{0xc9, 0x80},
	{0xca, 0x23},
	{0xcb, 0x24},
	{0xcc, 0xf4},
	{0xce, 0x74},
	{0x00, 0x00},
	{0xbd, 0x01},
	{0xb8, 0x00},
	{0x29, 0x01},
};
#endif
