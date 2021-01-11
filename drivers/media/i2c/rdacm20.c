// SPDX-License-Identifier: GPL-2.0+
/*
 * IMI RDACM20 GMSL Camera Driver
 *
 * Copyright (C) 2017-2020 Jacopo Mondi
 * Copyright (C) 2017-2020 Kieran Bingham
 * Copyright (C) 2017-2019 Laurent Pinchart
 * Copyright (C) 2017-2019 Niklas Söderlund
 * Copyright (C) 2016 Renesas Electronics Corporation
 * Copyright (C) 2015 Cogent Embedded, Inc.
 */

/*
 * The camera is made of an Omnivision OV10635 sensor connected to a Maxim
 * MAX9271 GMSL serializer.
 */

#include <linux/delay.h>
#include <linux/fwnode.h>
#include <linux/init.h>
#include <linux/i2c.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/videodev2.h>

#include <media/v4l2-async.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-subdev.h>

#include "max9271.h"

#define OV10635_I2C_ADDRESS		0x30

#define OV10635_SOFTWARE_RESET		0x0103
#define OV10635_PID			0x300a
#define OV10635_VER			0x300b
#define OV10635_SC_CMMN_SCCB_ID		0x300c
#define OV10635_SC_CMMN_SCCB_ID_SELECT	BIT(0)
#define OV10635_VERSION			0xa635

#define OV10635_WIDTH			1280
#define OV10635_HEIGHT			800

/* VTS = PCLK / FPS / HTS / 2 (= 88MHz / 1572 / 30 / 2) */
#define OV10635_HTS			1572
/* FPS = 29,9998 */
#define OV10635_VTS			933

/*
 * As the drivers supports a single MEDIA_BUS_FMT_UYVY8_2X8 format we
 * can harcode the pixel rate.
 *
 * PCLK is fed through the system clock, programmed @88MHz.
 * MEDIA_BUS_FMT_UYVY8_2X8 format = 2 samples per pixel.
 *
 * Pixelrate = PCLK / 2
 * FPS = (OV10635_VTS * OV10635_HTS) / PixelRate
 *     = 29,9998
 */
#define OV10635_PIXEL_RATE		(44000000)

static const struct ov10635_reg {
	u16	reg;
	u8	val;
} ov10635_regs_wizard[] = {
	{ 0x301b, 0xff }, { 0x301c, 0xff }, { 0x301a, 0xff }, { 0x3011, 0x42 },
	{ 0x6900, 0x0c }, { 0x6901, 0x19 }, { 0x3503, 0x10 }, { 0x3025, 0x03 },
	{ 0x3003, 0x16 }, { 0x3004, 0x30 }, { 0x3005, 0x40 }, { 0x3006, 0x91 },
	{ 0x3600, 0x74 }, { 0x3601, 0x2b }, { 0x3612, 0x00 }, { 0x3611, 0x67 },
	{ 0x3633, 0xca }, { 0x3602, 0xaf }, { 0x3603, 0x04 }, { 0x3630, 0x28 },
	{ 0x3631, 0x16 }, { 0x3714, 0x10 }, { 0x371d, 0x01 }, { 0x4300, 0x3a },
	{ 0x3007, 0x01 }, { 0x3024, 0x03 }, { 0x3020, 0x0a }, { 0x3702, 0x0d },
	{ 0x3703, 0x20 }, { 0x3704, 0x15 }, { 0x3709, 0xa8 }, { 0x370c, 0xc7 },
	{ 0x370d, 0x80 }, { 0x3712, 0x00 }, { 0x3713, 0x20 }, { 0x3715, 0x04 },
	{ 0x381d, 0x40 }, { 0x381c, 0x00 }, { 0x3822, 0x50 }, { 0x3824, 0x10 },
	{ 0x3815, 0x8c }, { 0x3804, 0x05 }, { 0x3805, 0x1f }, { 0x3800, 0x00 },
	{ 0x3801, 0x00 }, { 0x3806, 0x03 }, { 0x3807, 0x28 }, { 0x3802, 0x00 },
	{ 0x3803, 0x07 }, { 0x3808, 0x05 }, { 0x3809, 0x00 }, { 0x380a, 0x03 },
	{ 0x380b, 0x20 }, { 0x380c, OV10635_HTS >> 8 },
	{ 0x380d, OV10635_HTS & 0xff }, { 0x380e, OV10635_VTS >> 8 },
	{ 0x380f, OV10635_VTS & 0xff },	{ 0x3813, 0x02 }, { 0x3811, 0x08 },
	{ 0x381f, 0x0c }, { 0x3819, 0x04 }, { 0x3804, 0x01 }, { 0x3805, 0x00 },
	{ 0x3828, 0x03 }, { 0x3829, 0x10 }, { 0x382a, 0x10 }, { 0x3621, 0x63 },
	{ 0x5005, 0x08 }, { 0x56d5, 0x00 }, { 0x56d6, 0x80 }, { 0x56d7, 0x00 },
	{ 0x56d8, 0x00 }, { 0x56d9, 0x00 }, { 0x56da, 0x80 }, { 0x56db, 0x00 },
	{ 0x56dc, 0x00 }, { 0x56e8, 0x00 }, { 0x56e9, 0x7f }, { 0x56ea, 0x00 },
	{ 0x56eb, 0x7f }, { 0x5100, 0x00 }, { 0x5101, 0x80 }, { 0x5102, 0x00 },
	{ 0x5103, 0x80 }, { 0x5104, 0x00 }, { 0x5105, 0x80 }, { 0x5106, 0x00 },
	{ 0x5107, 0x80 }, { 0x5108, 0x00 }, { 0x5109, 0x00 }, { 0x510a, 0x00 },
	{ 0x510b, 0x00 }, { 0x510c, 0x00 }, { 0x510d, 0x00 }, { 0x510e, 0x00 },
	{ 0x510f, 0x00 }, { 0x5110, 0x00 }, { 0x5111, 0x80 }, { 0x5112, 0x00 },
	{ 0x5113, 0x80 }, { 0x5114, 0x00 }, { 0x5115, 0x80 }, { 0x5116, 0x00 },
	{ 0x5117, 0x80 }, { 0x5118, 0x00 }, { 0x5119, 0x00 }, { 0x511a, 0x00 },
	{ 0x511b, 0x00 }, { 0x511c, 0x00 }, { 0x511d, 0x00 }, { 0x511e, 0x00 },
	{ 0x511f, 0x00 }, { 0x56d0, 0x00 }, { 0x5006, 0x04 }, { 0x5608, 0x05 },
	{ 0x52d7, 0x06 }, { 0x528d, 0x08 }, { 0x5293, 0x12 }, { 0x52d3, 0x12 },
	{ 0x5288, 0x06 }, { 0x5289, 0x20 }, { 0x52c8, 0x06 }, { 0x52c9, 0x20 },
	{ 0x52cd, 0x04 }, { 0x5381, 0x00 }, { 0x5382, 0xff }, { 0x5589, 0x76 },
	{ 0x558a, 0x47 }, { 0x558b, 0xef }, { 0x558c, 0xc9 }, { 0x558d, 0x49 },
	{ 0x558e, 0x30 }, { 0x558f, 0x67 }, { 0x5590, 0x3f }, { 0x5591, 0xf0 },
	{ 0x5592, 0x10 }, { 0x55a2, 0x6d }, { 0x55a3, 0x55 }, { 0x55a4, 0xc3 },
	{ 0x55a5, 0xb5 }, { 0x55a6, 0x43 }, { 0x55a7, 0x38 }, { 0x55a8, 0x5f },
	{ 0x55a9, 0x4b }, { 0x55aa, 0xf0 }, { 0x55ab, 0x10 }, { 0x5581, 0x52 },
	{ 0x5300, 0x01 }, { 0x5301, 0x00 }, { 0x5302, 0x00 }, { 0x5303, 0x0e },
	{ 0x5304, 0x00 }, { 0x5305, 0x0e }, { 0x5306, 0x00 }, { 0x5307, 0x36 },
	{ 0x5308, 0x00 }, { 0x5309, 0xd9 }, { 0x530a, 0x00 }, { 0x530b, 0x0f },
	{ 0x530c, 0x00 }, { 0x530d, 0x2c }, { 0x530e, 0x00 }, { 0x530f, 0x59 },
	{ 0x5310, 0x00 }, { 0x5311, 0x7b }, { 0x5312, 0x00 }, { 0x5313, 0x22 },
	{ 0x5314, 0x00 }, { 0x5315, 0xd5 }, { 0x5316, 0x00 }, { 0x5317, 0x13 },
	{ 0x5318, 0x00 }, { 0x5319, 0x18 }, { 0x531a, 0x00 }, { 0x531b, 0x26 },
	{ 0x531c, 0x00 }, { 0x531d, 0xdc }, { 0x531e, 0x00 }, { 0x531f, 0x02 },
	{ 0x5320, 0x00 }, { 0x5321, 0x24 }, { 0x5322, 0x00 }, { 0x5323, 0x56 },
	{ 0x5324, 0x00 }, { 0x5325, 0x85 }, { 0x5326, 0x00 }, { 0x5327, 0x20 },
	{ 0x5609, 0x01 }, { 0x560a, 0x40 }, { 0x560b, 0x01 }, { 0x560c, 0x40 },
	{ 0x560d, 0x00 }, { 0x560e, 0xfa }, { 0x560f, 0x00 }, { 0x5610, 0xfa },
	{ 0x5611, 0x02 }, { 0x5612, 0x80 }, { 0x5613, 0x02 }, { 0x5614, 0x80 },
	{ 0x5615, 0x01 }, { 0x5616, 0x2c }, { 0x5617, 0x01 }, { 0x5618, 0x2c },
	{ 0x563b, 0x01 }, { 0x563c, 0x01 }, { 0x563d, 0x01 }, { 0x563e, 0x01 },
	{ 0x563f, 0x03 }, { 0x5640, 0x03 }, { 0x5641, 0x03 }, { 0x5642, 0x05 },
	{ 0x5643, 0x09 }, { 0x5644, 0x05 }, { 0x5645, 0x05 }, { 0x5646, 0x05 },
	{ 0x5647, 0x05 }, { 0x5651, 0x00 }, { 0x5652, 0x80 }, { 0x521a, 0x01 },
	{ 0x521b, 0x03 }, { 0x521c, 0x06 }, { 0x521d, 0x0a }, { 0x521e, 0x0e },
	{ 0x521f, 0x12 }, { 0x5220, 0x16 }, { 0x5223, 0x02 }, { 0x5225, 0x04 },
	{ 0x5227, 0x08 }, { 0x5229, 0x0c }, { 0x522b, 0x12 }, { 0x522d, 0x18 },
	{ 0x522f, 0x1e }, { 0x5241, 0x04 }, { 0x5242, 0x01 }, { 0x5243, 0x03 },
	{ 0x5244, 0x06 }, { 0x5245, 0x0a }, { 0x5246, 0x0e }, { 0x5247, 0x12 },
	{ 0x5248, 0x16 }, { 0x524a, 0x03 }, { 0x524c, 0x04 }, { 0x524e, 0x08 },
	{ 0x5250, 0x0c }, { 0x5252, 0x12 }, { 0x5254, 0x18 }, { 0x5256, 0x1e },
	/* fifo_line_length = 2*hts */
	{ 0x4606, (2 * OV10635_HTS) >> 8 }, { 0x4607, (2 * OV10635_HTS) & 0xff },
	/* fifo_hsync_start = 2*(hts - xres) */
	{ 0x460a, (2 * (OV10635_HTS - OV10635_WIDTH)) >> 8 },
	{ 0x460b, (2 * (OV10635_HTS - OV10635_WIDTH)) & 0xff },
	{ 0x460c, 0x00 }, { 0x4620, 0x0e },
	/* BT601: 0x08 is also acceptable as HS/VS mode */
	{ 0x4700, 0x04 }, { 0x4701, 0x00 }, { 0x4702, 0x01 }, { 0x4004, 0x04 },
	{ 0x4005, 0x18 }, { 0x4001, 0x06 }, { 0x4050, 0x22 }, { 0x4051, 0x24 },
	{ 0x4052, 0x02 }, { 0x4057, 0x9c }, { 0x405a, 0x00 }, { 0x4202, 0x02 },
	{ 0x3023, 0x10 }, { 0x0100, 0x01 }, { 0x0100, 0x01 }, { 0x6f10, 0x07 },
	{ 0x6f11, 0x82 }, { 0x6f12, 0x04 }, { 0x6f13, 0x00 }, { 0xd000, 0x19 },
	{ 0xd001, 0xa0 }, { 0xd002, 0x00 }, { 0xd003, 0x01 }, { 0xd004, 0xa9 },
	{ 0xd005, 0xad }, { 0xd006, 0x10 }, { 0xd007, 0x40 }, { 0xd008, 0x44 },
	{ 0xd009, 0x00 }, { 0xd00a, 0x68 }, { 0xd00b, 0x00 }, { 0xd00c, 0x15 },
	{ 0xd00d, 0x00 }, { 0xd00e, 0x00 }, { 0xd00f, 0x00 }, { 0xd040, 0x9c },
	{ 0xd041, 0x21 }, { 0xd042, 0xff }, { 0xd043, 0xf8 }, { 0xd044, 0xd4 },
	{ 0xd045, 0x01 }, { 0xd046, 0x48 }, { 0xd047, 0x00 }, { 0xd048, 0xd4 },
	{ 0xd049, 0x01 }, { 0xd04a, 0x50 }, { 0xd04b, 0x04 }, { 0xd04c, 0x18 },
	{ 0xd04d, 0x60 }, { 0xd04e, 0x00 }, { 0xd04f, 0x01 }, { 0xd050, 0xa8 },
	{ 0xd051, 0x63 }, { 0xd052, 0x02 }, { 0xd053, 0xa4 }, { 0xd054, 0x85 },
	{ 0xd055, 0x43 }, { 0xd056, 0x00 }, { 0xd057, 0x00 }, { 0xd058, 0x18 },
	{ 0xd059, 0x60 }, { 0xd05a, 0x00 }, { 0xd05b, 0x01 }, { 0xd05c, 0xa8 },
	{ 0xd05d, 0x63 }, { 0xd05e, 0x03 }, { 0xd05f, 0xf0 }, { 0xd060, 0x98 },
	{ 0xd061, 0xa3 }, { 0xd062, 0x00 }, { 0xd063, 0x00 }, { 0xd064, 0x8c },
	{ 0xd065, 0x6a }, { 0xd066, 0x00 }, { 0xd067, 0x6e }, { 0xd068, 0xe5 },
	{ 0xd069, 0x85 }, { 0xd06a, 0x18 }, { 0xd06b, 0x00 }, { 0xd06c, 0x10 },
	{ 0xd06d, 0x00 }, { 0xd06e, 0x00 }, { 0xd06f, 0x10 }, { 0xd070, 0x9c },
	{ 0xd071, 0x80 }, { 0xd072, 0x00 }, { 0xd073, 0x03 }, { 0xd074, 0x18 },
	{ 0xd075, 0x60 }, { 0xd076, 0x00 }, { 0xd077, 0x01 }, { 0xd078, 0xa8 },
	{ 0xd079, 0x63 }, { 0xd07a, 0x07 }, { 0xd07b, 0x80 }, { 0xd07c, 0x07 },
	{ 0xd07d, 0xff }, { 0xd07e, 0xf9 }, { 0xd07f, 0x03 }, { 0xd080, 0x8c },
	{ 0xd081, 0x63 }, { 0xd082, 0x00 }, { 0xd083, 0x00 }, { 0xd084, 0xa5 },
	{ 0xd085, 0x6b }, { 0xd086, 0x00 }, { 0xd087, 0xff }, { 0xd088, 0x18 },
	{ 0xd089, 0x80 }, { 0xd08a, 0x00 }, { 0xd08b, 0x01 }, { 0xd08c, 0xa8 },
	{ 0xd08d, 0x84 }, { 0xd08e, 0x01 }, { 0xd08f, 0x04 }, { 0xd090, 0xe1 },
	{ 0xd091, 0x6b }, { 0xd092, 0x58 }, { 0xd093, 0x00 }, { 0xd094, 0x94 },
	{ 0xd095, 0x6a }, { 0xd096, 0x00 }, { 0xd097, 0x70 }, { 0xd098, 0xe1 },
	{ 0xd099, 0x6b }, { 0xd09a, 0x20 }, { 0xd09b, 0x00 }, { 0xd09c, 0x95 },
	{ 0xd09d, 0x6b }, { 0xd09e, 0x00 }, { 0xd09f, 0x00 }, { 0xd0a0, 0xe4 },
	{ 0xd0a1, 0x8b }, { 0xd0a2, 0x18 }, { 0xd0a3, 0x00 }, { 0xd0a4, 0x0c },
	{ 0xd0a5, 0x00 }, { 0xd0a6, 0x00 }, { 0xd0a7, 0x23 }, { 0xd0a8, 0x15 },
	{ 0xd0a9, 0x00 }, { 0xd0aa, 0x00 }, { 0xd0ab, 0x00 }, { 0xd0ac, 0x18 },
	{ 0xd0ad, 0x60 }, { 0xd0ae, 0x80 }, { 0xd0af, 0x06 }, { 0xd0b0, 0xa8 },
	{ 0xd0b1, 0x83 }, { 0xd0b2, 0x40 }, { 0xd0b3, 0x08 }, { 0xd0b4, 0xa8 },
	{ 0xd0b5, 0xe3 }, { 0xd0b6, 0x38 }, { 0xd0b7, 0x2a }, { 0xd0b8, 0xa8 },
	{ 0xd0b9, 0xc3 }, { 0xd0ba, 0x40 }, { 0xd0bb, 0x09 }, { 0xd0bc, 0xa8 },
	{ 0xd0bd, 0xa3 }, { 0xd0be, 0x38 }, { 0xd0bf, 0x29 }, { 0xd0c0, 0x8c },
	{ 0xd0c1, 0x65 }, { 0xd0c2, 0x00 }, { 0xd0c3, 0x00 }, { 0xd0c4, 0xd8 },
	{ 0xd0c5, 0x04 }, { 0xd0c6, 0x18 }, { 0xd0c7, 0x00 }, { 0xd0c8, 0x8c },
	{ 0xd0c9, 0x67 }, { 0xd0ca, 0x00 }, { 0xd0cb, 0x00 }, { 0xd0cc, 0xd8 },
	{ 0xd0cd, 0x06 }, { 0xd0ce, 0x18 }, { 0xd0cf, 0x00 }, { 0xd0d0, 0x18 },
	{ 0xd0d1, 0x60 }, { 0xd0d2, 0x80 }, { 0xd0d3, 0x06 }, { 0xd0d4, 0xa8 },
	{ 0xd0d5, 0xe3 }, { 0xd0d6, 0x67 }, { 0xd0d7, 0x02 }, { 0xd0d8, 0xa9 },
	{ 0xd0d9, 0x03 }, { 0xd0da, 0x67 }, { 0xd0db, 0x03 }, { 0xd0dc, 0xa8 },
	{ 0xd0dd, 0xc3 }, { 0xd0de, 0x3d }, { 0xd0df, 0x05 }, { 0xd0e0, 0x8c },
	{ 0xd0e1, 0x66 }, { 0xd0e2, 0x00 }, { 0xd0e3, 0x00 }, { 0xd0e4, 0xb8 },
	{ 0xd0e5, 0x63 }, { 0xd0e6, 0x00 }, { 0xd0e7, 0x18 }, { 0xd0e8, 0xb8 },
	{ 0xd0e9, 0x63 }, { 0xd0ea, 0x00 }, { 0xd0eb, 0x98 }, { 0xd0ec, 0xbc },
	{ 0xd0ed, 0x03 }, { 0xd0ee, 0x00 }, { 0xd0ef, 0x00 }, { 0xd0f0, 0x10 },
	{ 0xd0f1, 0x00 }, { 0xd0f2, 0x00 }, { 0xd0f3, 0x16 }, { 0xd0f4, 0xb8 },
	{ 0xd0f5, 0x83 }, { 0xd0f6, 0x00 }, { 0xd0f7, 0x19 }, { 0xd0f8, 0x8c },
	{ 0xd0f9, 0x67 }, { 0xd0fa, 0x00 }, { 0xd0fb, 0x00 }, { 0xd0fc, 0xb8 },
	{ 0xd0fd, 0xa4 }, { 0xd0fe, 0x00 }, { 0xd0ff, 0x98 }, { 0xd100, 0xb8 },
	{ 0xd101, 0x83 }, { 0xd102, 0x00 }, { 0xd103, 0x08 }, { 0xd104, 0x8c },
	{ 0xd105, 0x68 }, { 0xd106, 0x00 }, { 0xd107, 0x00 }, { 0xd108, 0xe0 },
	{ 0xd109, 0x63 }, { 0xd10a, 0x20 }, { 0xd10b, 0x04 }, { 0xd10c, 0xe0 },
	{ 0xd10d, 0x65 }, { 0xd10e, 0x18 }, { 0xd10f, 0x00 }, { 0xd110, 0xa4 },
	{ 0xd111, 0x83 }, { 0xd112, 0xff }, { 0xd113, 0xff }, { 0xd114, 0xb8 },
	{ 0xd115, 0x64 }, { 0xd116, 0x00 }, { 0xd117, 0x48 }, { 0xd118, 0xd8 },
	{ 0xd119, 0x07 }, { 0xd11a, 0x18 }, { 0xd11b, 0x00 }, { 0xd11c, 0xd8 },
	{ 0xd11d, 0x08 }, { 0xd11e, 0x20 }, { 0xd11f, 0x00 }, { 0xd120, 0x9c },
	{ 0xd121, 0x60 }, { 0xd122, 0x00 }, { 0xd123, 0x00 }, { 0xd124, 0xd8 },
	{ 0xd125, 0x06 }, { 0xd126, 0x18 }, { 0xd127, 0x00 }, { 0xd128, 0x00 },
	{ 0xd129, 0x00 }, { 0xd12a, 0x00 }, { 0xd12b, 0x08 }, { 0xd12c, 0x15 },
	{ 0xd12d, 0x00 }, { 0xd12e, 0x00 }, { 0xd12f, 0x00 }, { 0xd130, 0x8c },
	{ 0xd131, 0x6a }, { 0xd132, 0x00 }, { 0xd133, 0x76 }, { 0xd134, 0xbc },
	{ 0xd135, 0x23 }, { 0xd136, 0x00 }, { 0xd137, 0x00 }, { 0xd138, 0x13 },
	{ 0xd139, 0xff }, { 0xd13a, 0xff }, { 0xd13b, 0xe6 }, { 0xd13c, 0x18 },
	{ 0xd13d, 0x60 }, { 0xd13e, 0x80 }, { 0xd13f, 0x06 }, { 0xd140, 0x03 },
	{ 0xd141, 0xff }, { 0xd142, 0xff }, { 0xd143, 0xdd }, { 0xd144, 0xa8 },
	{ 0xd145, 0x83 }, { 0xd146, 0x40 }, { 0xd147, 0x08 }, { 0xd148, 0x85 },
	{ 0xd149, 0x21 }, { 0xd14a, 0x00 }, { 0xd14b, 0x00 }, { 0xd14c, 0x85 },
	{ 0xd14d, 0x41 }, { 0xd14e, 0x00 }, { 0xd14f, 0x04 }, { 0xd150, 0x44 },
	{ 0xd151, 0x00 }, { 0xd152, 0x48 }, { 0xd153, 0x00 }, { 0xd154, 0x9c },
	{ 0xd155, 0x21 }, { 0xd156, 0x00 }, { 0xd157, 0x08 }, { 0x6f0e, 0x03 },
	{ 0x6f0f, 0x00 }, { 0x460e, 0x08 }, { 0x460f, 0x01 }, { 0x4610, 0x00 },
	{ 0x4611, 0x01 }, { 0x4612, 0x00 }, { 0x4613, 0x01 },
	/* 8 bits */
	{ 0x4605, 0x08 },
	/* Swap data bits order [9:0] -> [0:9] */
	{ 0x4709, 0x10 }, { 0x4608, 0x00 }, { 0x4609, 0x08 }, { 0x6804, 0x00 },
	{ 0x6805, 0x06 }, { 0x6806, 0x00 }, { 0x5120, 0x00 }, { 0x3510, 0x00 },
	{ 0x3504, 0x00 }, { 0x6800, 0x00 }, { 0x6f0d, 0x01 },
	/* PCLK falling edge */
	{ 0x4708, 0x01 }, { 0x5000, 0xff }, { 0x5001, 0xbf }, { 0x5002, 0x7e },
	{ 0x503d, 0x00 }, { 0xc450, 0x01 }, { 0xc452, 0x04 }, { 0xc453, 0x00 },
	{ 0xc454, 0x00 }, { 0xc455, 0x01 }, { 0xc456, 0x01 }, { 0xc457, 0x00 },
	{ 0xc458, 0x00 }, { 0xc459, 0x00 }, { 0xc45b, 0x00 }, { 0xc45c, 0x01 },
	{ 0xc45d, 0x00 }, { 0xc45e, 0x00 }, { 0xc45f, 0x00 }, { 0xc460, 0x00 },
	{ 0xc461, 0x01 }, { 0xc462, 0x01 }, { 0xc464, 0x03 }, { 0xc465, 0x00 },
	{ 0xc466, 0x8a }, { 0xc467, 0x00 }, { 0xc468, 0x86 }, { 0xc469, 0x00 },
	{ 0xc46a, 0x40 }, { 0xc46b, 0x50 }, { 0xc46c, 0x30 }, { 0xc46d, 0x28 },
	{ 0xc46e, 0x60 }, { 0xc46f, 0x40 }, { 0xc47c, 0x01 }, { 0xc47d, 0x38 },
	{ 0xc47e, 0x00 }, { 0xc47f, 0x00 }, { 0xc480, 0x00 }, { 0xc481, 0xff },
	{ 0xc482, 0x00 }, { 0xc483, 0x40 }, { 0xc484, 0x00 }, { 0xc485, 0x18 },
	{ 0xc486, 0x00 }, { 0xc487, 0x18 },
	{ 0xc488, (OV10635_VTS - 8) * 16 >> 8},
	{ 0xc489, (OV10635_VTS - 8) * 16 & 0xff},
	{ 0xc48a, (OV10635_VTS - 8) * 16 >> 8},
	{ 0xc48b, (OV10635_VTS - 8) * 16 & 0xff}, { 0xc48c, 0x00 },
	{ 0xc48d, 0x04 }, { 0xc48e, 0x00 }, { 0xc48f, 0x04 }, { 0xc490, 0x03 },
	{ 0xc492, 0x20 }, { 0xc493, 0x08 }, { 0xc498, 0x02 }, { 0xc499, 0x00 },
	{ 0xc49a, 0x02 }, { 0xc49b, 0x00 }, { 0xc49c, 0x02 }, { 0xc49d, 0x00 },
	{ 0xc49e, 0x02 }, { 0xc49f, 0x60 }, { 0xc4a0, 0x03 }, { 0xc4a1, 0x00 },
	{ 0xc4a2, 0x04 }, { 0xc4a3, 0x00 }, { 0xc4a4, 0x00 }, { 0xc4a5, 0x10 },
	{ 0xc4a6, 0x00 }, { 0xc4a7, 0x40 }, { 0xc4a8, 0x00 }, { 0xc4a9, 0x80 },
	{ 0xc4aa, 0x0d }, { 0xc4ab, 0x00 }, { 0xc4ac, 0x0f }, { 0xc4ad, 0xc0 },
	{ 0xc4b4, 0x01 }, { 0xc4b5, 0x01 }, { 0xc4b6, 0x00 }, { 0xc4b7, 0x01 },
	{ 0xc4b8, 0x00 }, { 0xc4b9, 0x01 }, { 0xc4ba, 0x01 }, { 0xc4bb, 0x00 },
	{ 0xc4bc, 0x01 }, { 0xc4bd, 0x60 }, { 0xc4be, 0x02 }, { 0xc4bf, 0x33 },
	{ 0xc4c8, 0x03 }, { 0xc4c9, 0xd0 }, { 0xc4ca, 0x0e }, { 0xc4cb, 0x00 },
	{ 0xc4cc, 0x0e }, { 0xc4cd, 0x51 }, { 0xc4ce, 0x0e }, { 0xc4cf, 0x51 },
	{ 0xc4d0, 0x04 }, { 0xc4d1, 0x80 }, { 0xc4e0, 0x04 }, { 0xc4e1, 0x02 },
	{ 0xc4e2, 0x01 }, { 0xc4e4, 0x10 }, { 0xc4e5, 0x20 }, { 0xc4e6, 0x30 },
	{ 0xc4e7, 0x40 }, { 0xc4e8, 0x50 }, { 0xc4e9, 0x60 }, { 0xc4ea, 0x70 },
	{ 0xc4eb, 0x80 }, { 0xc4ec, 0x90 }, { 0xc4ed, 0xa0 }, { 0xc4ee, 0xb0 },
	{ 0xc4ef, 0xc0 }, { 0xc4f0, 0xd0 }, { 0xc4f1, 0xe0 }, { 0xc4f2, 0xf0 },
	{ 0xc4f3, 0x80 }, { 0xc4f4, 0x00 }, { 0xc4f5, 0x20 }, { 0xc4f6, 0x02 },
	{ 0xc4f7, 0x00 }, { 0xc4f8, 0x00 }, { 0xc4f9, 0x00 }, { 0xc4fa, 0x00 },
	{ 0xc4fb, 0x01 }, { 0xc4fc, 0x01 }, { 0xc4fd, 0x00 }, { 0xc4fe, 0x04 },
	{ 0xc4ff, 0x02 }, { 0xc500, 0x48 }, { 0xc501, 0x74 }, { 0xc502, 0x58 },
	{ 0xc503, 0x80 }, { 0xc504, 0x05 }, { 0xc505, 0x80 }, { 0xc506, 0x03 },
	{ 0xc507, 0x80 }, { 0xc508, 0x01 }, { 0xc509, 0xc0 }, { 0xc50a, 0x01 },
	{ 0xc50b, 0xa0 }, { 0xc50c, 0x01 }, { 0xc50d, 0x2c }, { 0xc50e, 0x01 },
	{ 0xc50f, 0x0a }, { 0xc510, 0x00 }, { 0xc511, 0x00 }, { 0xc512, 0xe5 },
	{ 0xc513, 0x14 }, { 0xc514, 0x04 }, { 0xc515, 0x00 }, { 0xc518, OV10635_VTS >> 8},
	{ 0xc519, OV10635_VTS & 0xff}, { 0xc51a, OV10635_HTS >> 8},
	{ 0xc51b, OV10635_HTS & 0xff}, { 0xc2e0, 0x00 }, { 0xc2e1, 0x51 },
	{ 0xc2e2, 0x00 }, { 0xc2e3, 0xd6 }, { 0xc2e4, 0x01 }, { 0xc2e5, 0x5e },
	{ 0xc2e9, 0x01 }, { 0xc2ea, 0x7a }, { 0xc2eb, 0x90 }, { 0xc2ed, 0x00 },
	{ 0xc2ee, 0x7a }, { 0xc2ef, 0x64 }, { 0xc308, 0x00 }, { 0xc309, 0x00 },
	{ 0xc30a, 0x00 }, { 0xc30c, 0x00 }, { 0xc30d, 0x01 }, { 0xc30e, 0x00 },
	{ 0xc30f, 0x00 }, { 0xc310, 0x01 }, { 0xc311, 0x60 }, { 0xc312, 0xff },
	{ 0xc313, 0x08 }, { 0xc314, 0x01 }, { 0xc315, 0x00 }, { 0xc316, 0xff },
	{ 0xc317, 0x0b }, { 0xc318, 0x00 }, { 0xc319, 0x0c }, { 0xc31a, 0x00 },
	{ 0xc31b, 0xe0 }, { 0xc31c, 0x00 }, { 0xc31d, 0x14 }, { 0xc31e, 0x00 },
	{ 0xc31f, 0xc5 }, { 0xc320, 0xff }, { 0xc321, 0x4b }, { 0xc322, 0xff },
	{ 0xc323, 0xf0 }, { 0xc324, 0xff }, { 0xc325, 0xe8 }, { 0xc326, 0x00 },
	{ 0xc327, 0x46 }, { 0xc328, 0xff }, { 0xc329, 0xd2 }, { 0xc32a, 0xff },
	{ 0xc32b, 0xe4 }, { 0xc32c, 0xff }, { 0xc32d, 0xbb }, { 0xc32e, 0x00 },
	{ 0xc32f, 0x61 }, { 0xc330, 0xff }, { 0xc331, 0xf9 }, { 0xc332, 0x00 },
	{ 0xc333, 0xd9 }, { 0xc334, 0x00 }, { 0xc335, 0x2e }, { 0xc336, 0x00 },
	{ 0xc337, 0xb1 }, { 0xc338, 0xff }, { 0xc339, 0x64 }, { 0xc33a, 0xff },
	{ 0xc33b, 0xeb }, { 0xc33c, 0xff }, { 0xc33d, 0xe8 }, { 0xc33e, 0x00 },
	{ 0xc33f, 0x48 }, { 0xc340, 0xff }, { 0xc341, 0xd0 }, { 0xc342, 0xff },
	{ 0xc343, 0xed }, { 0xc344, 0xff }, { 0xc345, 0xad }, { 0xc346, 0x00 },
	{ 0xc347, 0x66 }, { 0xc348, 0x01 }, { 0xc349, 0x00 }, { 0x6700, 0x04 },
	{ 0x6701, 0x7b }, { 0x6702, 0xfd }, { 0x6703, 0xf9 }, { 0x6704, 0x3d },
	{ 0x6705, 0x71 }, { 0x6706, 0x78 }, { 0x6708, 0x05 }, { 0x6f06, 0x6f },
	{ 0x6f07, 0x00 }, { 0x6f0a, 0x6f }, { 0x6f0b, 0x00 }, { 0x6f00, 0x03 },
	{ 0xc34c, 0x01 }, { 0xc34d, 0x00 }, { 0xc34e, 0x46 }, { 0xc34f, 0x55 },
	{ 0xc350, 0x00 }, { 0xc351, 0x40 }, { 0xc352, 0x00 }, { 0xc353, 0xff },
	{ 0xc354, 0x04 }, { 0xc355, 0x08 }, { 0xc356, 0x01 }, { 0xc357, 0xef },
	{ 0xc358, 0x30 }, { 0xc359, 0x01 }, { 0xc35a, 0x64 }, { 0xc35b, 0x46 },
	{ 0xc35c, 0x00 }, { 0x3042, 0xf0 }, { 0x3042, 0xf0 }, { 0x3042, 0xf0 },
	{ 0x3042, 0xf0 }, { 0x3042, 0xf0 }, { 0x3042, 0xf0 }, { 0x3042, 0xf0 },
	{ 0x3042, 0xf0 }, { 0x3042, 0xf0 }, { 0x3042, 0xf0 }, { 0x3042, 0xf0 },
	{ 0x3042, 0xf0 }, { 0x3042, 0xf0 }, { 0x3042, 0xf0 }, { 0x3042, 0xf0 },
	{ 0x3042, 0xf0 }, { 0x3042, 0xf0 }, { 0x3042, 0xf0 }, { 0x3042, 0xf0 },
	{ 0x3042, 0xf0 }, { 0x3042, 0xf0 }, { 0x3042, 0xf0 }, { 0x3042, 0xf0 },
	{ 0x3042, 0xf0 }, { 0x3042, 0xf0 }, { 0x3042, 0xf0 }, { 0xc261, 0x01 },
	{ 0x301b, 0xf0 }, { 0x301c, 0xf0 }, { 0x301a, 0xf0 }, { 0x6f00, 0xc3 },
	{ 0xc46a, 0x30 }, { 0xc46d, 0x20 }, { 0xc464, 0x84 }, { 0xc465, 0x00 },
	{ 0x6f00, 0x03 }, { 0x6f00, 0x43 }, { 0x381c, 0x00 }, { 0x381d, 0x40 },
	{ 0xc454, 0x01 }, { 0x6f00, 0xc3 }, { 0xc454, 0x00 }, { 0xc4b1, 0x02 },
	{ 0xc4b2, 0x01 }, { 0xc4b3, 0x03 }, { 0x6f00, 0x03 }, { 0x6f00, 0x43 },
	/* enable FSIN (FRAMESYNC input) functionality */
	{ 0x3832, (0x0d + 2 * 0x20 + 0x15 + 38) >> 8 },
	{ 0x3833, (0x0d + 2 * 0x20 + 0x15 + 38) & 0xff },
	{ 0x3834, OV10635_VTS >> 8 }, { 0x3835, OV10635_VTS & 0xff },
	{ 0x302e, 0x01 },
};

struct rdacm20_device {
	struct device			*dev;
	struct max9271_device		*serializer;
	struct i2c_client		*sensor;
	struct v4l2_subdev		sd;
	struct media_pad		pad;
	struct v4l2_ctrl_handler	ctrls;
	u32				addrs[2];
};

static inline struct rdacm20_device *sd_to_rdacm20(struct v4l2_subdev *sd)
{
	return container_of(sd, struct rdacm20_device, sd);
}

static inline struct rdacm20_device *i2c_to_rdacm20(struct i2c_client *client)
{
	return sd_to_rdacm20(i2c_get_clientdata(client));
}

static int ov10635_read16(struct rdacm20_device *dev, u16 reg)
{
	u8 buf[2] = { reg >> 8, reg & 0xff };
	int ret;

	ret = i2c_master_send(dev->sensor, buf, 2);
	if (ret != 2) {
		dev_dbg(dev->dev, "%s: register 0x%04x write failed (%d)\n",
			__func__, reg, ret);
		return ret;
	}

	ret = i2c_master_recv(dev->sensor, buf, 2);
	if (ret < 0) {
		dev_dbg(dev->dev, "%s: register 0x%04x read failed (%d)\n",
			__func__, reg, ret);
		return ret;
	}

	return (buf[0] << 8) | buf[1];
}

static int __ov10635_write(struct rdacm20_device *dev, u16 reg, u8 val)
{
	u8 buf[3] = { reg >> 8, reg & 0xff, val };
	int ret;

	dev_dbg(dev->dev, "%s(0x%04x, 0x%02x)\n", __func__, reg, val);

	ret = i2c_master_send(dev->sensor, buf, 3);
	return ret < 0 ? ret : 0;
}

static int ov10635_write(struct rdacm20_device *dev, u16 reg, u8 val)
{
	int ret;

	ret = __ov10635_write(dev, reg, val);
	if (ret < 0)
		dev_err(dev->dev, "%s: register 0x%04x write failed (%d)\n",
			__func__, reg, ret);

	return ret;
}

static int ov10635_set_regs(struct rdacm20_device *dev,
			    const struct ov10635_reg *regs,
			    unsigned int nr_regs)
{
	unsigned int i;
	int ret;

	for (i = 0; i < nr_regs; i++) {
		ret = __ov10635_write(dev, regs[i].reg, regs[i].val);
		if (ret) {
			dev_err(dev->dev,
				"%s: register %u (0x%04x) write failed (%d)\n",
				__func__, i, regs[i].reg, ret);
			return ret;
		}
	}

	return 0;
}

static int rdacm20_s_stream(struct v4l2_subdev *sd, int enable)
{
	struct rdacm20_device *dev = sd_to_rdacm20(sd);

	return max9271_set_serial_link(dev->serializer, enable);
}

static int rdacm20_enum_mbus_code(struct v4l2_subdev *sd,
				  struct v4l2_subdev_pad_config *cfg,
				  struct v4l2_subdev_mbus_code_enum *code)
{
	if (code->pad || code->index > 0)
		return -EINVAL;

	code->code = MEDIA_BUS_FMT_UYVY8_2X8;

	return 0;
}

static int rdacm20_get_fmt(struct v4l2_subdev *sd,
			   struct v4l2_subdev_pad_config *cfg,
			   struct v4l2_subdev_format *format)
{
	struct v4l2_mbus_framefmt *mf = &format->format;

	if (format->pad)
		return -EINVAL;

	mf->width		= OV10635_WIDTH;
	mf->height		= OV10635_HEIGHT;
	mf->code		= MEDIA_BUS_FMT_UYVY8_2X8;
	mf->colorspace		= V4L2_COLORSPACE_RAW;
	mf->field		= V4L2_FIELD_NONE;
	mf->ycbcr_enc		= V4L2_YCBCR_ENC_601;
	mf->quantization	= V4L2_QUANTIZATION_FULL_RANGE;
	mf->xfer_func		= V4L2_XFER_FUNC_NONE;

	return 0;
}

static struct v4l2_subdev_video_ops rdacm20_video_ops = {
	.s_stream	= rdacm20_s_stream,
};

static const struct v4l2_subdev_pad_ops rdacm20_subdev_pad_ops = {
	.enum_mbus_code = rdacm20_enum_mbus_code,
	.get_fmt	= rdacm20_get_fmt,
	.set_fmt	= rdacm20_get_fmt,
};

static struct v4l2_subdev_ops rdacm20_subdev_ops = {
	.video		= &rdacm20_video_ops,
	.pad		= &rdacm20_subdev_pad_ops,
};

static int rdacm20_initialize(struct rdacm20_device *dev)
{
	unsigned int retry = 3;
	int ret;

	/* Verify communication with the MAX9271: ping to wakeup. */
	dev->serializer->client->addr = MAX9271_DEFAULT_ADDR;
	i2c_smbus_read_byte(dev->serializer->client);

	/* Serial link disabled during config as it needs a valid pixel clock. */
	ret = max9271_set_serial_link(dev->serializer, false);
	if (ret)
		return ret;

	/*
	 *  Ensure that we have a good link configuration before attempting to
	 *  identify the device.
	 */
	max9271_configure_i2c(dev->serializer, MAX9271_I2CSLVSH_469NS_234NS |
					       MAX9271_I2CSLVTO_1024US |
					       MAX9271_I2CMSTBT_105KBPS);

	max9271_configure_gmsl_link(dev->serializer);

	ret = max9271_verify_id(dev->serializer);
	if (ret < 0)
		return ret;

	ret = max9271_set_address(dev->serializer, dev->addrs[0]);
	if (ret < 0)
		return ret;
	dev->serializer->client->addr = dev->addrs[0];

	/*
	 * Reset the sensor by cycling the OV10635 reset signal connected to the
	 * MAX9271 GPIO1 and verify communication with the OV10635.
	 */
	ret = max9271_enable_gpios(dev->serializer, MAX9271_GPIO1OUT);
	if (ret)
		return ret;

	ret = max9271_clear_gpios(dev->serializer, MAX9271_GPIO1OUT);
	if (ret)
		return ret;
	usleep_range(10000, 15000);

	ret = max9271_set_gpios(dev->serializer, MAX9271_GPIO1OUT);
	if (ret)
		return ret;
	usleep_range(10000, 15000);

again:
	ret = ov10635_read16(dev, OV10635_PID);
	if (ret < 0) {
		if (retry--)
			goto again;

		dev_err(dev->dev, "OV10635 ID read failed (%d)\n",
			ret);
		return -ENXIO;
	}

	if (ret != OV10635_VERSION) {
		if (retry--)
			goto again;

		dev_err(dev->dev, "OV10635 ID mismatch (0x%04x)\n",
			ret);
		return -ENXIO;
	}

	/* Change the sensor I2C address. */
	ret = ov10635_write(dev, OV10635_SC_CMMN_SCCB_ID,
			    (dev->addrs[1] << 1) |
			    OV10635_SC_CMMN_SCCB_ID_SELECT);
	if (ret < 0) {
		dev_err(dev->dev,
			"OV10635 I2C address change failed (%d)\n", ret);
		return ret;
	}
	dev->sensor->addr = dev->addrs[1];
	usleep_range(3500, 5000);

	/* Program the 0V10635 initial configuration. */
	ret = ov10635_set_regs(dev, ov10635_regs_wizard,
			       ARRAY_SIZE(ov10635_regs_wizard));
	if (ret)
		return ret;

	dev_info(dev->dev, "Identified MAX9271 + OV10635 device\n");

	return 0;
}

static int rdacm20_probe(struct i2c_client *client)
{
	struct rdacm20_device *dev;
	struct fwnode_handle *ep;
	int ret;

	dev = devm_kzalloc(&client->dev, sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;
	dev->dev = &client->dev;

	dev->serializer = devm_kzalloc(&client->dev, sizeof(*dev->serializer),
				       GFP_KERNEL);
	if (!dev->serializer)
		return -ENOMEM;

	dev->serializer->client = client;

	ret = of_property_read_u32_array(client->dev.of_node, "reg",
					 dev->addrs, 2);
	if (ret < 0) {
		dev_err(dev->dev, "Invalid DT reg property: %d\n", ret);
		return -EINVAL;
	}

	/* Create the dummy I2C client for the sensor. */
	dev->sensor = i2c_new_dummy_device(client->adapter,
					   OV10635_I2C_ADDRESS);
	if (IS_ERR(dev->sensor)) {
		ret = PTR_ERR(dev->sensor);
		goto error;
	}

	/* Initialize the hardware. */
	ret = rdacm20_initialize(dev);
	if (ret < 0)
		goto error;

	/* Initialize and register the subdevice. */
	v4l2_i2c_subdev_init(&dev->sd, client, &rdacm20_subdev_ops);
	dev->sd.flags |= V4L2_SUBDEV_FL_HAS_DEVNODE;

	v4l2_ctrl_handler_init(&dev->ctrls, 1);
	v4l2_ctrl_new_std(&dev->ctrls, NULL, V4L2_CID_PIXEL_RATE,
			  OV10635_PIXEL_RATE, OV10635_PIXEL_RATE, 1,
			  OV10635_PIXEL_RATE);
	dev->sd.ctrl_handler = &dev->ctrls;

	ret = dev->ctrls.error;
	if (ret)
		goto error_free_ctrls;

	dev->pad.flags = MEDIA_PAD_FL_SOURCE;
	dev->sd.entity.flags |= MEDIA_ENT_F_CAM_SENSOR;
	ret = media_entity_pads_init(&dev->sd.entity, 1, &dev->pad);
	if (ret < 0)
		goto error_free_ctrls;

	ep = fwnode_graph_get_next_endpoint(dev_fwnode(&client->dev), NULL);
	if (!ep) {
		dev_err(&client->dev,
			"Unable to get endpoint in node %pOF\n",
			client->dev.of_node);
		ret = -ENOENT;
		goto error_free_ctrls;
	}
	dev->sd.fwnode = ep;

	ret = v4l2_async_register_subdev(&dev->sd);
	if (ret)
		goto error_put_node;

	return 0;

error_put_node:
	fwnode_handle_put(ep);
error_free_ctrls:
	v4l2_ctrl_handler_free(&dev->ctrls);
error:
	media_entity_cleanup(&dev->sd.entity);
	if (dev->sensor)
		i2c_unregister_device(dev->sensor);

	dev_err(&client->dev, "probe failed\n");

	return ret;
}

static int rdacm20_remove(struct i2c_client *client)
{
	struct rdacm20_device *dev = i2c_to_rdacm20(client);

	fwnode_handle_put(dev->sd.fwnode);
	v4l2_async_unregister_subdev(&dev->sd);
	v4l2_ctrl_handler_free(&dev->ctrls);
	media_entity_cleanup(&dev->sd.entity);
	i2c_unregister_device(dev->sensor);

	return 0;
}

static void rdacm20_shutdown(struct i2c_client *client)
{
	struct rdacm20_device *dev = i2c_to_rdacm20(client);

	/* make sure stream off during shutdown (reset/reboot) */
	rdacm20_s_stream(&dev->sd, 0);
}

static const struct of_device_id rdacm20_of_ids[] = {
	{ .compatible = "imi,rdacm20", },
	{ }
};
MODULE_DEVICE_TABLE(of, rdacm20_of_ids);

static struct i2c_driver rdacm20_i2c_driver = {
	.driver	= {
		.name	= "rdacm20",
		.of_match_table = rdacm20_of_ids,
	},
	.probe_new	= rdacm20_probe,
	.remove		= rdacm20_remove,
	.shutdown	= rdacm20_shutdown,
};

module_i2c_driver(rdacm20_i2c_driver);

MODULE_DESCRIPTION("GMSL Camera driver for RDACM20");
MODULE_AUTHOR("Vladimir Barinov");
MODULE_LICENSE("GPL");
