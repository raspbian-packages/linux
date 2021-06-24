/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2010-2013 Bluecherry, LLC <https://www.bluecherrydvr.com>
 *
 * Original author:
 * Ben Collins <bcollins@ubuntu.com>
 *
 * Additional work by:
 * John Brooks <john.brooks@bluecherry.net>
 */

#ifndef __SOLO6X10_JPEG_H
#define __SOLO6X10_JPEG_H

static const u8 jpeg_header[] = {
	0xff, 0xd8, 0xff, 0xfe, 0x00, 0x0d, 0x42, 0x6c,
	0x75, 0x65, 0x63, 0x68, 0x65, 0x72, 0x72, 0x79,
	0x20, 0xff, 0xdb, 0x00, 0x43, 0x00, 0x20, 0x16,
	0x18, 0x1c, 0x18, 0x14, 0x20, 0x1c, 0x1a, 0x1c,
	0x24, 0x22, 0x20, 0x26, 0x30, 0x50, 0x34, 0x30,
	0x2c, 0x2c, 0x30, 0x62, 0x46, 0x4a, 0x3a, 0x50,
	0x74, 0x66, 0x7a, 0x78, 0x72, 0x66, 0x70, 0x6e,
	0x80, 0x90, 0xb8, 0x9c, 0x80, 0x88, 0xae, 0x8a,
	0x6e, 0x70, 0xa0, 0xda, 0xa2, 0xae, 0xbe, 0xc4,
	0xce, 0xd0, 0xce, 0x7c, 0x9a, 0xe2, 0xf2, 0xe0,
	0xc8, 0xf0, 0xb8, 0xca, 0xce, 0xc6, 0xff, 0xdb,
	0x00, 0x43, 0x01, 0x22, 0x24, 0x24, 0x30, 0x2a,
	0x30, 0x5e, 0x34, 0x34, 0x5e, 0xc6, 0x84, 0x70,
	0x84, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6,
	0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6,
	0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6,
	0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6,
	0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6,
	0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6,
	0xc6, 0xc6, 0xc6, 0xff, 0xc4, 0x01, 0xa2, 0x00,
	0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x10, 0x00, 0x02, 0x01,
	0x03, 0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04,
	0x04, 0x00, 0x00, 0x01, 0x7d, 0x01, 0x02, 0x03,
	0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41,
	0x06, 0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14,
	0x32, 0x81, 0x91, 0xa1, 0x08, 0x23, 0x42, 0xb1,
	0xc1, 0x15, 0x52, 0xd1, 0xf0, 0x24, 0x33, 0x62,
	0x72, 0x82, 0x09, 0x0a, 0x16, 0x17, 0x18, 0x19,
	0x1a, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x34,
	0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44,
	0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x53, 0x54,
	0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64,
	0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x73, 0x74,
	0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x83, 0x84,
	0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x92, 0x93,
	0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2,
	0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa,
	0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9,
	0xba, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
	0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
	0xd8, 0xd9, 0xda, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5,
	0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3,
	0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0x01,
	0x00, 0x03, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x11, 0x00, 0x02, 0x01,
	0x02, 0x04, 0x04, 0x03, 0x04, 0x07, 0x05, 0x04,
	0x04, 0x00, 0x01, 0x02, 0x77, 0x00, 0x01, 0x02,
	0x03, 0x11, 0x04, 0x05, 0x21, 0x31, 0x06, 0x12,
	0x41, 0x51, 0x07, 0x61, 0x71, 0x13, 0x22, 0x32,
	0x81, 0x08, 0x14, 0x42, 0x91, 0xa1, 0xb1, 0xc1,
	0x09, 0x23, 0x33, 0x52, 0xf0, 0x15, 0x62, 0x72,
	0xd1, 0x0a, 0x16, 0x24, 0x34, 0xe1, 0x25, 0xf1,
	0x17, 0x18, 0x19, 0x1a, 0x26, 0x27, 0x28, 0x29,
	0x2a, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43,
	0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x53,
	0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63,
	0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x73,
	0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x82,
	0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a,
	0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
	0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
	0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
	0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6,
	0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5,
	0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe2, 0xe3, 0xe4,
	0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf2, 0xf3,
	0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xff,
	0xc0, 0x00, 0x11, 0x08, 0x00, 0xf0, 0x02, 0xc0,
	0x03, 0x01, 0x22, 0x00, 0x02, 0x11, 0x01, 0x03,
	0x11, 0x01, 0xff, 0xda, 0x00, 0x0c, 0x03, 0x01,
	0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3f, 0x00
};

/* This is the byte marker for the start of SOF0: 0xffc0 marker */
#define SOF0_START	575

/* This is the byte marker for the start of the DQT */
#define DQT_START	17
#define DQT_LEN		138
static const u8 jpeg_dqt[4][DQT_LEN] = {
	{
		0xff, 0xdb, 0x00, 0x43, 0x00,
		0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07,
		0x07, 0x07, 0x09, 0x09, 0x08, 0x0a, 0x0c, 0x14,
		0x0d, 0x0c, 0x0b, 0x0b, 0x0c, 0x19, 0x12, 0x13,
		0x0f, 0x14, 0x1d, 0x1a, 0x1f, 0x1e, 0x1d, 0x1a,
		0x1c, 0x1c, 0x20, 0x24, 0x2e, 0x27, 0x20, 0x22,
		0x2c, 0x23, 0x1c, 0x1c, 0x28, 0x37, 0x29, 0x2c,
		0x30, 0x31, 0x34, 0x34, 0x34, 0x1f, 0x27, 0x39,
		0x3d, 0x38, 0x32, 0x3c, 0x2e, 0x33, 0x34, 0x32,
		0xff, 0xdb, 0x00, 0x43, 0x01,
		0x09, 0x09, 0x09, 0x0c, 0x0b, 0x0c, 0x18, 0x0d,
		0x0d, 0x18, 0x32, 0x21, 0x1c, 0x21, 0x32, 0x32,
		0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32,
		0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32,
		0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32,
		0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32,
		0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32,
		0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32
	}, {
		0xff, 0xdb, 0x00, 0x43, 0x00,
		0x10, 0x0b, 0x0c, 0x0e, 0x0c, 0x0a, 0x10, 0x0e,
		0x0d, 0x0e, 0x12, 0x11, 0x10, 0x13, 0x18, 0x28,
		0x1a, 0x18, 0x16, 0x16, 0x18, 0x31, 0x23, 0x25,
		0x1d, 0x28, 0x3a, 0x33, 0x3d, 0x3c, 0x39, 0x33,
		0x38, 0x37, 0x40, 0x48, 0x5c, 0x4e, 0x40, 0x44,
		0x57, 0x45, 0x37, 0x38, 0x50, 0x6d, 0x51, 0x57,
		0x5f, 0x62, 0x67, 0x68, 0x67, 0x3e, 0x4d, 0x71,
		0x79, 0x70, 0x64, 0x78, 0x5c, 0x65, 0x67, 0x63,
		0xff, 0xdb, 0x00, 0x43, 0x01,
		0x11, 0x12, 0x12, 0x18, 0x15, 0x18, 0x2f, 0x1a,
		0x1a, 0x2f, 0x63, 0x42, 0x38, 0x42, 0x63, 0x63,
		0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
		0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
		0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
		0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
		0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
		0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63
	}, {
		0xff, 0xdb, 0x00, 0x43, 0x00,
		0x20, 0x16, 0x18, 0x1c, 0x18, 0x14, 0x20, 0x1c,
		0x1a, 0x1c, 0x24, 0x22, 0x20, 0x26, 0x30, 0x50,
		0x34, 0x30, 0x2c, 0x2c, 0x30, 0x62, 0x46, 0x4a,
		0x3a, 0x50, 0x74, 0x66, 0x7a, 0x78, 0x72, 0x66,
		0x70, 0x6e, 0x80, 0x90, 0xb8, 0x9c, 0x80, 0x88,
		0xae, 0x8a, 0x6e, 0x70, 0xa0, 0xda, 0xa2, 0xae,
		0xbe, 0xc4, 0xce, 0xd0, 0xce, 0x7c, 0x9a, 0xe2,
		0xf2, 0xe0, 0xc8, 0xf0, 0xb8, 0xca, 0xce, 0xc6,
		0xff, 0xdb, 0x00, 0x43, 0x01,
		0x22, 0x24, 0x24, 0x30, 0x2a, 0x30, 0x5e, 0x34,
		0x34, 0x5e, 0xc6, 0x84, 0x70, 0x84, 0xc6, 0xc6,
		0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6,
		0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6,
		0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6,
		0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6,
		0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6,
		0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6
	}, {
		0xff, 0xdb, 0x00, 0x43, 0x00,
		0x30, 0x21, 0x24, 0x2a, 0x24, 0x1e, 0x30, 0x2a,
		0x27, 0x2a, 0x36, 0x33, 0x30, 0x39, 0x48, 0x78,
		0x4e, 0x48, 0x42, 0x42, 0x48, 0x93, 0x69, 0x6f,
		0x57, 0x78, 0xae, 0x99, 0xb7, 0xb4, 0xab, 0x99,
		0xa8, 0xa5, 0xc0, 0xd8, 0xff, 0xea, 0xc0, 0xcc,
		0xff, 0xcf, 0xa5, 0xa8, 0xf0, 0xff, 0xf3, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xba, 0xe7, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xdb, 0x00, 0x43, 0x01,
		0x33, 0x36, 0x36, 0x48, 0x3f, 0x48, 0x8d, 0x4e,
		0x4e, 0x8d, 0xff, 0xc6, 0xa8, 0xc6, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	}
};

#endif /* __SOLO6X10_JPEG_H */
