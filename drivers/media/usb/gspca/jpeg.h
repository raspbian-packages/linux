#ifndef JPEG_H
#define JPEG_H 1
/*
 * Insert a JPEG header at start of frame
 *
 * This module is used by the gspca subdrivers.
 * A special case is done for Conexant webcams.
 *
 * Copyright (C) Jean-Francois Moine (http://moinejf.free.fr)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

/*
 * generation options
 *	CONEX_CAM	Conexant if present
 */

/* JPEG header */
static const u8 jpeg_head[] = {
	0xff, 0xd8,			/* jpeg */

/* quantization table quality 50% */
	0xff, 0xdb, 0x00, 0x84,		/* DQT */
0,
#define JPEG_QT0_OFFSET 7
	0x10, 0x0b, 0x0c, 0x0e, 0x0c, 0x0a, 0x10, 0x0e,
	0x0d, 0x0e, 0x12, 0x11, 0x10, 0x13, 0x18, 0x28,
	0x1a, 0x18, 0x16, 0x16, 0x18, 0x31, 0x23, 0x25,
	0x1d, 0x28, 0x3a, 0x33, 0x3d, 0x3c, 0x39, 0x33,
	0x38, 0x37, 0x40, 0x48, 0x5c, 0x4e, 0x40, 0x44,
	0x57, 0x45, 0x37, 0x38, 0x50, 0x6d, 0x51, 0x57,
	0x5f, 0x62, 0x67, 0x68, 0x67, 0x3e, 0x4d, 0x71,
	0x79, 0x70, 0x64, 0x78, 0x5c, 0x65, 0x67, 0x63,
1,
#define JPEG_QT1_OFFSET 72
	0x11, 0x12, 0x12, 0x18, 0x15, 0x18, 0x2f, 0x1a,
	0x1a, 0x2f, 0x63, 0x42, 0x38, 0x42, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,

/* huffman table */
	0xff, 0xc4, 0x01, 0xa2,
	0x00, 0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	0x07, 0x08, 0x09, 0x0a, 0x0b, 0x01, 0x00, 0x03,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x0a, 0x0b, 0x10, 0x00, 0x02, 0x01, 0x03, 0x03,
	0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00,
	0x00, 0x01, 0x7d, 0x01, 0x02, 0x03, 0x00, 0x04,
	0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13,
	0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32, 0x81,
	0x91, 0xa1, 0x08, 0x23, 0x42, 0xb1, 0xc1, 0x15,
	0x52, 0xd1, 0xf0, 0x24, 0x33, 0x62, 0x72, 0x82,
	0x09, 0x0a, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x25,
	0x26, 0x27, 0x28, 0x29, 0x2a, 0x34, 0x35, 0x36,
	0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46,
	0x47, 0x48, 0x49, 0x4a, 0x53, 0x54, 0x55, 0x56,
	0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66,
	0x67, 0x68, 0x69, 0x6a, 0x73, 0x74, 0x75, 0x76,
	0x77, 0x78, 0x79, 0x7a, 0x83, 0x84, 0x85, 0x86,
	0x87, 0x88, 0x89, 0x8a, 0x92, 0x93, 0x94, 0x95,
	0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4,
	0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2, 0xb3,
	0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2,
	0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca,
	0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9,
	0xda, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
	0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
	0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0x11, 0x00, 0x02,
	0x01, 0x02, 0x04, 0x04, 0x03, 0x04, 0x07, 0x05,
	0x04, 0x04, 0x00, 0x01, 0x02, 0x77, 0x00, 0x01,
	0x02, 0x03, 0x11, 0x04, 0x05, 0x21, 0x31, 0x06,
	0x12, 0x41, 0x51, 0x07, 0x61, 0x71, 0x13, 0x22,
	0x32, 0x81, 0x08, 0x14, 0x42, 0x91, 0xa1, 0xb1,
	0xc1, 0x09, 0x23, 0x33, 0x52, 0xf0, 0x15, 0x62,
	0x72, 0xd1, 0x0a, 0x16, 0x24, 0x34, 0xe1, 0x25,
	0xf1, 0x17, 0x18, 0x19, 0x1a, 0x26, 0x27, 0x28,
	0x29, 0x2a, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a,
	0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a,
	0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
	0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
	0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a,
	0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
	0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
	0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
	0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6,
	0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5,
	0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4,
	0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe2, 0xe3,
	0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf2,
	0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa,
#ifdef CONEX_CAM
/* the Conexant frames start with SOF0 */
#define JPEG_HDR_SZ 556
#else
	0xff, 0xc0, 0x00, 0x11,		/* SOF0 (start of frame 0 */
	0x08,				/* data precision */
#define JPEG_HEIGHT_OFFSET 561
	0x01, 0xe0,			/* height */
	0x02, 0x80,			/* width */
	0x03,				/* component number */
		0x01,
			0x21,		/* samples Y */
			0x00,		/* quant Y */
		0x02, 0x11, 0x01,	/* samples CbCr - quant CbCr */
		0x03, 0x11, 0x01,

	0xff, 0xda, 0x00, 0x0c,		/* SOS (start of scan) */
	0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3f, 0x00
#define JPEG_HDR_SZ 589
#endif
};

/* define the JPEG header */
static void jpeg_define(u8 *jpeg_hdr,
			int height,
			int width,
			int samplesY)
{
	memcpy(jpeg_hdr, jpeg_head, sizeof jpeg_head);
#ifndef CONEX_CAM
	jpeg_hdr[JPEG_HEIGHT_OFFSET + 0] = height >> 8;
	jpeg_hdr[JPEG_HEIGHT_OFFSET + 1] = height;
	jpeg_hdr[JPEG_HEIGHT_OFFSET + 2] = width >> 8;
	jpeg_hdr[JPEG_HEIGHT_OFFSET + 3] = width;
	jpeg_hdr[JPEG_HEIGHT_OFFSET + 6] = samplesY;
#endif
}

/* set the JPEG quality */
static void jpeg_set_qual(u8 *jpeg_hdr,
			  int quality)
{
	int i, sc;

	if (quality <= 0)
		sc = 5000;
	else if (quality < 50)
		sc = 5000 / quality;
	else
		sc = 200 - quality * 2;
	for (i = 0; i < 64; i++) {
		jpeg_hdr[JPEG_QT0_OFFSET + i] =
			(jpeg_head[JPEG_QT0_OFFSET + i] * sc + 50) / 100;
		jpeg_hdr[JPEG_QT1_OFFSET + i] =
			(jpeg_head[JPEG_QT1_OFFSET + i] * sc + 50) / 100;
	}
}
#endif
