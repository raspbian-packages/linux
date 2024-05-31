// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 1996, 2003 VIA Networking Technologies, Inc.
 * All rights reserved.
 *
 * Purpose: Implement functions to access baseband
 *
 * Author: Kyle Hsu
 *
 * Date: Aug.22, 2002
 *
 * Functions:
 *      bb_get_frame_time	 - Calculate data frame transmitting time
 *      bb_read_embedded	 - Embedded read baseband register via MAC
 *      bb_write_embedded	 - Embedded write baseband register via MAC
 *      bb_vt3253_init		 - VIA VT3253 baseband chip init code
 *
 * Revision History:
 *      06-10-2003 Bryan YC Fan:  Re-write codes to support VT3253 spec.
 *      08-07-2003 Bryan YC Fan:  Add MAXIM2827/2825 and RFMD2959 support.
 *      08-26-2003 Kyle Hsu    :  Modify BBuGetFrameTime() and
 *				  BBvCalculateParameter().
 *                                cancel the setting of MAC_REG_SOFTPWRCTL on
 *				  BBbVT3253Init().
 *                                Add the comments.
 *      09-01-2003 Bryan YC Fan:  RF & BB tables updated.
 *                                Modified BBvLoopbackOn & BBvLoopbackOff().
 *
 *
 */

#include "mac.h"
#include "baseband.h"
#include "srom.h"
#include "rf.h"

/*---------------------  Static Classes  ----------------------------*/

/*---------------------  Static Variables  --------------------------*/

/*---------------------  Static Functions  --------------------------*/

/*---------------------  Export Variables  --------------------------*/

/*---------------------  Static Definitions -------------------------*/

/*---------------------  Static Classes  ----------------------------*/

/*---------------------  Static Variables  --------------------------*/

#define CB_VT3253_INIT_FOR_RFMD 446
static const unsigned char by_vt3253_init_tab_rfmd[CB_VT3253_INIT_FOR_RFMD][2] = {
	{0x00, 0x30},
	{0x01, 0x00},
	{0x02, 0x00},
	{0x03, 0x00},
	{0x04, 0x00},
	{0x05, 0x00},
	{0x06, 0x00},
	{0x07, 0x00},
	{0x08, 0x70},
	{0x09, 0x45},
	{0x0a, 0x2a},
	{0x0b, 0x76},
	{0x0c, 0x00},
	{0x0d, 0x01},
	{0x0e, 0x80},
	{0x0f, 0x00},
	{0x10, 0x00},
	{0x11, 0x00},
	{0x12, 0x00},
	{0x13, 0x00},
	{0x14, 0x00},
	{0x15, 0x00},
	{0x16, 0x00},
	{0x17, 0x00},
	{0x18, 0x00},
	{0x19, 0x00},
	{0x1a, 0x00},
	{0x1b, 0x9d},
	{0x1c, 0x05},
	{0x1d, 0x00},
	{0x1e, 0x00},
	{0x1f, 0x00},
	{0x20, 0x00},
	{0x21, 0x00},
	{0x22, 0x00},
	{0x23, 0x00},
	{0x24, 0x00},
	{0x25, 0x4a},
	{0x26, 0x00},
	{0x27, 0x00},
	{0x28, 0x00},
	{0x29, 0x00},
	{0x2a, 0x00},
	{0x2b, 0x00},
	{0x2c, 0x00},
	{0x2d, 0xa8},
	{0x2e, 0x1a},
	{0x2f, 0x0c},
	{0x30, 0x26},
	{0x31, 0x5b},
	{0x32, 0x00},
	{0x33, 0x00},
	{0x34, 0x00},
	{0x35, 0x00},
	{0x36, 0xaa},
	{0x37, 0xaa},
	{0x38, 0xff},
	{0x39, 0xff},
	{0x3a, 0x00},
	{0x3b, 0x00},
	{0x3c, 0x00},
	{0x3d, 0x0d},
	{0x3e, 0x51},
	{0x3f, 0x04},
	{0x40, 0x00},
	{0x41, 0x08},
	{0x42, 0x00},
	{0x43, 0x08},
	{0x44, 0x06},
	{0x45, 0x14},
	{0x46, 0x05},
	{0x47, 0x08},
	{0x48, 0x00},
	{0x49, 0x00},
	{0x4a, 0x00},
	{0x4b, 0x00},
	{0x4c, 0x09},
	{0x4d, 0x80},
	{0x4e, 0x00},
	{0x4f, 0xc5},
	{0x50, 0x14},
	{0x51, 0x19},
	{0x52, 0x00},
	{0x53, 0x00},
	{0x54, 0x00},
	{0x55, 0x00},
	{0x56, 0x00},
	{0x57, 0x00},
	{0x58, 0x00},
	{0x59, 0xb0},
	{0x5a, 0x00},
	{0x5b, 0x00},
	{0x5c, 0x00},
	{0x5d, 0x00},
	{0x5e, 0x00},
	{0x5f, 0x00},
	{0x60, 0x44},
	{0x61, 0x04},
	{0x62, 0x00},
	{0x63, 0x00},
	{0x64, 0x00},
	{0x65, 0x00},
	{0x66, 0x04},
	{0x67, 0xb7},
	{0x68, 0x00},
	{0x69, 0x00},
	{0x6a, 0x00},
	{0x6b, 0x00},
	{0x6c, 0x00},
	{0x6d, 0x03},
	{0x6e, 0x01},
	{0x6f, 0x00},
	{0x70, 0x00},
	{0x71, 0x00},
	{0x72, 0x00},
	{0x73, 0x00},
	{0x74, 0x00},
	{0x75, 0x00},
	{0x76, 0x00},
	{0x77, 0x00},
	{0x78, 0x00},
	{0x79, 0x00},
	{0x7a, 0x00},
	{0x7b, 0x00},
	{0x7c, 0x00},
	{0x7d, 0x00},
	{0x7e, 0x00},
	{0x7f, 0x00},
	{0x80, 0x0b},
	{0x81, 0x00},
	{0x82, 0x3c},
	{0x83, 0x00},
	{0x84, 0x00},
	{0x85, 0x00},
	{0x86, 0x00},
	{0x87, 0x00},
	{0x88, 0x08},
	{0x89, 0x00},
	{0x8a, 0x08},
	{0x8b, 0xa6},
	{0x8c, 0x84},
	{0x8d, 0x47},
	{0x8e, 0xbb},
	{0x8f, 0x02},
	{0x90, 0x21},
	{0x91, 0x0c},
	{0x92, 0x04},
	{0x93, 0x22},
	{0x94, 0x00},
	{0x95, 0x00},
	{0x96, 0x00},
	{0x97, 0xeb},
	{0x98, 0x00},
	{0x99, 0x00},
	{0x9a, 0x00},
	{0x9b, 0x00},
	{0x9c, 0x00},
	{0x9d, 0x00},
	{0x9e, 0x00},
	{0x9f, 0x00},
	{0xa0, 0x00},
	{0xa1, 0x00},
	{0xa2, 0x00},
	{0xa3, 0x00},
	{0xa4, 0x00},
	{0xa5, 0x00},
	{0xa6, 0x10},
	{0xa7, 0x04},
	{0xa8, 0x10},
	{0xa9, 0x00},
	{0xaa, 0x8f},
	{0xab, 0x00},
	{0xac, 0x00},
	{0xad, 0x00},
	{0xae, 0x00},
	{0xaf, 0x80},
	{0xb0, 0x38},
	{0xb1, 0x00},
	{0xb2, 0x00},
	{0xb3, 0x00},
	{0xb4, 0xee},
	{0xb5, 0xff},
	{0xb6, 0x10},
	{0xb7, 0x00},
	{0xb8, 0x00},
	{0xb9, 0x00},
	{0xba, 0x00},
	{0xbb, 0x03},
	{0xbc, 0x00},
	{0xbd, 0x00},
	{0xbe, 0x00},
	{0xbf, 0x00},
	{0xc0, 0x10},
	{0xc1, 0x10},
	{0xc2, 0x18},
	{0xc3, 0x20},
	{0xc4, 0x10},
	{0xc5, 0x00},
	{0xc6, 0x22},
	{0xc7, 0x14},
	{0xc8, 0x0f},
	{0xc9, 0x08},
	{0xca, 0xa4},
	{0xcb, 0xa7},
	{0xcc, 0x3c},
	{0xcd, 0x10},
	{0xce, 0x20},
	{0xcf, 0x00},
	{0xd0, 0x00},
	{0xd1, 0x10},
	{0xd2, 0x00},
	{0xd3, 0x00},
	{0xd4, 0x10},
	{0xd5, 0x33},
	{0xd6, 0x70},
	{0xd7, 0x01},
	{0xd8, 0x00},
	{0xd9, 0x00},
	{0xda, 0x00},
	{0xdb, 0x00},
	{0xdc, 0x00},
	{0xdd, 0x00},
	{0xde, 0x00},
	{0xdf, 0x00},
	{0xe0, 0x00},
	{0xe1, 0x00},
	{0xe2, 0xcc},
	{0xe3, 0x04},
	{0xe4, 0x08},
	{0xe5, 0x10},
	{0xe6, 0x00},
	{0xe7, 0x0e},
	{0xe8, 0x88},
	{0xe9, 0xd4},
	{0xea, 0x05},
	{0xeb, 0xf0},
	{0xec, 0x79},
	{0xed, 0x0f},
	{0xee, 0x04},
	{0xef, 0x04},
	{0xf0, 0x00},
	{0xf1, 0x00},
	{0xf2, 0x00},
	{0xf3, 0x00},
	{0xf4, 0x00},
	{0xf5, 0x00},
	{0xf6, 0x00},
	{0xf7, 0x00},
	{0xf8, 0x00},
	{0xf9, 0x00},
	{0xF0, 0x00},
	{0xF1, 0xF8},
	{0xF0, 0x80},
	{0xF0, 0x00},
	{0xF1, 0xF4},
	{0xF0, 0x81},
	{0xF0, 0x01},
	{0xF1, 0xF0},
	{0xF0, 0x82},
	{0xF0, 0x02},
	{0xF1, 0xEC},
	{0xF0, 0x83},
	{0xF0, 0x03},
	{0xF1, 0xE8},
	{0xF0, 0x84},
	{0xF0, 0x04},
	{0xF1, 0xE4},
	{0xF0, 0x85},
	{0xF0, 0x05},
	{0xF1, 0xE0},
	{0xF0, 0x86},
	{0xF0, 0x06},
	{0xF1, 0xDC},
	{0xF0, 0x87},
	{0xF0, 0x07},
	{0xF1, 0xD8},
	{0xF0, 0x88},
	{0xF0, 0x08},
	{0xF1, 0xD4},
	{0xF0, 0x89},
	{0xF0, 0x09},
	{0xF1, 0xD0},
	{0xF0, 0x8A},
	{0xF0, 0x0A},
	{0xF1, 0xCC},
	{0xF0, 0x8B},
	{0xF0, 0x0B},
	{0xF1, 0xC8},
	{0xF0, 0x8C},
	{0xF0, 0x0C},
	{0xF1, 0xC4},
	{0xF0, 0x8D},
	{0xF0, 0x0D},
	{0xF1, 0xC0},
	{0xF0, 0x8E},
	{0xF0, 0x0E},
	{0xF1, 0xBC},
	{0xF0, 0x8F},
	{0xF0, 0x0F},
	{0xF1, 0xB8},
	{0xF0, 0x90},
	{0xF0, 0x10},
	{0xF1, 0xB4},
	{0xF0, 0x91},
	{0xF0, 0x11},
	{0xF1, 0xB0},
	{0xF0, 0x92},
	{0xF0, 0x12},
	{0xF1, 0xAC},
	{0xF0, 0x93},
	{0xF0, 0x13},
	{0xF1, 0xA8},
	{0xF0, 0x94},
	{0xF0, 0x14},
	{0xF1, 0xA4},
	{0xF0, 0x95},
	{0xF0, 0x15},
	{0xF1, 0xA0},
	{0xF0, 0x96},
	{0xF0, 0x16},
	{0xF1, 0x9C},
	{0xF0, 0x97},
	{0xF0, 0x17},
	{0xF1, 0x98},
	{0xF0, 0x98},
	{0xF0, 0x18},
	{0xF1, 0x94},
	{0xF0, 0x99},
	{0xF0, 0x19},
	{0xF1, 0x90},
	{0xF0, 0x9A},
	{0xF0, 0x1A},
	{0xF1, 0x8C},
	{0xF0, 0x9B},
	{0xF0, 0x1B},
	{0xF1, 0x88},
	{0xF0, 0x9C},
	{0xF0, 0x1C},
	{0xF1, 0x84},
	{0xF0, 0x9D},
	{0xF0, 0x1D},
	{0xF1, 0x80},
	{0xF0, 0x9E},
	{0xF0, 0x1E},
	{0xF1, 0x7C},
	{0xF0, 0x9F},
	{0xF0, 0x1F},
	{0xF1, 0x78},
	{0xF0, 0xA0},
	{0xF0, 0x20},
	{0xF1, 0x74},
	{0xF0, 0xA1},
	{0xF0, 0x21},
	{0xF1, 0x70},
	{0xF0, 0xA2},
	{0xF0, 0x22},
	{0xF1, 0x6C},
	{0xF0, 0xA3},
	{0xF0, 0x23},
	{0xF1, 0x68},
	{0xF0, 0xA4},
	{0xF0, 0x24},
	{0xF1, 0x64},
	{0xF0, 0xA5},
	{0xF0, 0x25},
	{0xF1, 0x60},
	{0xF0, 0xA6},
	{0xF0, 0x26},
	{0xF1, 0x5C},
	{0xF0, 0xA7},
	{0xF0, 0x27},
	{0xF1, 0x58},
	{0xF0, 0xA8},
	{0xF0, 0x28},
	{0xF1, 0x54},
	{0xF0, 0xA9},
	{0xF0, 0x29},
	{0xF1, 0x50},
	{0xF0, 0xAA},
	{0xF0, 0x2A},
	{0xF1, 0x4C},
	{0xF0, 0xAB},
	{0xF0, 0x2B},
	{0xF1, 0x48},
	{0xF0, 0xAC},
	{0xF0, 0x2C},
	{0xF1, 0x44},
	{0xF0, 0xAD},
	{0xF0, 0x2D},
	{0xF1, 0x40},
	{0xF0, 0xAE},
	{0xF0, 0x2E},
	{0xF1, 0x3C},
	{0xF0, 0xAF},
	{0xF0, 0x2F},
	{0xF1, 0x38},
	{0xF0, 0xB0},
	{0xF0, 0x30},
	{0xF1, 0x34},
	{0xF0, 0xB1},
	{0xF0, 0x31},
	{0xF1, 0x30},
	{0xF0, 0xB2},
	{0xF0, 0x32},
	{0xF1, 0x2C},
	{0xF0, 0xB3},
	{0xF0, 0x33},
	{0xF1, 0x28},
	{0xF0, 0xB4},
	{0xF0, 0x34},
	{0xF1, 0x24},
	{0xF0, 0xB5},
	{0xF0, 0x35},
	{0xF1, 0x20},
	{0xF0, 0xB6},
	{0xF0, 0x36},
	{0xF1, 0x1C},
	{0xF0, 0xB7},
	{0xF0, 0x37},
	{0xF1, 0x18},
	{0xF0, 0xB8},
	{0xF0, 0x38},
	{0xF1, 0x14},
	{0xF0, 0xB9},
	{0xF0, 0x39},
	{0xF1, 0x10},
	{0xF0, 0xBA},
	{0xF0, 0x3A},
	{0xF1, 0x0C},
	{0xF0, 0xBB},
	{0xF0, 0x3B},
	{0xF1, 0x08},
	{0xF0, 0x00},
	{0xF0, 0x3C},
	{0xF1, 0x04},
	{0xF0, 0xBD},
	{0xF0, 0x3D},
	{0xF1, 0x00},
	{0xF0, 0xBE},
	{0xF0, 0x3E},
	{0xF1, 0x00},
	{0xF0, 0xBF},
	{0xF0, 0x3F},
	{0xF1, 0x00},
	{0xF0, 0xC0},
	{0xF0, 0x00},
};

#define CB_VT3253B0_INIT_FOR_RFMD 256
static const unsigned char vt3253b0_rfmd[CB_VT3253B0_INIT_FOR_RFMD][2] = {
	{0x00, 0x31},
	{0x01, 0x00},
	{0x02, 0x00},
	{0x03, 0x00},
	{0x04, 0x00},
	{0x05, 0x81},
	{0x06, 0x00},
	{0x07, 0x00},
	{0x08, 0x38},
	{0x09, 0x45},
	{0x0a, 0x2a},
	{0x0b, 0x76},
	{0x0c, 0x00},
	{0x0d, 0x00},
	{0x0e, 0x80},
	{0x0f, 0x00},
	{0x10, 0x00},
	{0x11, 0x00},
	{0x12, 0x00},
	{0x13, 0x00},
	{0x14, 0x00},
	{0x15, 0x00},
	{0x16, 0x00},
	{0x17, 0x00},
	{0x18, 0x00},
	{0x19, 0x00},
	{0x1a, 0x00},
	{0x1b, 0x8e},
	{0x1c, 0x06},
	{0x1d, 0x00},
	{0x1e, 0x00},
	{0x1f, 0x00},
	{0x20, 0x00},
	{0x21, 0x00},
	{0x22, 0x00},
	{0x23, 0x00},
	{0x24, 0x00},
	{0x25, 0x4a},
	{0x26, 0x00},
	{0x27, 0x00},
	{0x28, 0x00},
	{0x29, 0x00},
	{0x2a, 0x00},
	{0x2b, 0x00},
	{0x2c, 0x00},
	{0x2d, 0x34},
	{0x2e, 0x18},
	{0x2f, 0x0c},
	{0x30, 0x26},
	{0x31, 0x5b},
	{0x32, 0x00},
	{0x33, 0x00},
	{0x34, 0x00},
	{0x35, 0x00},
	{0x36, 0xaa},
	{0x37, 0xaa},
	{0x38, 0xff},
	{0x39, 0xff},
	{0x3a, 0xf8},
	{0x3b, 0x00},
	{0x3c, 0x00},
	{0x3d, 0x09},
	{0x3e, 0x0d},
	{0x3f, 0x04},
	{0x40, 0x00},
	{0x41, 0x08},
	{0x42, 0x00},
	{0x43, 0x08},
	{0x44, 0x08},
	{0x45, 0x14},
	{0x46, 0x05},
	{0x47, 0x08},
	{0x48, 0x00},
	{0x49, 0x00},
	{0x4a, 0x00},
	{0x4b, 0x00},
	{0x4c, 0x09},
	{0x4d, 0x80},
	{0x4e, 0x00},
	{0x4f, 0xc5},
	{0x50, 0x14},
	{0x51, 0x19},
	{0x52, 0x00},
	{0x53, 0x00},
	{0x54, 0x00},
	{0x55, 0x00},
	{0x56, 0x00},
	{0x57, 0x00},
	{0x58, 0x00},
	{0x59, 0xb0},
	{0x5a, 0x00},
	{0x5b, 0x00},
	{0x5c, 0x00},
	{0x5d, 0x00},
	{0x5e, 0x00},
	{0x5f, 0x00},
	{0x60, 0x39},
	{0x61, 0x83},
	{0x62, 0x00},
	{0x63, 0x00},
	{0x64, 0x00},
	{0x65, 0x00},
	{0x66, 0xc0},
	{0x67, 0x49},
	{0x68, 0x00},
	{0x69, 0x00},
	{0x6a, 0x00},
	{0x6b, 0x00},
	{0x6c, 0x00},
	{0x6d, 0x03},
	{0x6e, 0x01},
	{0x6f, 0x00},
	{0x70, 0x00},
	{0x71, 0x00},
	{0x72, 0x00},
	{0x73, 0x00},
	{0x74, 0x00},
	{0x75, 0x00},
	{0x76, 0x00},
	{0x77, 0x00},
	{0x78, 0x00},
	{0x79, 0x00},
	{0x7a, 0x00},
	{0x7b, 0x00},
	{0x7c, 0x00},
	{0x7d, 0x00},
	{0x7e, 0x00},
	{0x7f, 0x00},
	{0x80, 0x89},
	{0x81, 0x00},
	{0x82, 0x0e},
	{0x83, 0x00},
	{0x84, 0x00},
	{0x85, 0x00},
	{0x86, 0x00},
	{0x87, 0x00},
	{0x88, 0x08},
	{0x89, 0x00},
	{0x8a, 0x0e},
	{0x8b, 0xa7},
	{0x8c, 0x88},
	{0x8d, 0x47},
	{0x8e, 0xaa},
	{0x8f, 0x02},
	{0x90, 0x23},
	{0x91, 0x0c},
	{0x92, 0x06},
	{0x93, 0x08},
	{0x94, 0x00},
	{0x95, 0x00},
	{0x96, 0x00},
	{0x97, 0xeb},
	{0x98, 0x00},
	{0x99, 0x00},
	{0x9a, 0x00},
	{0x9b, 0x00},
	{0x9c, 0x00},
	{0x9d, 0x00},
	{0x9e, 0x00},
	{0x9f, 0x00},
	{0xa0, 0x00},
	{0xa1, 0x00},
	{0xa2, 0x00},
	{0xa3, 0xcd},
	{0xa4, 0x07},
	{0xa5, 0x33},
	{0xa6, 0x18},
	{0xa7, 0x00},
	{0xa8, 0x18},
	{0xa9, 0x00},
	{0xaa, 0x28},
	{0xab, 0x00},
	{0xac, 0x00},
	{0xad, 0x00},
	{0xae, 0x00},
	{0xaf, 0x18},
	{0xb0, 0x38},
	{0xb1, 0x30},
	{0xb2, 0x00},
	{0xb3, 0x00},
	{0xb4, 0x00},
	{0xb5, 0x00},
	{0xb6, 0x84},
	{0xb7, 0xfd},
	{0xb8, 0x00},
	{0xb9, 0x00},
	{0xba, 0x00},
	{0xbb, 0x03},
	{0xbc, 0x00},
	{0xbd, 0x00},
	{0xbe, 0x00},
	{0xbf, 0x00},
	{0xc0, 0x10},
	{0xc1, 0x20},
	{0xc2, 0x18},
	{0xc3, 0x20},
	{0xc4, 0x10},
	{0xc5, 0x2c},
	{0xc6, 0x1e},
	{0xc7, 0x10},
	{0xc8, 0x12},
	{0xc9, 0x01},
	{0xca, 0x6f},
	{0xcb, 0xa7},
	{0xcc, 0x3c},
	{0xcd, 0x10},
	{0xce, 0x00},
	{0xcf, 0x22},
	{0xd0, 0x00},
	{0xd1, 0x10},
	{0xd2, 0x00},
	{0xd3, 0x00},
	{0xd4, 0x10},
	{0xd5, 0x33},
	{0xd6, 0x80},
	{0xd7, 0x21},
	{0xd8, 0x00},
	{0xd9, 0x00},
	{0xda, 0x00},
	{0xdb, 0x00},
	{0xdc, 0x00},
	{0xdd, 0x00},
	{0xde, 0x00},
	{0xdf, 0x00},
	{0xe0, 0x00},
	{0xe1, 0xB3},
	{0xe2, 0x00},
	{0xe3, 0x00},
	{0xe4, 0x00},
	{0xe5, 0x10},
	{0xe6, 0x00},
	{0xe7, 0x18},
	{0xe8, 0x08},
	{0xe9, 0xd4},
	{0xea, 0x00},
	{0xeb, 0xff},
	{0xec, 0x79},
	{0xed, 0x10},
	{0xee, 0x30},
	{0xef, 0x02},
	{0xf0, 0x00},
	{0xf1, 0x09},
	{0xf2, 0x00},
	{0xf3, 0x00},
	{0xf4, 0x00},
	{0xf5, 0x00},
	{0xf6, 0x00},
	{0xf7, 0x00},
	{0xf8, 0x00},
	{0xf9, 0x00},
	{0xfa, 0x00},
	{0xfb, 0x00},
	{0xfc, 0x00},
	{0xfd, 0x00},
	{0xfe, 0x00},
	{0xff, 0x00},
};

#define CB_VT3253B0_AGC_FOR_RFMD2959 195
/* For RFMD2959 */
static
unsigned char vt3253b0_agc4_rfmd2959[CB_VT3253B0_AGC_FOR_RFMD2959][2] = {
	{0xF0, 0x00},
	{0xF1, 0x3E},
	{0xF0, 0x80},
	{0xF0, 0x00},
	{0xF1, 0x3E},
	{0xF0, 0x81},
	{0xF0, 0x01},
	{0xF1, 0x3E},
	{0xF0, 0x82},
	{0xF0, 0x02},
	{0xF1, 0x3E},
	{0xF0, 0x83},
	{0xF0, 0x03},
	{0xF1, 0x3B},
	{0xF0, 0x84},
	{0xF0, 0x04},
	{0xF1, 0x39},
	{0xF0, 0x85},
	{0xF0, 0x05},
	{0xF1, 0x38},
	{0xF0, 0x86},
	{0xF0, 0x06},
	{0xF1, 0x37},
	{0xF0, 0x87},
	{0xF0, 0x07},
	{0xF1, 0x36},
	{0xF0, 0x88},
	{0xF0, 0x08},
	{0xF1, 0x35},
	{0xF0, 0x89},
	{0xF0, 0x09},
	{0xF1, 0x35},
	{0xF0, 0x8A},
	{0xF0, 0x0A},
	{0xF1, 0x34},
	{0xF0, 0x8B},
	{0xF0, 0x0B},
	{0xF1, 0x34},
	{0xF0, 0x8C},
	{0xF0, 0x0C},
	{0xF1, 0x33},
	{0xF0, 0x8D},
	{0xF0, 0x0D},
	{0xF1, 0x32},
	{0xF0, 0x8E},
	{0xF0, 0x0E},
	{0xF1, 0x31},
	{0xF0, 0x8F},
	{0xF0, 0x0F},
	{0xF1, 0x30},
	{0xF0, 0x90},
	{0xF0, 0x10},
	{0xF1, 0x2F},
	{0xF0, 0x91},
	{0xF0, 0x11},
	{0xF1, 0x2F},
	{0xF0, 0x92},
	{0xF0, 0x12},
	{0xF1, 0x2E},
	{0xF0, 0x93},
	{0xF0, 0x13},
	{0xF1, 0x2D},
	{0xF0, 0x94},
	{0xF0, 0x14},
	{0xF1, 0x2C},
	{0xF0, 0x95},
	{0xF0, 0x15},
	{0xF1, 0x2B},
	{0xF0, 0x96},
	{0xF0, 0x16},
	{0xF1, 0x2B},
	{0xF0, 0x97},
	{0xF0, 0x17},
	{0xF1, 0x2A},
	{0xF0, 0x98},
	{0xF0, 0x18},
	{0xF1, 0x29},
	{0xF0, 0x99},
	{0xF0, 0x19},
	{0xF1, 0x28},
	{0xF0, 0x9A},
	{0xF0, 0x1A},
	{0xF1, 0x27},
	{0xF0, 0x9B},
	{0xF0, 0x1B},
	{0xF1, 0x26},
	{0xF0, 0x9C},
	{0xF0, 0x1C},
	{0xF1, 0x25},
	{0xF0, 0x9D},
	{0xF0, 0x1D},
	{0xF1, 0x24},
	{0xF0, 0x9E},
	{0xF0, 0x1E},
	{0xF1, 0x24},
	{0xF0, 0x9F},
	{0xF0, 0x1F},
	{0xF1, 0x23},
	{0xF0, 0xA0},
	{0xF0, 0x20},
	{0xF1, 0x22},
	{0xF0, 0xA1},
	{0xF0, 0x21},
	{0xF1, 0x21},
	{0xF0, 0xA2},
	{0xF0, 0x22},
	{0xF1, 0x20},
	{0xF0, 0xA3},
	{0xF0, 0x23},
	{0xF1, 0x20},
	{0xF0, 0xA4},
	{0xF0, 0x24},
	{0xF1, 0x1F},
	{0xF0, 0xA5},
	{0xF0, 0x25},
	{0xF1, 0x1E},
	{0xF0, 0xA6},
	{0xF0, 0x26},
	{0xF1, 0x1D},
	{0xF0, 0xA7},
	{0xF0, 0x27},
	{0xF1, 0x1C},
	{0xF0, 0xA8},
	{0xF0, 0x28},
	{0xF1, 0x1B},
	{0xF0, 0xA9},
	{0xF0, 0x29},
	{0xF1, 0x1B},
	{0xF0, 0xAA},
	{0xF0, 0x2A},
	{0xF1, 0x1A},
	{0xF0, 0xAB},
	{0xF0, 0x2B},
	{0xF1, 0x1A},
	{0xF0, 0xAC},
	{0xF0, 0x2C},
	{0xF1, 0x19},
	{0xF0, 0xAD},
	{0xF0, 0x2D},
	{0xF1, 0x18},
	{0xF0, 0xAE},
	{0xF0, 0x2E},
	{0xF1, 0x17},
	{0xF0, 0xAF},
	{0xF0, 0x2F},
	{0xF1, 0x16},
	{0xF0, 0xB0},
	{0xF0, 0x30},
	{0xF1, 0x15},
	{0xF0, 0xB1},
	{0xF0, 0x31},
	{0xF1, 0x15},
	{0xF0, 0xB2},
	{0xF0, 0x32},
	{0xF1, 0x15},
	{0xF0, 0xB3},
	{0xF0, 0x33},
	{0xF1, 0x14},
	{0xF0, 0xB4},
	{0xF0, 0x34},
	{0xF1, 0x13},
	{0xF0, 0xB5},
	{0xF0, 0x35},
	{0xF1, 0x12},
	{0xF0, 0xB6},
	{0xF0, 0x36},
	{0xF1, 0x11},
	{0xF0, 0xB7},
	{0xF0, 0x37},
	{0xF1, 0x10},
	{0xF0, 0xB8},
	{0xF0, 0x38},
	{0xF1, 0x0F},
	{0xF0, 0xB9},
	{0xF0, 0x39},
	{0xF1, 0x0E},
	{0xF0, 0xBA},
	{0xF0, 0x3A},
	{0xF1, 0x0D},
	{0xF0, 0xBB},
	{0xF0, 0x3B},
	{0xF1, 0x0C},
	{0xF0, 0xBC},
	{0xF0, 0x3C},
	{0xF1, 0x0B},
	{0xF0, 0xBD},
	{0xF0, 0x3D},
	{0xF1, 0x0B},
	{0xF0, 0xBE},
	{0xF0, 0x3E},
	{0xF1, 0x0A},
	{0xF0, 0xBF},
	{0xF0, 0x3F},
	{0xF1, 0x09},
	{0xF0, 0x00},
};

#define CB_VT3253B0_INIT_FOR_AIROHA2230 256
/* For AIROHA */
static
unsigned char vt3253b0_airoha2230[CB_VT3253B0_INIT_FOR_AIROHA2230][2] = {
	{0x00, 0x31},
	{0x01, 0x00},
	{0x02, 0x00},
	{0x03, 0x00},
	{0x04, 0x00},
	{0x05, 0x80},
	{0x06, 0x00},
	{0x07, 0x00},
	{0x08, 0x70},
	{0x09, 0x41},
	{0x0a, 0x2A},
	{0x0b, 0x76},
	{0x0c, 0x00},
	{0x0d, 0x00},
	{0x0e, 0x80},
	{0x0f, 0x00},
	{0x10, 0x00},
	{0x11, 0x00},
	{0x12, 0x00},
	{0x13, 0x00},
	{0x14, 0x00},
	{0x15, 0x00},
	{0x16, 0x00},
	{0x17, 0x00},
	{0x18, 0x00},
	{0x19, 0x00},
	{0x1a, 0x00},
	{0x1b, 0x8f},
	{0x1c, 0x09},
	{0x1d, 0x00},
	{0x1e, 0x00},
	{0x1f, 0x00},
	{0x20, 0x00},
	{0x21, 0x00},
	{0x22, 0x00},
	{0x23, 0x00},
	{0x24, 0x00},
	{0x25, 0x4a},
	{0x26, 0x00},
	{0x27, 0x00},
	{0x28, 0x00},
	{0x29, 0x00},
	{0x2a, 0x00},
	{0x2b, 0x00},
	{0x2c, 0x00},
	{0x2d, 0x4a},
	{0x2e, 0x00},
	{0x2f, 0x0a},
	{0x30, 0x26},
	{0x31, 0x5b},
	{0x32, 0x00},
	{0x33, 0x00},
	{0x34, 0x00},
	{0x35, 0x00},
	{0x36, 0xaa},
	{0x37, 0xaa},
	{0x38, 0xff},
	{0x39, 0xff},
	{0x3a, 0x79},
	{0x3b, 0x00},
	{0x3c, 0x00},
	{0x3d, 0x0b},
	{0x3e, 0x48},
	{0x3f, 0x04},
	{0x40, 0x00},
	{0x41, 0x08},
	{0x42, 0x00},
	{0x43, 0x08},
	{0x44, 0x08},
	{0x45, 0x14},
	{0x46, 0x05},
	{0x47, 0x09},
	{0x48, 0x00},
	{0x49, 0x00},
	{0x4a, 0x00},
	{0x4b, 0x00},
	{0x4c, 0x09},
	{0x4d, 0x73},
	{0x4e, 0x00},
	{0x4f, 0xc5},
	{0x50, 0x15},
	{0x51, 0x19},
	{0x52, 0x00},
	{0x53, 0x00},
	{0x54, 0x00},
	{0x55, 0x00},
	{0x56, 0x00},
	{0x57, 0x00},
	{0x58, 0x00},
	{0x59, 0xb0},
	{0x5a, 0x00},
	{0x5b, 0x00},
	{0x5c, 0x00},
	{0x5d, 0x00},
	{0x5e, 0x00},
	{0x5f, 0x00},
	{0x60, 0xe4},
	{0x61, 0x80},
	{0x62, 0x00},
	{0x63, 0x00},
	{0x64, 0x00},
	{0x65, 0x00},
	{0x66, 0x98},
	{0x67, 0x0a},
	{0x68, 0x00},
	{0x69, 0x00},
	{0x6a, 0x00},
	{0x6b, 0x00},
	{0x6c, 0x00}, /* RobertYu:20050125, request by JJSue */
	{0x6d, 0x03},
	{0x6e, 0x01},
	{0x6f, 0x00},
	{0x70, 0x00},
	{0x71, 0x00},
	{0x72, 0x00},
	{0x73, 0x00},
	{0x74, 0x00},
	{0x75, 0x00},
	{0x76, 0x00},
	{0x77, 0x00},
	{0x78, 0x00},
	{0x79, 0x00},
	{0x7a, 0x00},
	{0x7b, 0x00},
	{0x7c, 0x00},
	{0x7d, 0x00},
	{0x7e, 0x00},
	{0x7f, 0x00},
	{0x80, 0x8c},
	{0x81, 0x01},
	{0x82, 0x09},
	{0x83, 0x00},
	{0x84, 0x00},
	{0x85, 0x00},
	{0x86, 0x00},
	{0x87, 0x00},
	{0x88, 0x08},
	{0x89, 0x00},
	{0x8a, 0x0f},
	{0x8b, 0xb7},
	{0x8c, 0x88},
	{0x8d, 0x47},
	{0x8e, 0xaa},
	{0x8f, 0x02},
	{0x90, 0x22},
	{0x91, 0x00},
	{0x92, 0x00},
	{0x93, 0x00},
	{0x94, 0x00},
	{0x95, 0x00},
	{0x96, 0x00},
	{0x97, 0xeb},
	{0x98, 0x00},
	{0x99, 0x00},
	{0x9a, 0x00},
	{0x9b, 0x00},
	{0x9c, 0x00},
	{0x9d, 0x00},
	{0x9e, 0x00},
	{0x9f, 0x01},
	{0xa0, 0x00},
	{0xa1, 0x00},
	{0xa2, 0x00},
	{0xa3, 0x00},
	{0xa4, 0x00},
	{0xa5, 0x00},
	{0xa6, 0x10},
	{0xa7, 0x00},
	{0xa8, 0x18},
	{0xa9, 0x00},
	{0xaa, 0x00},
	{0xab, 0x00},
	{0xac, 0x00},
	{0xad, 0x00},
	{0xae, 0x00},
	{0xaf, 0x18},
	{0xb0, 0x38},
	{0xb1, 0x30},
	{0xb2, 0x00},
	{0xb3, 0x00},
	{0xb4, 0xff},
	{0xb5, 0x0f},
	{0xb6, 0xe4},
	{0xb7, 0xe2},
	{0xb8, 0x00},
	{0xb9, 0x00},
	{0xba, 0x00},
	{0xbb, 0x03},
	{0xbc, 0x01},
	{0xbd, 0x00},
	{0xbe, 0x00},
	{0xbf, 0x00},
	{0xc0, 0x18},
	{0xc1, 0x20},
	{0xc2, 0x07},
	{0xc3, 0x18},
	{0xc4, 0xff},
	{0xc5, 0x2c},
	{0xc6, 0x0c},
	{0xc7, 0x0a},
	{0xc8, 0x0e},
	{0xc9, 0x01},
	{0xca, 0x68},
	{0xcb, 0xa7},
	{0xcc, 0x3c},
	{0xcd, 0x10},
	{0xce, 0x00},
	{0xcf, 0x25},
	{0xd0, 0x40},
	{0xd1, 0x12},
	{0xd2, 0x00},
	{0xd3, 0x00},
	{0xd4, 0x10},
	{0xd5, 0x28},
	{0xd6, 0x80},
	{0xd7, 0x2A},
	{0xd8, 0x00},
	{0xd9, 0x00},
	{0xda, 0x00},
	{0xdb, 0x00},
	{0xdc, 0x00},
	{0xdd, 0x00},
	{0xde, 0x00},
	{0xdf, 0x00},
	{0xe0, 0x00},
	{0xe1, 0xB3},
	{0xe2, 0x00},
	{0xe3, 0x00},
	{0xe4, 0x00},
	{0xe5, 0x10},
	{0xe6, 0x00},
	{0xe7, 0x1C},
	{0xe8, 0x00},
	{0xe9, 0xf4},
	{0xea, 0x00},
	{0xeb, 0xff},
	{0xec, 0x79},
	{0xed, 0x20},
	{0xee, 0x30},
	{0xef, 0x01},
	{0xf0, 0x00},
	{0xf1, 0x3e},
	{0xf2, 0x00},
	{0xf3, 0x00},
	{0xf4, 0x00},
	{0xf5, 0x00},
	{0xf6, 0x00},
	{0xf7, 0x00},
	{0xf8, 0x00},
	{0xf9, 0x00},
	{0xfa, 0x00},
	{0xfb, 0x00},
	{0xfc, 0x00},
	{0xfd, 0x00},
	{0xfe, 0x00},
	{0xff, 0x00},
};

#define CB_VT3253B0_INIT_FOR_UW2451 256
/* For UW2451 */
static unsigned char vt3253b0_uw2451[CB_VT3253B0_INIT_FOR_UW2451][2] = {
	{0x00, 0x31},
	{0x01, 0x00},
	{0x02, 0x00},
	{0x03, 0x00},
	{0x04, 0x00},
	{0x05, 0x81},
	{0x06, 0x00},
	{0x07, 0x00},
	{0x08, 0x38},
	{0x09, 0x45},
	{0x0a, 0x28},
	{0x0b, 0x76},
	{0x0c, 0x00},
	{0x0d, 0x00},
	{0x0e, 0x80},
	{0x0f, 0x00},
	{0x10, 0x00},
	{0x11, 0x00},
	{0x12, 0x00},
	{0x13, 0x00},
	{0x14, 0x00},
	{0x15, 0x00},
	{0x16, 0x00},
	{0x17, 0x00},
	{0x18, 0x00},
	{0x19, 0x00},
	{0x1a, 0x00},
	{0x1b, 0x8f},
	{0x1c, 0x0f},
	{0x1d, 0x00},
	{0x1e, 0x00},
	{0x1f, 0x00},
	{0x20, 0x00},
	{0x21, 0x00},
	{0x22, 0x00},
	{0x23, 0x00},
	{0x24, 0x00},
	{0x25, 0x4a},
	{0x26, 0x00},
	{0x27, 0x00},
	{0x28, 0x00},
	{0x29, 0x00},
	{0x2a, 0x00},
	{0x2b, 0x00},
	{0x2c, 0x00},
	{0x2d, 0x18},
	{0x2e, 0x00},
	{0x2f, 0x0a},
	{0x30, 0x26},
	{0x31, 0x5b},
	{0x32, 0x00},
	{0x33, 0x00},
	{0x34, 0x00},
	{0x35, 0x00},
	{0x36, 0xaa},
	{0x37, 0xaa},
	{0x38, 0xff},
	{0x39, 0xff},
	{0x3a, 0x00},
	{0x3b, 0x00},
	{0x3c, 0x00},
	{0x3d, 0x03},
	{0x3e, 0x1d},
	{0x3f, 0x04},
	{0x40, 0x00},
	{0x41, 0x08},
	{0x42, 0x00},
	{0x43, 0x08},
	{0x44, 0x08},
	{0x45, 0x14},
	{0x46, 0x05},
	{0x47, 0x09},
	{0x48, 0x00},
	{0x49, 0x00},
	{0x4a, 0x00},
	{0x4b, 0x00},
	{0x4c, 0x09},
	{0x4d, 0x90},
	{0x4e, 0x00},
	{0x4f, 0xc5},
	{0x50, 0x15},
	{0x51, 0x19},
	{0x52, 0x00},
	{0x53, 0x00},
	{0x54, 0x00},
	{0x55, 0x00},
	{0x56, 0x00},
	{0x57, 0x00},
	{0x58, 0x00},
	{0x59, 0xb0},
	{0x5a, 0x00},
	{0x5b, 0x00},
	{0x5c, 0x00},
	{0x5d, 0x00},
	{0x5e, 0x00},
	{0x5f, 0x00},
	{0x60, 0xb3},
	{0x61, 0x81},
	{0x62, 0x00},
	{0x63, 0x00},
	{0x64, 0x00},
	{0x65, 0x00},
	{0x66, 0x57},
	{0x67, 0x6c},
	{0x68, 0x00},
	{0x69, 0x00},
	{0x6a, 0x00},
	{0x6b, 0x00},
	{0x6c, 0x00}, /* RobertYu:20050125, request by JJSue */
	{0x6d, 0x03},
	{0x6e, 0x01},
	{0x6f, 0x00},
	{0x70, 0x00},
	{0x71, 0x00},
	{0x72, 0x00},
	{0x73, 0x00},
	{0x74, 0x00},
	{0x75, 0x00},
	{0x76, 0x00},
	{0x77, 0x00},
	{0x78, 0x00},
	{0x79, 0x00},
	{0x7a, 0x00},
	{0x7b, 0x00},
	{0x7c, 0x00},
	{0x7d, 0x00},
	{0x7e, 0x00},
	{0x7f, 0x00},
	{0x80, 0x8c},
	{0x81, 0x00},
	{0x82, 0x0e},
	{0x83, 0x00},
	{0x84, 0x00},
	{0x85, 0x00},
	{0x86, 0x00},
	{0x87, 0x00},
	{0x88, 0x08},
	{0x89, 0x00},
	{0x8a, 0x0e},
	{0x8b, 0xa7},
	{0x8c, 0x88},
	{0x8d, 0x47},
	{0x8e, 0xaa},
	{0x8f, 0x02},
	{0x90, 0x00},
	{0x91, 0x00},
	{0x92, 0x00},
	{0x93, 0x00},
	{0x94, 0x00},
	{0x95, 0x00},
	{0x96, 0x00},
	{0x97, 0xe3},
	{0x98, 0x00},
	{0x99, 0x00},
	{0x9a, 0x00},
	{0x9b, 0x00},
	{0x9c, 0x00},
	{0x9d, 0x00},
	{0x9e, 0x00},
	{0x9f, 0x00},
	{0xa0, 0x00},
	{0xa1, 0x00},
	{0xa2, 0x00},
	{0xa3, 0x00},
	{0xa4, 0x00},
	{0xa5, 0x00},
	{0xa6, 0x10},
	{0xa7, 0x00},
	{0xa8, 0x18},
	{0xa9, 0x00},
	{0xaa, 0x00},
	{0xab, 0x00},
	{0xac, 0x00},
	{0xad, 0x00},
	{0xae, 0x00},
	{0xaf, 0x18},
	{0xb0, 0x18},
	{0xb1, 0x30},
	{0xb2, 0x00},
	{0xb3, 0x00},
	{0xb4, 0x00},
	{0xb5, 0x00},
	{0xb6, 0x00},
	{0xb7, 0x00},
	{0xb8, 0x00},
	{0xb9, 0x00},
	{0xba, 0x00},
	{0xbb, 0x03},
	{0xbc, 0x01},
	{0xbd, 0x00},
	{0xbe, 0x00},
	{0xbf, 0x00},
	{0xc0, 0x10},
	{0xc1, 0x20},
	{0xc2, 0x00},
	{0xc3, 0x20},
	{0xc4, 0x00},
	{0xc5, 0x2c},
	{0xc6, 0x1c},
	{0xc7, 0x10},
	{0xc8, 0x10},
	{0xc9, 0x01},
	{0xca, 0x68},
	{0xcb, 0xa7},
	{0xcc, 0x3c},
	{0xcd, 0x09},
	{0xce, 0x00},
	{0xcf, 0x20},
	{0xd0, 0x40},
	{0xd1, 0x10},
	{0xd2, 0x00},
	{0xd3, 0x00},
	{0xd4, 0x20},
	{0xd5, 0x28},
	{0xd6, 0xa0},
	{0xd7, 0x2a},
	{0xd8, 0x00},
	{0xd9, 0x00},
	{0xda, 0x00},
	{0xdb, 0x00},
	{0xdc, 0x00},
	{0xdd, 0x00},
	{0xde, 0x00},
	{0xdf, 0x00},
	{0xe0, 0x00},
	{0xe1, 0xd3},
	{0xe2, 0xc0},
	{0xe3, 0x00},
	{0xe4, 0x00},
	{0xe5, 0x10},
	{0xe6, 0x00},
	{0xe7, 0x12},
	{0xe8, 0x12},
	{0xe9, 0x34},
	{0xea, 0x00},
	{0xeb, 0xff},
	{0xec, 0x79},
	{0xed, 0x20},
	{0xee, 0x30},
	{0xef, 0x01},
	{0xf0, 0x00},
	{0xf1, 0x3e},
	{0xf2, 0x00},
	{0xf3, 0x00},
	{0xf4, 0x00},
	{0xf5, 0x00},
	{0xf6, 0x00},
	{0xf7, 0x00},
	{0xf8, 0x00},
	{0xf9, 0x00},
	{0xfa, 0x00},
	{0xfb, 0x00},
	{0xfc, 0x00},
	{0xfd, 0x00},
	{0xfe, 0x00},
	{0xff, 0x00},
};

#define CB_VT3253B0_AGC 193
/* For AIROHA */
static unsigned char vt3253b0_agc[CB_VT3253B0_AGC][2] = {
	{0xF0, 0x00},
	{0xF1, 0x00},
	{0xF0, 0x80},
	{0xF0, 0x01},
	{0xF1, 0x00},
	{0xF0, 0x81},
	{0xF0, 0x02},
	{0xF1, 0x02},
	{0xF0, 0x82},
	{0xF0, 0x03},
	{0xF1, 0x04},
	{0xF0, 0x83},
	{0xF0, 0x03},
	{0xF1, 0x04},
	{0xF0, 0x84},
	{0xF0, 0x04},
	{0xF1, 0x06},
	{0xF0, 0x85},
	{0xF0, 0x05},
	{0xF1, 0x06},
	{0xF0, 0x86},
	{0xF0, 0x06},
	{0xF1, 0x06},
	{0xF0, 0x87},
	{0xF0, 0x07},
	{0xF1, 0x08},
	{0xF0, 0x88},
	{0xF0, 0x08},
	{0xF1, 0x08},
	{0xF0, 0x89},
	{0xF0, 0x09},
	{0xF1, 0x0A},
	{0xF0, 0x8A},
	{0xF0, 0x0A},
	{0xF1, 0x0A},
	{0xF0, 0x8B},
	{0xF0, 0x0B},
	{0xF1, 0x0C},
	{0xF0, 0x8C},
	{0xF0, 0x0C},
	{0xF1, 0x0C},
	{0xF0, 0x8D},
	{0xF0, 0x0D},
	{0xF1, 0x0E},
	{0xF0, 0x8E},
	{0xF0, 0x0E},
	{0xF1, 0x0E},
	{0xF0, 0x8F},
	{0xF0, 0x0F},
	{0xF1, 0x10},
	{0xF0, 0x90},
	{0xF0, 0x10},
	{0xF1, 0x10},
	{0xF0, 0x91},
	{0xF0, 0x11},
	{0xF1, 0x12},
	{0xF0, 0x92},
	{0xF0, 0x12},
	{0xF1, 0x12},
	{0xF0, 0x93},
	{0xF0, 0x13},
	{0xF1, 0x14},
	{0xF0, 0x94},
	{0xF0, 0x14},
	{0xF1, 0x14},
	{0xF0, 0x95},
	{0xF0, 0x15},
	{0xF1, 0x16},
	{0xF0, 0x96},
	{0xF0, 0x16},
	{0xF1, 0x16},
	{0xF0, 0x97},
	{0xF0, 0x17},
	{0xF1, 0x18},
	{0xF0, 0x98},
	{0xF0, 0x18},
	{0xF1, 0x18},
	{0xF0, 0x99},
	{0xF0, 0x19},
	{0xF1, 0x1A},
	{0xF0, 0x9A},
	{0xF0, 0x1A},
	{0xF1, 0x1A},
	{0xF0, 0x9B},
	{0xF0, 0x1B},
	{0xF1, 0x1C},
	{0xF0, 0x9C},
	{0xF0, 0x1C},
	{0xF1, 0x1C},
	{0xF0, 0x9D},
	{0xF0, 0x1D},
	{0xF1, 0x1E},
	{0xF0, 0x9E},
	{0xF0, 0x1E},
	{0xF1, 0x1E},
	{0xF0, 0x9F},
	{0xF0, 0x1F},
	{0xF1, 0x20},
	{0xF0, 0xA0},
	{0xF0, 0x20},
	{0xF1, 0x20},
	{0xF0, 0xA1},
	{0xF0, 0x21},
	{0xF1, 0x22},
	{0xF0, 0xA2},
	{0xF0, 0x22},
	{0xF1, 0x22},
	{0xF0, 0xA3},
	{0xF0, 0x23},
	{0xF1, 0x24},
	{0xF0, 0xA4},
	{0xF0, 0x24},
	{0xF1, 0x24},
	{0xF0, 0xA5},
	{0xF0, 0x25},
	{0xF1, 0x26},
	{0xF0, 0xA6},
	{0xF0, 0x26},
	{0xF1, 0x26},
	{0xF0, 0xA7},
	{0xF0, 0x27},
	{0xF1, 0x28},
	{0xF0, 0xA8},
	{0xF0, 0x28},
	{0xF1, 0x28},
	{0xF0, 0xA9},
	{0xF0, 0x29},
	{0xF1, 0x2A},
	{0xF0, 0xAA},
	{0xF0, 0x2A},
	{0xF1, 0x2A},
	{0xF0, 0xAB},
	{0xF0, 0x2B},
	{0xF1, 0x2C},
	{0xF0, 0xAC},
	{0xF0, 0x2C},
	{0xF1, 0x2C},
	{0xF0, 0xAD},
	{0xF0, 0x2D},
	{0xF1, 0x2E},
	{0xF0, 0xAE},
	{0xF0, 0x2E},
	{0xF1, 0x2E},
	{0xF0, 0xAF},
	{0xF0, 0x2F},
	{0xF1, 0x30},
	{0xF0, 0xB0},
	{0xF0, 0x30},
	{0xF1, 0x30},
	{0xF0, 0xB1},
	{0xF0, 0x31},
	{0xF1, 0x32},
	{0xF0, 0xB2},
	{0xF0, 0x32},
	{0xF1, 0x32},
	{0xF0, 0xB3},
	{0xF0, 0x33},
	{0xF1, 0x34},
	{0xF0, 0xB4},
	{0xF0, 0x34},
	{0xF1, 0x34},
	{0xF0, 0xB5},
	{0xF0, 0x35},
	{0xF1, 0x36},
	{0xF0, 0xB6},
	{0xF0, 0x36},
	{0xF1, 0x36},
	{0xF0, 0xB7},
	{0xF0, 0x37},
	{0xF1, 0x38},
	{0xF0, 0xB8},
	{0xF0, 0x38},
	{0xF1, 0x38},
	{0xF0, 0xB9},
	{0xF0, 0x39},
	{0xF1, 0x3A},
	{0xF0, 0xBA},
	{0xF0, 0x3A},
	{0xF1, 0x3A},
	{0xF0, 0xBB},
	{0xF0, 0x3B},
	{0xF1, 0x3C},
	{0xF0, 0xBC},
	{0xF0, 0x3C},
	{0xF1, 0x3C},
	{0xF0, 0xBD},
	{0xF0, 0x3D},
	{0xF1, 0x3E},
	{0xF0, 0xBE},
	{0xF0, 0x3E},
	{0xF1, 0x3E},
	{0xF0, 0xBF},
	{0xF0, 0x00},
};

static const unsigned short awc_frame_time[MAX_RATE] = {
		10, 20, 55, 110, 24, 36, 48, 72, 96, 144, 192, 216
};

/*---------------------  Export Variables  --------------------------*/
/*
 * Description: Calculate data frame transmitting time
 *
 * Parameters:
 *  In:
 *      preamble_type     - Preamble Type
 *      by_pkt_type        - PK_TYPE_11A, PK_TYPE_11B, PK_TYPE_11GB, PK_TYPE_11GA
 *      cb_frame_length   - Baseband Type
 *      tx_rate           - Tx Rate
 *  Out:
 *
 * Return Value: FrameTime
 *
 */
unsigned int bb_get_frame_time(unsigned char preamble_type,
			       unsigned char by_pkt_type,
			       unsigned int cb_frame_length,
			       unsigned short tx_rate)
{
	unsigned int frame_time;
	unsigned int preamble;
	unsigned int tmp;
	unsigned int rate_idx = (unsigned int)tx_rate;
	unsigned int rate = 0;

	if (rate_idx > RATE_54M)
		return 0;

	rate = (unsigned int)awc_frame_time[rate_idx];

	if (rate_idx <= 3) {		    /* CCK mode */
		if (preamble_type == PREAMBLE_SHORT)
			preamble = 96;
		else
			preamble = 192;
		frame_time = (cb_frame_length * 80) / rate;  /* ????? */
		tmp = (frame_time * rate) / 80;
		if (cb_frame_length != tmp)
			frame_time++;

		return preamble + frame_time;
	}
	frame_time = (cb_frame_length * 8 + 22) / rate; /* ???????? */
	tmp = ((frame_time * rate) - 22) / 8;
	if (cb_frame_length != tmp)
		frame_time++;

	frame_time = frame_time * 4;    /* ??????? */
	if (by_pkt_type != PK_TYPE_11A)
		frame_time += 6;     /* ?????? */

	return 20 + frame_time; /* ?????? */
}

/*
 * Description: Calculate Length, Service, and Signal fields of Phy for Tx
 *
 * Parameters:
 *  In:
 *      priv         - Device Structure
 *      frame_length   - Tx Frame Length
 *      tx_rate           - Tx Rate
 *  Out:
 *	struct vnt_phy_field *phy
 *		- pointer to Phy Length field
 *		- pointer to Phy Service field
 *		- pointer to Phy Signal field
 *
 * Return Value: none
 *
 */
void vnt_get_phy_field(struct vnt_private *priv, u32 frame_length,
		       u16 tx_rate, u8 pkt_type, struct vnt_phy_field *phy)
{
	u32 bit_count;
	u32 count = 0;
	u32 tmp;
	int ext_bit;
	u8 preamble_type = priv->preamble_type;

	bit_count = frame_length * 8;
	ext_bit = false;

	switch (tx_rate) {
	case RATE_1M:
		count = bit_count;

		phy->signal = 0x00;

		break;
	case RATE_2M:
		count = bit_count / 2;

		if (preamble_type == PREAMBLE_SHORT)
			phy->signal = 0x09;
		else
			phy->signal = 0x01;

		break;
	case RATE_5M:
		count = (bit_count * 10) / 55;
		tmp = (count * 55) / 10;

		if (tmp != bit_count)
			count++;

		if (preamble_type == PREAMBLE_SHORT)
			phy->signal = 0x0a;
		else
			phy->signal = 0x02;

		break;
	case RATE_11M:
		count = bit_count / 11;
		tmp = count * 11;

		if (tmp != bit_count) {
			count++;

			if ((bit_count - tmp) <= 3)
				ext_bit = true;
		}

		if (preamble_type == PREAMBLE_SHORT)
			phy->signal = 0x0b;
		else
			phy->signal = 0x03;

		break;
	case RATE_6M:
		if (pkt_type == PK_TYPE_11A)
			phy->signal = 0x9b;
		else
			phy->signal = 0x8b;

		break;
	case RATE_9M:
		if (pkt_type == PK_TYPE_11A)
			phy->signal = 0x9f;
		else
			phy->signal = 0x8f;

		break;
	case RATE_12M:
		if (pkt_type == PK_TYPE_11A)
			phy->signal = 0x9a;
		else
			phy->signal = 0x8a;

		break;
	case RATE_18M:
		if (pkt_type == PK_TYPE_11A)
			phy->signal = 0x9e;
		else
			phy->signal = 0x8e;

		break;
	case RATE_24M:
		if (pkt_type == PK_TYPE_11A)
			phy->signal = 0x99;
		else
			phy->signal = 0x89;

		break;
	case RATE_36M:
		if (pkt_type == PK_TYPE_11A)
			phy->signal = 0x9d;
		else
			phy->signal = 0x8d;

		break;
	case RATE_48M:
		if (pkt_type == PK_TYPE_11A)
			phy->signal = 0x98;
		else
			phy->signal = 0x88;

		break;
	case RATE_54M:
		if (pkt_type == PK_TYPE_11A)
			phy->signal = 0x9c;
		else
			phy->signal = 0x8c;
		break;
	default:
		if (pkt_type == PK_TYPE_11A)
			phy->signal = 0x9c;
		else
			phy->signal = 0x8c;
		break;
	}

	if (pkt_type == PK_TYPE_11B) {
		phy->service = 0x00;
		if (ext_bit)
			phy->service |= 0x80;
		phy->len = cpu_to_le16((u16)count);
	} else {
		phy->service = 0x00;
		phy->len = cpu_to_le16((u16)frame_length);
	}
}

/*
 * Description: Read a byte from BASEBAND, by embedded programming
 *
 * Parameters:
 *  In:
 *      iobase      - I/O base address
 *      by_bb_addr  - address of register in Baseband
 *  Out:
 *      pby_data    - data read
 *
 * Return Value: true if succeeded; false if failed.
 *
 */
bool bb_read_embedded(struct vnt_private *priv, unsigned char by_bb_addr,
		      unsigned char *pby_data)
{
	void __iomem *iobase = priv->port_offset;
	unsigned short ww;
	unsigned char by_value;

	/* BB reg offset */
	iowrite8(by_bb_addr, iobase + MAC_REG_BBREGADR);

	/* turn on REGR */
	vt6655_mac_reg_bits_on(iobase, MAC_REG_BBREGCTL, BBREGCTL_REGR);
	/* W_MAX_TIMEOUT is the timeout period */
	for (ww = 0; ww < W_MAX_TIMEOUT; ww++) {
		by_value = ioread8(iobase + MAC_REG_BBREGCTL);
		if (by_value & BBREGCTL_DONE)
			break;
	}

	/* get BB data */
	*pby_data = ioread8(iobase + MAC_REG_BBREGDATA);

	if (ww == W_MAX_TIMEOUT) {
		pr_debug(" DBG_PORT80(0x30)\n");
		return false;
	}
	return true;
}

/*
 * Description: Write a Byte to BASEBAND, by embedded programming
 *
 * Parameters:
 *  In:
 *      iobase      - I/O base address
 *      by_bb_addr  - address of register in Baseband
 *      by_data     - data to write
 *  Out:
 *      none
 *
 * Return Value: true if succeeded; false if failed.
 *
 */
bool bb_write_embedded(struct vnt_private *priv, unsigned char by_bb_addr,
		       unsigned char by_data)
{
	void __iomem *iobase = priv->port_offset;
	unsigned short ww;
	unsigned char by_value;

	/* BB reg offset */
	iowrite8(by_bb_addr, iobase + MAC_REG_BBREGADR);
	/* set BB data */
	iowrite8(by_data, iobase + MAC_REG_BBREGDATA);

	/* turn on BBREGCTL_REGW */
	vt6655_mac_reg_bits_on(iobase, MAC_REG_BBREGCTL, BBREGCTL_REGW);
	/* W_MAX_TIMEOUT is the timeout period */
	for (ww = 0; ww < W_MAX_TIMEOUT; ww++) {
		by_value = ioread8(iobase + MAC_REG_BBREGCTL);
		if (by_value & BBREGCTL_DONE)
			break;
	}

	if (ww == W_MAX_TIMEOUT) {
		pr_debug(" DBG_PORT80(0x31)\n");
		return false;
	}
	return true;
}

/*
 * Description: VIA VT3253 Baseband chip init function
 *
 * Parameters:
 *  In:
 *      iobase      - I/O base address
 *      byRevId     - Revision ID
 *      rf_type     - RF type
 *  Out:
 *      none
 *
 * Return Value: true if succeeded; false if failed.
 *
 */

bool bb_vt3253_init(struct vnt_private *priv)
{
	bool result = true;
	int        ii;
	void __iomem *iobase = priv->port_offset;
	unsigned char rf_type = priv->rf_type;
	unsigned char by_local_id = priv->local_id;

	if (rf_type == RF_RFMD2959) {
		if (by_local_id <= REV_ID_VT3253_A1) {
			for (ii = 0; ii < CB_VT3253_INIT_FOR_RFMD; ii++)
				result &= bb_write_embedded(priv,
					by_vt3253_init_tab_rfmd[ii][0],
					by_vt3253_init_tab_rfmd[ii][1]);

		} else {
			for (ii = 0; ii < CB_VT3253B0_INIT_FOR_RFMD; ii++)
				result &= bb_write_embedded(priv,
					vt3253b0_rfmd[ii][0],
					vt3253b0_rfmd[ii][1]);

			for (ii = 0; ii < CB_VT3253B0_AGC_FOR_RFMD2959; ii++)
				result &= bb_write_embedded(priv,
					vt3253b0_agc4_rfmd2959[ii][0],
					vt3253b0_agc4_rfmd2959[ii][1]);

			iowrite32(0x23, iobase + MAC_REG_ITRTMSET);
			vt6655_mac_reg_bits_on(iobase, MAC_REG_PAPEDELAY, BIT(0));
		}
		priv->bbvga[0] = 0x18;
		priv->bbvga[1] = 0x0A;
		priv->bbvga[2] = 0x0;
		priv->bbvga[3] = 0x0;
		priv->dbm_threshold[0] = -70;
		priv->dbm_threshold[1] = -50;
		priv->dbm_threshold[2] = 0;
		priv->dbm_threshold[3] = 0;
	} else if ((rf_type == RF_AIROHA) || (rf_type == RF_AL2230S)) {
		for (ii = 0; ii < CB_VT3253B0_INIT_FOR_AIROHA2230; ii++)
			result &= bb_write_embedded(priv,
				vt3253b0_airoha2230[ii][0],
				vt3253b0_airoha2230[ii][1]);

		for (ii = 0; ii < CB_VT3253B0_AGC; ii++)
			result &= bb_write_embedded(priv,
				vt3253b0_agc[ii][0], vt3253b0_agc[ii][1]);

		priv->bbvga[0] = 0x1C;
		priv->bbvga[1] = 0x10;
		priv->bbvga[2] = 0x0;
		priv->bbvga[3] = 0x0;
		priv->dbm_threshold[0] = -70;
		priv->dbm_threshold[1] = -48;
		priv->dbm_threshold[2] = 0;
		priv->dbm_threshold[3] = 0;
	} else if (rf_type == RF_UW2451) {
		for (ii = 0; ii < CB_VT3253B0_INIT_FOR_UW2451; ii++)
			result &= bb_write_embedded(priv,
				vt3253b0_uw2451[ii][0],
				vt3253b0_uw2451[ii][1]);

		for (ii = 0; ii < CB_VT3253B0_AGC; ii++)
			result &= bb_write_embedded(priv,
				vt3253b0_agc[ii][0],
				vt3253b0_agc[ii][1]);

		iowrite8(0x23, iobase + MAC_REG_ITRTMSET);
		vt6655_mac_reg_bits_on(iobase, MAC_REG_PAPEDELAY, BIT(0));

		priv->bbvga[0] = 0x14;
		priv->bbvga[1] = 0x0A;
		priv->bbvga[2] = 0x0;
		priv->bbvga[3] = 0x0;
		priv->dbm_threshold[0] = -60;
		priv->dbm_threshold[1] = -50;
		priv->dbm_threshold[2] = 0;
		priv->dbm_threshold[3] = 0;
	} else if (rf_type == RF_VT3226) {
		for (ii = 0; ii < CB_VT3253B0_INIT_FOR_AIROHA2230; ii++)
			result &= bb_write_embedded(priv,
				vt3253b0_airoha2230[ii][0],
				vt3253b0_airoha2230[ii][1]);

		for (ii = 0; ii < CB_VT3253B0_AGC; ii++)
			result &= bb_write_embedded(priv,
				vt3253b0_agc[ii][0], vt3253b0_agc[ii][1]);

		priv->bbvga[0] = 0x1C;
		priv->bbvga[1] = 0x10;
		priv->bbvga[2] = 0x0;
		priv->bbvga[3] = 0x0;
		priv->dbm_threshold[0] = -70;
		priv->dbm_threshold[1] = -48;
		priv->dbm_threshold[2] = 0;
		priv->dbm_threshold[3] = 0;
		/* Fix VT3226 DFC system timing issue */
		vt6655_mac_word_reg_bits_on(iobase, MAC_REG_SOFTPWRCTL, SOFTPWRCTL_RFLEOPT);
		/* {{ RobertYu: 20050104 */
	} else {
		/* No VGA Table now */
		priv->update_bbvga = false;
		priv->bbvga[0] = 0x1C;
	}

	if (by_local_id > REV_ID_VT3253_A1) {
		bb_write_embedded(priv, 0x04, 0x7F);
		bb_write_embedded(priv, 0x0D, 0x01);
	}

	return result;
}

/*
 * Description: Set ShortSlotTime mode
 *
 * Parameters:
 *  In:
 *      priv     - Device Structure
 *  Out:
 *      none
 *
 * Return Value: none
 *
 */
void
bb_set_short_slot_time(struct vnt_private *priv)
{
	unsigned char by_bb_rx_conf = 0;
	unsigned char by_bb_vga = 0;

	bb_read_embedded(priv, 0x0A, &by_bb_rx_conf); /* CR10 */

	if (priv->short_slot_time)
		by_bb_rx_conf &= 0xDF; /* 1101 1111 */
	else
		by_bb_rx_conf |= 0x20; /* 0010 0000 */

	/* patch for 3253B0 Baseband with Cardbus module */
	bb_read_embedded(priv, 0xE7, &by_bb_vga);
	if (by_bb_vga == priv->bbvga[0])
		by_bb_rx_conf |= 0x20; /* 0010 0000 */

	bb_write_embedded(priv, 0x0A, by_bb_rx_conf); /* CR10 */
}

void bb_set_vga_gain_offset(struct vnt_private *priv, unsigned char by_data)
{
	unsigned char by_bb_rx_conf = 0;

	bb_write_embedded(priv, 0xE7, by_data);

	bb_read_embedded(priv, 0x0A, &by_bb_rx_conf); /* CR10 */
	/* patch for 3253B0 Baseband with Cardbus module */
	if (by_data == priv->bbvga[0])
		by_bb_rx_conf |= 0x20; /* 0010 0000 */
	else if (priv->short_slot_time)
		by_bb_rx_conf &= 0xDF; /* 1101 1111 */
	else
		by_bb_rx_conf |= 0x20; /* 0010 0000 */
	priv->bbvga_current = by_data;
	bb_write_embedded(priv, 0x0A, by_bb_rx_conf); /* CR10 */
}

/*
 * Description: Baseband SoftwareReset
 *
 * Parameters:
 *  In:
 *      iobase      - I/O base address
 *  Out:
 *      none
 *
 * Return Value: none
 *
 */
void
bb_software_reset(struct vnt_private *priv)
{
	bb_write_embedded(priv, 0x50, 0x40);
	bb_write_embedded(priv, 0x50, 0);
	bb_write_embedded(priv, 0x9C, 0x01);
	bb_write_embedded(priv, 0x9C, 0);
}

/*
 * Description: Set Tx Antenna mode
 *
 * Parameters:
 *  In:
 *      priv          - Device Structure
 *      by_antenna_mode    - Antenna Mode
 *  Out:
 *      none
 *
 * Return Value: none
 *
 */

void
bb_set_tx_antenna_mode(struct vnt_private *priv, unsigned char by_antenna_mode)
{
	unsigned char by_bb_tx_conf;

	bb_read_embedded(priv, 0x09, &by_bb_tx_conf); /* CR09 */
	if (by_antenna_mode == ANT_DIVERSITY) {
		/* bit 1 is diversity */
		by_bb_tx_conf |= 0x02;
	} else if (by_antenna_mode == ANT_A) {
		/* bit 2 is ANTSEL */
		by_bb_tx_conf &= 0xF9; /* 1111 1001 */
	} else if (by_antenna_mode == ANT_B) {
		by_bb_tx_conf &= 0xFD; /* 1111 1101 */
		by_bb_tx_conf |= 0x04;
	}
	bb_write_embedded(priv, 0x09, by_bb_tx_conf); /* CR09 */
}

/*
 * Description: Set Rx Antenna mode
 *
 * Parameters:
 *  In:
 *      priv          - Device Structure
 *      by_antenna_mode   - Antenna Mode
 *  Out:
 *      none
 *
 * Return Value: none
 *
 */

void
bb_set_rx_antenna_mode(struct vnt_private *priv, unsigned char by_antenna_mode)
{
	unsigned char by_bb_rx_conf;

	bb_read_embedded(priv, 0x0A, &by_bb_rx_conf); /* CR10 */
	if (by_antenna_mode == ANT_DIVERSITY) {
		by_bb_rx_conf |= 0x01;

	} else if (by_antenna_mode == ANT_A) {
		by_bb_rx_conf &= 0xFC; /* 1111 1100 */
	} else if (by_antenna_mode == ANT_B) {
		by_bb_rx_conf &= 0xFE; /* 1111 1110 */
		by_bb_rx_conf |= 0x02;
	}
	bb_write_embedded(priv, 0x0A, by_bb_rx_conf); /* CR10 */
}

/*
 * Description: bb_set_deep_sleep
 *
 * Parameters:
 *  In:
 *      priv          - Device Structure
 *  Out:
 *      none
 *
 * Return Value: none
 *
 */
void
bb_set_deep_sleep(struct vnt_private *priv, unsigned char by_local_id)
{
	bb_write_embedded(priv, 0x0C, 0x17); /* CR12 */
	bb_write_embedded(priv, 0x0D, 0xB9); /* CR13 */
}

