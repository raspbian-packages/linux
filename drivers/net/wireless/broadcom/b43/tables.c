// SPDX-License-Identifier: GPL-2.0-or-later
/*

  Broadcom B43 wireless driver

  Copyright (c) 2005 Martin Langer <martin-langer@gmx.de>,
  Copyright (c) 2005-2007 Stefano Brivio <stefano.brivio@polimi.it>
  Copyright (c) 2006, 2006 Michael Buesch <m@bues.ch>
  Copyright (c) 2005 Danny van Dyk <kugelfang@gentoo.org>
  Copyright (c) 2005 Andreas Jaggi <andreas.jaggi@waterwave.ch>


*/

#include "b43.h"
#include "tables.h"
#include "phy_g.h"


const u32 b43_tab_rotor[] = {
	0xFEB93FFD, 0xFEC63FFD,	/* 0 */
	0xFED23FFD, 0xFEDF3FFD,
	0xFEEC3FFE, 0xFEF83FFE,
	0xFF053FFE, 0xFF113FFE,
	0xFF1E3FFE, 0xFF2A3FFF,	/* 8 */
	0xFF373FFF, 0xFF443FFF,
	0xFF503FFF, 0xFF5D3FFF,
	0xFF693FFF, 0xFF763FFF,
	0xFF824000, 0xFF8F4000,	/* 16 */
	0xFF9B4000, 0xFFA84000,
	0xFFB54000, 0xFFC14000,
	0xFFCE4000, 0xFFDA4000,
	0xFFE74000, 0xFFF34000,	/* 24 */
	0x00004000, 0x000D4000,
	0x00194000, 0x00264000,
	0x00324000, 0x003F4000,
	0x004B4000, 0x00584000,	/* 32 */
	0x00654000, 0x00714000,
	0x007E4000, 0x008A3FFF,
	0x00973FFF, 0x00A33FFF,
	0x00B03FFF, 0x00BC3FFF,	/* 40 */
	0x00C93FFF, 0x00D63FFF,
	0x00E23FFE, 0x00EF3FFE,
	0x00FB3FFE, 0x01083FFE,
	0x01143FFE, 0x01213FFD,	/* 48 */
	0x012E3FFD, 0x013A3FFD,
	0x01473FFD,
};

const u32 b43_tab_retard[] = {
	0xDB93CB87, 0xD666CF64,	/* 0 */
	0xD1FDD358, 0xCDA6D826,
	0xCA38DD9F, 0xC729E2B4,
	0xC469E88E, 0xC26AEE2B,
	0xC0DEF46C, 0xC073FA62,	/* 8 */
	0xC01D00D5, 0xC0760743,
	0xC1560D1E, 0xC2E51369,
	0xC4ED18FF, 0xC7AC1ED7,
	0xCB2823B2, 0xCEFA28D9,	/* 16 */
	0xD2F62D3F, 0xD7BB3197,
	0xDCE53568, 0xE1FE3875,
	0xE7D13B35, 0xED663D35,
	0xF39B3EC4, 0xF98E3FA7,	/* 24 */
	0x00004000, 0x06723FA7,
	0x0C653EC4, 0x129A3D35,
	0x182F3B35, 0x1E023875,
	0x231B3568, 0x28453197,	/* 32 */
	0x2D0A2D3F, 0x310628D9,
	0x34D823B2, 0x38541ED7,
	0x3B1318FF, 0x3D1B1369,
	0x3EAA0D1E, 0x3F8A0743,	/* 40 */
	0x3FE300D5, 0x3F8DFA62,
	0x3F22F46C, 0x3D96EE2B,
	0x3B97E88E, 0x38D7E2B4,
	0x35C8DD9F, 0x325AD826,	/* 48 */
	0x2E03D358, 0x299ACF64,
	0x246DCB87,
};

const u16 b43_tab_finefreqa[] = {
	0x0082, 0x0082, 0x0102, 0x0182,	/* 0 */
	0x0202, 0x0282, 0x0302, 0x0382,
	0x0402, 0x0482, 0x0502, 0x0582,
	0x05E2, 0x0662, 0x06E2, 0x0762,
	0x07E2, 0x0842, 0x08C2, 0x0942,	/* 16 */
	0x09C2, 0x0A22, 0x0AA2, 0x0B02,
	0x0B82, 0x0BE2, 0x0C62, 0x0CC2,
	0x0D42, 0x0DA2, 0x0E02, 0x0E62,
	0x0EE2, 0x0F42, 0x0FA2, 0x1002,	/* 32 */
	0x1062, 0x10C2, 0x1122, 0x1182,
	0x11E2, 0x1242, 0x12A2, 0x12E2,
	0x1342, 0x13A2, 0x1402, 0x1442,
	0x14A2, 0x14E2, 0x1542, 0x1582,	/* 48 */
	0x15E2, 0x1622, 0x1662, 0x16C1,
	0x1701, 0x1741, 0x1781, 0x17E1,
	0x1821, 0x1861, 0x18A1, 0x18E1,
	0x1921, 0x1961, 0x19A1, 0x19E1,	/* 64 */
	0x1A21, 0x1A61, 0x1AA1, 0x1AC1,
	0x1B01, 0x1B41, 0x1B81, 0x1BA1,
	0x1BE1, 0x1C21, 0x1C41, 0x1C81,
	0x1CA1, 0x1CE1, 0x1D01, 0x1D41,	/* 80 */
	0x1D61, 0x1DA1, 0x1DC1, 0x1E01,
	0x1E21, 0x1E61, 0x1E81, 0x1EA1,
	0x1EE1, 0x1F01, 0x1F21, 0x1F41,
	0x1F81, 0x1FA1, 0x1FC1, 0x1FE1,	/* 96 */
	0x2001, 0x2041, 0x2061, 0x2081,
	0x20A1, 0x20C1, 0x20E1, 0x2101,
	0x2121, 0x2141, 0x2161, 0x2181,
	0x21A1, 0x21C1, 0x21E1, 0x2201,	/* 112 */
	0x2221, 0x2241, 0x2261, 0x2281,
	0x22A1, 0x22C1, 0x22C1, 0x22E1,
	0x2301, 0x2321, 0x2341, 0x2361,
	0x2361, 0x2381, 0x23A1, 0x23C1,	/* 128 */
	0x23E1, 0x23E1, 0x2401, 0x2421,
	0x2441, 0x2441, 0x2461, 0x2481,
	0x2481, 0x24A1, 0x24C1, 0x24C1,
	0x24E1, 0x2501, 0x2501, 0x2521,	/* 144 */
	0x2541, 0x2541, 0x2561, 0x2561,
	0x2581, 0x25A1, 0x25A1, 0x25C1,
	0x25C1, 0x25E1, 0x2601, 0x2601,
	0x2621, 0x2621, 0x2641, 0x2641,	/* 160 */
	0x2661, 0x2661, 0x2681, 0x2681,
	0x26A1, 0x26A1, 0x26C1, 0x26C1,
	0x26E1, 0x26E1, 0x2701, 0x2701,
	0x2721, 0x2721, 0x2740, 0x2740,	/* 176 */
	0x2760, 0x2760, 0x2780, 0x2780,
	0x2780, 0x27A0, 0x27A0, 0x27C0,
	0x27C0, 0x27E0, 0x27E0, 0x27E0,
	0x2800, 0x2800, 0x2820, 0x2820,	/* 192 */
	0x2820, 0x2840, 0x2840, 0x2840,
	0x2860, 0x2860, 0x2880, 0x2880,
	0x2880, 0x28A0, 0x28A0, 0x28A0,
	0x28C0, 0x28C0, 0x28C0, 0x28E0,	/* 208 */
	0x28E0, 0x28E0, 0x2900, 0x2900,
	0x2900, 0x2920, 0x2920, 0x2920,
	0x2940, 0x2940, 0x2940, 0x2960,
	0x2960, 0x2960, 0x2960, 0x2980,	/* 224 */
	0x2980, 0x2980, 0x29A0, 0x29A0,
	0x29A0, 0x29A0, 0x29C0, 0x29C0,
	0x29C0, 0x29E0, 0x29E0, 0x29E0,
	0x29E0, 0x2A00, 0x2A00, 0x2A00,	/* 240 */
	0x2A00, 0x2A20, 0x2A20, 0x2A20,
	0x2A20, 0x2A40, 0x2A40, 0x2A40,
	0x2A40, 0x2A60, 0x2A60, 0x2A60,
};

const u16 b43_tab_finefreqg[] = {
	0x0089, 0x02E9, 0x0409, 0x04E9,	/* 0 */
	0x05A9, 0x0669, 0x0709, 0x0789,
	0x0829, 0x08A9, 0x0929, 0x0989,
	0x0A09, 0x0A69, 0x0AC9, 0x0B29,
	0x0BA9, 0x0BE9, 0x0C49, 0x0CA9,	/* 16 */
	0x0D09, 0x0D69, 0x0DA9, 0x0E09,
	0x0E69, 0x0EA9, 0x0F09, 0x0F49,
	0x0FA9, 0x0FE9, 0x1029, 0x1089,
	0x10C9, 0x1109, 0x1169, 0x11A9,	/* 32 */
	0x11E9, 0x1229, 0x1289, 0x12C9,
	0x1309, 0x1349, 0x1389, 0x13C9,
	0x1409, 0x1449, 0x14A9, 0x14E9,
	0x1529, 0x1569, 0x15A9, 0x15E9,	/* 48 */
	0x1629, 0x1669, 0x16A9, 0x16E8,
	0x1728, 0x1768, 0x17A8, 0x17E8,
	0x1828, 0x1868, 0x18A8, 0x18E8,
	0x1928, 0x1968, 0x19A8, 0x19E8,	/* 64 */
	0x1A28, 0x1A68, 0x1AA8, 0x1AE8,
	0x1B28, 0x1B68, 0x1BA8, 0x1BE8,
	0x1C28, 0x1C68, 0x1CA8, 0x1CE8,
	0x1D28, 0x1D68, 0x1DC8, 0x1E08,	/* 80 */
	0x1E48, 0x1E88, 0x1EC8, 0x1F08,
	0x1F48, 0x1F88, 0x1FE8, 0x2028,
	0x2068, 0x20A8, 0x2108, 0x2148,
	0x2188, 0x21C8, 0x2228, 0x2268,	/* 96 */
	0x22C8, 0x2308, 0x2348, 0x23A8,
	0x23E8, 0x2448, 0x24A8, 0x24E8,
	0x2548, 0x25A8, 0x2608, 0x2668,
	0x26C8, 0x2728, 0x2787, 0x27E7,	/* 112 */
	0x2847, 0x28C7, 0x2947, 0x29A7,
	0x2A27, 0x2AC7, 0x2B47, 0x2BE7,
	0x2CA7, 0x2D67, 0x2E47, 0x2F67,
	0x3247, 0x3526, 0x3646, 0x3726,	/* 128 */
	0x3806, 0x38A6, 0x3946, 0x39E6,
	0x3A66, 0x3AE6, 0x3B66, 0x3BC6,
	0x3C45, 0x3CA5, 0x3D05, 0x3D85,
	0x3DE5, 0x3E45, 0x3EA5, 0x3EE5,	/* 144 */
	0x3F45, 0x3FA5, 0x4005, 0x4045,
	0x40A5, 0x40E5, 0x4145, 0x4185,
	0x41E5, 0x4225, 0x4265, 0x42C5,
	0x4305, 0x4345, 0x43A5, 0x43E5,	/* 160 */
	0x4424, 0x4464, 0x44C4, 0x4504,
	0x4544, 0x4584, 0x45C4, 0x4604,
	0x4644, 0x46A4, 0x46E4, 0x4724,
	0x4764, 0x47A4, 0x47E4, 0x4824,	/* 176 */
	0x4864, 0x48A4, 0x48E4, 0x4924,
	0x4964, 0x49A4, 0x49E4, 0x4A24,
	0x4A64, 0x4AA4, 0x4AE4, 0x4B23,
	0x4B63, 0x4BA3, 0x4BE3, 0x4C23,	/* 192 */
	0x4C63, 0x4CA3, 0x4CE3, 0x4D23,
	0x4D63, 0x4DA3, 0x4DE3, 0x4E23,
	0x4E63, 0x4EA3, 0x4EE3, 0x4F23,
	0x4F63, 0x4FC3, 0x5003, 0x5043,	/* 208 */
	0x5083, 0x50C3, 0x5103, 0x5143,
	0x5183, 0x51E2, 0x5222, 0x5262,
	0x52A2, 0x52E2, 0x5342, 0x5382,
	0x53C2, 0x5402, 0x5462, 0x54A2,	/* 224 */
	0x5502, 0x5542, 0x55A2, 0x55E2,
	0x5642, 0x5682, 0x56E2, 0x5722,
	0x5782, 0x57E1, 0x5841, 0x58A1,
	0x5901, 0x5961, 0x59C1, 0x5A21,	/* 240 */
	0x5AA1, 0x5B01, 0x5B81, 0x5BE1,
	0x5C61, 0x5D01, 0x5D80, 0x5E20,
	0x5EE0, 0x5FA0, 0x6080, 0x61C0,
};

const u16 b43_tab_noisea2[] = {
	0x0001, 0x0001, 0x0001, 0xFFFE,
	0xFFFE, 0x3FFF, 0x1000, 0x0393,
};

const u16 b43_tab_noisea3[] = {
	0x5E5E, 0x5E5E, 0x5E5E, 0x3F48,
	0x4C4C, 0x4C4C, 0x4C4C, 0x2D36,
};

const u16 b43_tab_noiseg1[] = {
	0x013C, 0x01F5, 0x031A, 0x0631,
	0x0001, 0x0001, 0x0001, 0x0001,
};

const u16 b43_tab_noiseg2[] = {
	0x5484, 0x3C40, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000,
};

const u16 b43_tab_noisescalea2[] = {
	0x6767, 0x6767, 0x6767, 0x6767, /* 0 */
	0x6767, 0x6767, 0x6767, 0x6767,
	0x6767, 0x6767, 0x6767, 0x6767,
	0x6767, 0x6700, 0x6767, 0x6767,
	0x6767, 0x6767, 0x6767, 0x6767, /* 16 */
	0x6767, 0x6767, 0x6767, 0x6767,
	0x6767, 0x6767, 0x0067,
};

const u16 b43_tab_noisescalea3[] = {
	0x2323, 0x2323, 0x2323, 0x2323, /* 0 */
	0x2323, 0x2323, 0x2323, 0x2323,
	0x2323, 0x2323, 0x2323, 0x2323,
	0x2323, 0x2300, 0x2323, 0x2323,
	0x2323, 0x2323, 0x2323, 0x2323, /* 16 */
	0x2323, 0x2323, 0x2323, 0x2323,
	0x2323, 0x2323, 0x0023,
};

const u16 b43_tab_noisescaleg1[] = {
	0x6C77, 0x5162, 0x3B40, 0x3335,	/* 0 */
	0x2F2D, 0x2A2A, 0x2527, 0x1F21,
	0x1A1D, 0x1719, 0x1616, 0x1414,
	0x1414, 0x1400, 0x1414, 0x1614,
	0x1716, 0x1A19, 0x1F1D, 0x2521,	/* 16 */
	0x2A27, 0x2F2A, 0x332D, 0x3B35,
	0x5140, 0x6C62, 0x0077,
};

const u16 b43_tab_noisescaleg2[] = {
	0xD8DD, 0xCBD4, 0xBCC0, 0xB6B7,	/* 0 */
	0xB2B0, 0xADAD, 0xA7A9, 0x9FA1,
	0x969B, 0x9195, 0x8F8F, 0x8A8A,
	0x8A8A, 0x8A00, 0x8A8A, 0x8F8A,
	0x918F, 0x9695, 0x9F9B, 0xA7A1,	/* 16 */
	0xADA9, 0xB2AD, 0xB6B0, 0xBCB7,
	0xCBC0, 0xD8D4, 0x00DD,
};

const u16 b43_tab_noisescaleg3[] = {
	0xA4A4, 0xA4A4, 0xA4A4, 0xA4A4,	/* 0 */
	0xA4A4, 0xA4A4, 0xA4A4, 0xA4A4,
	0xA4A4, 0xA4A4, 0xA4A4, 0xA4A4,
	0xA4A4, 0xA400, 0xA4A4, 0xA4A4,
	0xA4A4, 0xA4A4, 0xA4A4, 0xA4A4,	/* 16 */
	0xA4A4, 0xA4A4, 0xA4A4, 0xA4A4,
	0xA4A4, 0xA4A4, 0x00A4,
};

const u16 b43_tab_sigmasqr1[] = {
	0x007A, 0x0075, 0x0071, 0x006C,	/* 0 */
	0x0067, 0x0063, 0x005E, 0x0059,
	0x0054, 0x0050, 0x004B, 0x0046,
	0x0042, 0x003D, 0x003D, 0x003D,
	0x003D, 0x003D, 0x003D, 0x003D,	/* 16 */
	0x003D, 0x003D, 0x003D, 0x003D,
	0x003D, 0x003D, 0x0000, 0x003D,
	0x003D, 0x003D, 0x003D, 0x003D,
	0x003D, 0x003D, 0x003D, 0x003D,	/* 32 */
	0x003D, 0x003D, 0x003D, 0x003D,
	0x0042, 0x0046, 0x004B, 0x0050,
	0x0054, 0x0059, 0x005E, 0x0063,
	0x0067, 0x006C, 0x0071, 0x0075,	/* 48 */
	0x007A,
};

const u16 b43_tab_sigmasqr2[] = {
	0x00DE, 0x00DC, 0x00DA, 0x00D8,	/* 0 */
	0x00D6, 0x00D4, 0x00D2, 0x00CF,
	0x00CD, 0x00CA, 0x00C7, 0x00C4,
	0x00C1, 0x00BE, 0x00BE, 0x00BE,
	0x00BE, 0x00BE, 0x00BE, 0x00BE,	/* 16 */
	0x00BE, 0x00BE, 0x00BE, 0x00BE,
	0x00BE, 0x00BE, 0x0000, 0x00BE,
	0x00BE, 0x00BE, 0x00BE, 0x00BE,
	0x00BE, 0x00BE, 0x00BE, 0x00BE,	/* 32 */
	0x00BE, 0x00BE, 0x00BE, 0x00BE,
	0x00C1, 0x00C4, 0x00C7, 0x00CA,
	0x00CD, 0x00CF, 0x00D2, 0x00D4,
	0x00D6, 0x00D8, 0x00DA, 0x00DC,	/* 48 */
	0x00DE,
};

const u16 b43_tab_rssiagc1[] = {
	0xFFF8, 0xFFF8, 0xFFF8, 0xFFF8, /* 0 */
	0xFFF8, 0xFFF9, 0xFFFC, 0xFFFE,
	0xFFF8, 0xFFF8, 0xFFF8, 0xFFF8,
	0xFFF8, 0xFFF8, 0xFFF8, 0xFFF8,
};

const u16 b43_tab_rssiagc2[] = {
	0x0820, 0x0820, 0x0920, 0x0C38, /* 0 */
	0x0820, 0x0820, 0x0820, 0x0820,
	0x0820, 0x0820, 0x0920, 0x0A38,
	0x0820, 0x0820, 0x0820, 0x0820,
	0x0820, 0x0820, 0x0920, 0x0A38, /* 16 */
	0x0820, 0x0820, 0x0820, 0x0820,
	0x0820, 0x0820, 0x0920, 0x0A38,
	0x0820, 0x0820, 0x0820, 0x0820,
	0x0820, 0x0820, 0x0920, 0x0A38, /* 32 */
	0x0820, 0x0820, 0x0820, 0x0820,
	0x0820, 0x0820, 0x0920, 0x0A38,
	0x0820, 0x0820, 0x0820, 0x0820,
};

static inline void assert_sizes(void)
{
	BUILD_BUG_ON(B43_TAB_ROTOR_SIZE != ARRAY_SIZE(b43_tab_rotor));
	BUILD_BUG_ON(B43_TAB_RETARD_SIZE != ARRAY_SIZE(b43_tab_retard));
	BUILD_BUG_ON(B43_TAB_FINEFREQA_SIZE != ARRAY_SIZE(b43_tab_finefreqa));
	BUILD_BUG_ON(B43_TAB_FINEFREQG_SIZE != ARRAY_SIZE(b43_tab_finefreqg));
	BUILD_BUG_ON(B43_TAB_NOISEA2_SIZE != ARRAY_SIZE(b43_tab_noisea2));
	BUILD_BUG_ON(B43_TAB_NOISEA3_SIZE != ARRAY_SIZE(b43_tab_noisea3));
	BUILD_BUG_ON(B43_TAB_NOISEG1_SIZE != ARRAY_SIZE(b43_tab_noiseg1));
	BUILD_BUG_ON(B43_TAB_NOISEG2_SIZE != ARRAY_SIZE(b43_tab_noiseg2));
	BUILD_BUG_ON(B43_TAB_NOISESCALE_SIZE !=
		     ARRAY_SIZE(b43_tab_noisescalea2));
	BUILD_BUG_ON(B43_TAB_NOISESCALE_SIZE !=
		     ARRAY_SIZE(b43_tab_noisescalea3));
	BUILD_BUG_ON(B43_TAB_NOISESCALE_SIZE !=
		     ARRAY_SIZE(b43_tab_noisescaleg1));
	BUILD_BUG_ON(B43_TAB_NOISESCALE_SIZE !=
		     ARRAY_SIZE(b43_tab_noisescaleg2));
	BUILD_BUG_ON(B43_TAB_NOISESCALE_SIZE !=
		     ARRAY_SIZE(b43_tab_noisescaleg3));
	BUILD_BUG_ON(B43_TAB_SIGMASQR_SIZE != ARRAY_SIZE(b43_tab_sigmasqr1));
	BUILD_BUG_ON(B43_TAB_SIGMASQR_SIZE != ARRAY_SIZE(b43_tab_sigmasqr2));
	BUILD_BUG_ON(B43_TAB_RSSIAGC1_SIZE != ARRAY_SIZE(b43_tab_rssiagc1));
	BUILD_BUG_ON(B43_TAB_RSSIAGC2_SIZE != ARRAY_SIZE(b43_tab_rssiagc2));
}

u16 b43_ofdmtab_read16(struct b43_wldev *dev, u16 table, u16 offset)
{
	struct b43_phy_g *gphy = dev->phy.g;
	u16 addr;

	addr = table + offset;
	if ((gphy->ofdmtab_addr_direction != B43_OFDMTAB_DIRECTION_READ) ||
	    (addr - 1 != gphy->ofdmtab_addr)) {
		/* The hardware has a different address in memory. Update it. */
		b43_phy_write(dev, B43_PHY_OTABLECTL, addr);
		gphy->ofdmtab_addr_direction = B43_OFDMTAB_DIRECTION_READ;
	}
	gphy->ofdmtab_addr = addr;

	return b43_phy_read(dev, B43_PHY_OTABLEI);

	/* Some compiletime assertions... */
	assert_sizes();
}

void b43_ofdmtab_write16(struct b43_wldev *dev, u16 table,
			 u16 offset, u16 value)
{
	struct b43_phy_g *gphy = dev->phy.g;
	u16 addr;

	addr = table + offset;
	if ((gphy->ofdmtab_addr_direction != B43_OFDMTAB_DIRECTION_WRITE) ||
	    (addr - 1 != gphy->ofdmtab_addr)) {
		/* The hardware has a different address in memory. Update it. */
		b43_phy_write(dev, B43_PHY_OTABLECTL, addr);
		gphy->ofdmtab_addr_direction = B43_OFDMTAB_DIRECTION_WRITE;
	}
	gphy->ofdmtab_addr = addr;
	b43_phy_write(dev, B43_PHY_OTABLEI, value);
}

u32 b43_ofdmtab_read32(struct b43_wldev *dev, u16 table, u16 offset)
{
	struct b43_phy_g *gphy = dev->phy.g;
	u32 ret;
	u16 addr;

	addr = table + offset;
	if ((gphy->ofdmtab_addr_direction != B43_OFDMTAB_DIRECTION_READ) ||
	    (addr - 1 != gphy->ofdmtab_addr)) {
		/* The hardware has a different address in memory. Update it. */
		b43_phy_write(dev, B43_PHY_OTABLECTL, addr);
		gphy->ofdmtab_addr_direction = B43_OFDMTAB_DIRECTION_READ;
	}
	gphy->ofdmtab_addr = addr;
	ret = b43_phy_read(dev, B43_PHY_OTABLEQ);
	ret <<= 16;
	ret |= b43_phy_read(dev, B43_PHY_OTABLEI);

	return ret;
}

void b43_ofdmtab_write32(struct b43_wldev *dev, u16 table,
			 u16 offset, u32 value)
{
	struct b43_phy_g *gphy = dev->phy.g;
	u16 addr;

	addr = table + offset;
	if ((gphy->ofdmtab_addr_direction != B43_OFDMTAB_DIRECTION_WRITE) ||
	    (addr - 1 != gphy->ofdmtab_addr)) {
		/* The hardware has a different address in memory. Update it. */
		b43_phy_write(dev, B43_PHY_OTABLECTL, addr);
		gphy->ofdmtab_addr_direction = B43_OFDMTAB_DIRECTION_WRITE;
	}
	gphy->ofdmtab_addr = addr;

	b43_phy_write(dev, B43_PHY_OTABLEI, value);
	b43_phy_write(dev, B43_PHY_OTABLEQ, (value >> 16));
}

u16 b43_gtab_read(struct b43_wldev *dev, u16 table, u16 offset)
{
	b43_phy_write(dev, B43_PHY_GTABCTL, table + offset);
	return b43_phy_read(dev, B43_PHY_GTABDATA);
}

void b43_gtab_write(struct b43_wldev *dev, u16 table, u16 offset, u16 value)
{
	b43_phy_write(dev, B43_PHY_GTABCTL, table + offset);
	b43_phy_write(dev, B43_PHY_GTABDATA, value);
}
