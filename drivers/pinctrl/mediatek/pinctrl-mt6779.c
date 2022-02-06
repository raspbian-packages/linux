// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 MediaTek Inc.
 * Author: Andy Teng <andy.teng@mediatek.com>
 *
 */

#include <linux/module.h>
#include "pinctrl-mtk-mt6779.h"
#include "pinctrl-paris.h"

/* MT6779 have multiple bases to program pin configuration listed as the below:
 * gpio:0x10005000,     iocfg_rm:0x11C20000, iocfg_br:0x11D10000,
 * iocfg_lm:0x11E20000, iocfg_lb:0x11E70000, iocfg_rt:0x11EA0000,
 * iocfg_lt:0x11F20000, iocfg_tl:0x11F30000
 * _i_based could be used to indicate what base the pin should be mapped into.
 */

#define PIN_FIELD_BASE(s_pin, e_pin, i_base, s_addr, x_addrs, s_bit, x_bits) \
	PIN_FIELD_CALC(s_pin, e_pin, i_base, s_addr, x_addrs, s_bit, x_bits, \
		       32, 0)

#define PINS_FIELD_BASE(s_pin, e_pin, i_base, s_addr, x_addrs, s_bit, x_bits) \
	PIN_FIELD_CALC(s_pin, e_pin, i_base, s_addr, x_addrs, s_bit, x_bits,  \
		       32, 1)

static const struct mtk_pin_field_calc mt6779_pin_mode_range[] = {
	PIN_FIELD_BASE(0, 7, 0, 0x0300, 0x10, 0, 4),
	PIN_FIELD_BASE(8, 15, 0, 0x0310, 0x10, 0, 4),
	PIN_FIELD_BASE(16, 23, 0, 0x0320, 0x10, 0, 4),
	PIN_FIELD_BASE(24, 31, 0, 0x0330, 0x10, 0, 4),
	PIN_FIELD_BASE(32, 39, 0, 0x0340, 0x10, 0, 4),
	PIN_FIELD_BASE(40, 47, 0, 0x0350, 0x10, 0, 4),
	PIN_FIELD_BASE(48, 55, 0, 0x0360, 0x10, 0, 4),
	PIN_FIELD_BASE(56, 63, 0, 0x0370, 0x10, 0, 4),
	PIN_FIELD_BASE(64, 71, 0, 0x0380, 0x10, 0, 4),
	PIN_FIELD_BASE(72, 79, 0, 0x0390, 0x10, 0, 4),
	PIN_FIELD_BASE(80, 87, 0, 0x03A0, 0x10, 0, 4),
	PIN_FIELD_BASE(88, 95, 0, 0x03B0, 0x10, 0, 4),
	PIN_FIELD_BASE(96, 103, 0, 0x03C0, 0x10, 0, 4),
	PIN_FIELD_BASE(104, 111, 0, 0x03D0, 0x10, 0, 4),
	PIN_FIELD_BASE(112, 119, 0, 0x03E0, 0x10, 0, 4),
	PIN_FIELD_BASE(120, 127, 0, 0x03F0, 0x10, 0, 4),
	PIN_FIELD_BASE(128, 135, 0, 0x0400, 0x10, 0, 4),
	PIN_FIELD_BASE(136, 143, 0, 0x0410, 0x10, 0, 4),
	PIN_FIELD_BASE(144, 151, 0, 0x0420, 0x10, 0, 4),
	PIN_FIELD_BASE(152, 159, 0, 0x0430, 0x10, 0, 4),
	PIN_FIELD_BASE(160, 167, 0, 0x0440, 0x10, 0, 4),
	PIN_FIELD_BASE(168, 175, 0, 0x0450, 0x10, 0, 4),
	PIN_FIELD_BASE(176, 183, 0, 0x0460, 0x10, 0, 4),
	PIN_FIELD_BASE(184, 191, 0, 0x0470, 0x10, 0, 4),
	PIN_FIELD_BASE(192, 199, 0, 0x0480, 0x10, 0, 4),
	PIN_FIELD_BASE(200, 202, 0, 0x0490, 0x10, 0, 4),
};

static const struct mtk_pin_field_calc mt6779_pin_dir_range[] = {
	PIN_FIELD_BASE(0, 31, 0, 0x0000, 0x10, 0, 1),
	PIN_FIELD_BASE(32, 63, 0, 0x0010, 0x10, 0, 1),
	PIN_FIELD_BASE(64, 95, 0, 0x0020, 0x10, 0, 1),
	PIN_FIELD_BASE(96, 127, 0, 0x0030, 0x10, 0, 1),
	PIN_FIELD_BASE(128, 159, 0, 0x0040, 0x10, 0, 1),
	PIN_FIELD_BASE(160, 191, 0, 0x0050, 0x10, 0, 1),
	PIN_FIELD_BASE(192, 202, 0, 0x0060, 0x10, 0, 1),
};

static const struct mtk_pin_field_calc mt6779_pin_di_range[] = {
	PIN_FIELD_BASE(0, 31, 0, 0x0200, 0x10, 0, 1),
	PIN_FIELD_BASE(32, 63, 0, 0x0210, 0x10, 0, 1),
	PIN_FIELD_BASE(64, 95, 0, 0x0220, 0x10, 0, 1),
	PIN_FIELD_BASE(96, 127, 0, 0x0230, 0x10, 0, 1),
	PIN_FIELD_BASE(128, 159, 0, 0x0240, 0x10, 0, 1),
	PIN_FIELD_BASE(160, 191, 0, 0x0250, 0x10, 0, 1),
	PIN_FIELD_BASE(192, 202, 0, 0x0260, 0x10, 0, 1),
};

static const struct mtk_pin_field_calc mt6779_pin_do_range[] = {
	PIN_FIELD_BASE(0, 31, 0, 0x0100, 0x10, 0, 1),
	PIN_FIELD_BASE(32, 63, 0, 0x0110, 0x10, 0, 1),
	PIN_FIELD_BASE(64, 95, 0, 0x0120, 0x10, 0, 1),
	PIN_FIELD_BASE(96, 127, 0, 0x0130, 0x10, 0, 1),
	PIN_FIELD_BASE(128, 159, 0, 0x0140, 0x10, 0, 1),
	PIN_FIELD_BASE(160, 191, 0, 0x0150, 0x10, 0, 1),
	PIN_FIELD_BASE(192, 202, 0, 0x0160, 0x10, 0, 1),
};

static const struct mtk_pin_field_calc mt6779_pin_ies_range[] = {
	PIN_FIELD_BASE(0, 9, 6, 0x0030, 0x10, 3, 1),
	PIN_FIELD_BASE(10, 16, 3, 0x0050, 0x10, 0, 1),
	PIN_FIELD_BASE(17, 18, 6, 0x0030, 0x10, 28, 1),
	PIN_FIELD_BASE(19, 19, 6, 0x0030, 0x10, 27, 1),
	PIN_FIELD_BASE(20, 20, 6, 0x0030, 0x10, 26, 1),
	PIN_FIELD_BASE(21, 24, 6, 0x0030, 0x10, 19, 1),
	PIN_FIELD_BASE(25, 25, 6, 0x0030, 0x10, 30, 1),
	PIN_FIELD_BASE(26, 26, 6, 0x0030, 0x10, 23, 1),
	PIN_FIELD_BASE(27, 27, 6, 0x0030, 0x10, 0, 1),
	PIN_FIELD_BASE(28, 29, 6, 0x0030, 0x10, 24, 1),
	PIN_FIELD_BASE(30, 30, 6, 0x0030, 0x10, 16, 1),
	PIN_FIELD_BASE(31, 31, 6, 0x0030, 0x10, 13, 1),
	PIN_FIELD_BASE(32, 32, 6, 0x0030, 0x10, 15, 1),
	PIN_FIELD_BASE(33, 33, 6, 0x0030, 0x10, 17, 1),
	PIN_FIELD_BASE(34, 34, 6, 0x0030, 0x10, 14, 1),
	PIN_FIELD_BASE(35, 35, 6, 0x0040, 0x10, 4, 1),
	PIN_FIELD_BASE(36, 36, 6, 0x0030, 0x10, 31, 1),
	PIN_FIELD_BASE(37, 37, 6, 0x0040, 0x10, 5, 1),
	PIN_FIELD_BASE(38, 41, 6, 0x0040, 0x10, 0, 1),
	PIN_FIELD_BASE(42, 43, 6, 0x0030, 0x10, 1, 1),
	PIN_FIELD_BASE(44, 44, 6, 0x0030, 0x10, 18, 1),
	PIN_FIELD_BASE(45, 45, 3, 0x0050, 0x10, 14, 1),
	PIN_FIELD_BASE(46, 46, 3, 0x0050, 0x10, 22, 1),
	PIN_FIELD_BASE(47, 47, 3, 0x0050, 0x10, 25, 1),
	PIN_FIELD_BASE(48, 48, 3, 0x0050, 0x10, 24, 1),
	PIN_FIELD_BASE(49, 49, 3, 0x0050, 0x10, 26, 1),
	PIN_FIELD_BASE(50, 50, 3, 0x0050, 0x10, 23, 1),
	PIN_FIELD_BASE(51, 51, 3, 0x0050, 0x10, 11, 1),
	PIN_FIELD_BASE(52, 52, 3, 0x0050, 0x10, 19, 1),
	PIN_FIELD_BASE(53, 54, 3, 0x0050, 0x10, 27, 1),
	PIN_FIELD_BASE(55, 55, 3, 0x0050, 0x10, 13, 1),
	PIN_FIELD_BASE(56, 56, 3, 0x0050, 0x10, 21, 1),
	PIN_FIELD_BASE(57, 57, 3, 0x0050, 0x10, 10, 1),
	PIN_FIELD_BASE(58, 58, 3, 0x0050, 0x10, 9, 1),
	PIN_FIELD_BASE(59, 60, 3, 0x0050, 0x10, 7, 1),
	PIN_FIELD_BASE(61, 61, 3, 0x0050, 0x10, 12, 1),
	PIN_FIELD_BASE(62, 62, 3, 0x0050, 0x10, 20, 1),
	PIN_FIELD_BASE(63, 63, 3, 0x0050, 0x10, 17, 1),
	PIN_FIELD_BASE(64, 64, 3, 0x0050, 0x10, 16, 1),
	PIN_FIELD_BASE(65, 65, 3, 0x0050, 0x10, 18, 1),
	PIN_FIELD_BASE(66, 66, 3, 0x0050, 0x10, 15, 1),
	PIN_FIELD_BASE(67, 67, 2, 0x0060, 0x10, 7, 1),
	PIN_FIELD_BASE(68, 68, 2, 0x0060, 0x10, 6, 1),
	PIN_FIELD_BASE(69, 69, 2, 0x0060, 0x10, 8, 1),
	PIN_FIELD_BASE(70, 71, 2, 0x0060, 0x10, 4, 1),
	PIN_FIELD_BASE(72, 72, 4, 0x0020, 0x10, 3, 1),
	PIN_FIELD_BASE(73, 73, 4, 0x0020, 0x10, 2, 1),
	PIN_FIELD_BASE(74, 74, 4, 0x0020, 0x10, 1, 1),
	PIN_FIELD_BASE(75, 75, 4, 0x0020, 0x10, 4, 1),
	PIN_FIELD_BASE(76, 76, 4, 0x0020, 0x10, 12, 1),
	PIN_FIELD_BASE(77, 77, 4, 0x0020, 0x10, 11, 1),
	PIN_FIELD_BASE(78, 78, 2, 0x0050, 0x10, 18, 1),
	PIN_FIELD_BASE(79, 79, 2, 0x0050, 0x10, 17, 1),
	PIN_FIELD_BASE(80, 81, 2, 0x0050, 0x10, 19, 1),
	PIN_FIELD_BASE(82, 88, 2, 0x0050, 0x10, 1, 1),
	PIN_FIELD_BASE(89, 89, 2, 0x0050, 0x10, 16, 1),
	PIN_FIELD_BASE(90, 90, 2, 0x0050, 0x10, 15, 1),
	PIN_FIELD_BASE(91, 91, 2, 0x0050, 0x10, 14, 1),
	PIN_FIELD_BASE(92, 92, 2, 0x0050, 0x10, 8, 1),
	PIN_FIELD_BASE(93, 93, 4, 0x0020, 0x10, 0, 1),
	PIN_FIELD_BASE(94, 94, 2, 0x0050, 0x10, 0, 1),
	PIN_FIELD_BASE(95, 95, 4, 0x0020, 0x10, 7, 1),
	PIN_FIELD_BASE(96, 96, 4, 0x0020, 0x10, 5, 1),
	PIN_FIELD_BASE(97, 97, 4, 0x0020, 0x10, 8, 1),
	PIN_FIELD_BASE(98, 98, 4, 0x0020, 0x10, 6, 1),
	PIN_FIELD_BASE(99, 99, 2, 0x0060, 0x10, 9, 1),
	PIN_FIELD_BASE(100, 100, 2, 0x0060, 0x10, 12, 1),
	PIN_FIELD_BASE(101, 101, 2, 0x0060, 0x10, 10, 1),
	PIN_FIELD_BASE(102, 102, 2, 0x0060, 0x10, 13, 1),
	PIN_FIELD_BASE(103, 103, 2, 0x0060, 0x10, 11, 1),
	PIN_FIELD_BASE(104, 104, 2, 0x0060, 0x10, 14, 1),
	PIN_FIELD_BASE(105, 105, 2, 0x0050, 0x10, 10, 1),
	PIN_FIELD_BASE(106, 106, 2, 0x0050, 0x10, 9, 1),
	PIN_FIELD_BASE(107, 108, 2, 0x0050, 0x10, 12, 1),
	PIN_FIELD_BASE(109, 109, 2, 0x0050, 0x10, 11, 1),
	PIN_FIELD_BASE(110, 110, 2, 0x0060, 0x10, 16, 1),
	PIN_FIELD_BASE(111, 111, 2, 0x0060, 0x10, 18, 1),
	PIN_FIELD_BASE(112, 112, 2, 0x0060, 0x10, 15, 1),
	PIN_FIELD_BASE(113, 113, 2, 0x0060, 0x10, 17, 1),
	PIN_FIELD_BASE(114, 115, 2, 0x0050, 0x10, 26, 1),
	PIN_FIELD_BASE(116, 117, 2, 0x0050, 0x10, 21, 1),
	PIN_FIELD_BASE(118, 118, 2, 0x0050, 0x10, 31, 1),
	PIN_FIELD_BASE(119, 119, 2, 0x0060, 0x10, 0, 1),
	PIN_FIELD_BASE(120, 121, 2, 0x0050, 0x10, 23, 1),
	PIN_FIELD_BASE(122, 123, 2, 0x0050, 0x10, 28, 1),
	PIN_FIELD_BASE(124, 125, 2, 0x0060, 0x10, 1, 1),
	PIN_FIELD_BASE(126, 127, 1, 0x0030, 0x10, 8, 1),
	PIN_FIELD_BASE(128, 129, 1, 0x0030, 0x10, 17, 1),
	PIN_FIELD_BASE(130, 130, 1, 0x0030, 0x10, 16, 1),
	PIN_FIELD_BASE(131, 131, 1, 0x0030, 0x10, 19, 1),
	PIN_FIELD_BASE(132, 132, 1, 0x0030, 0x10, 21, 1),
	PIN_FIELD_BASE(133, 133, 1, 0x0030, 0x10, 20, 1),
	PIN_FIELD_BASE(134, 135, 1, 0x0030, 0x10, 2, 1),
	PIN_FIELD_BASE(136, 136, 1, 0x0030, 0x10, 7, 1),
	PIN_FIELD_BASE(137, 137, 1, 0x0030, 0x10, 4, 1),
	PIN_FIELD_BASE(138, 138, 1, 0x0030, 0x10, 6, 1),
	PIN_FIELD_BASE(139, 139, 1, 0x0030, 0x10, 5, 1),
	PIN_FIELD_BASE(140, 141, 1, 0x0030, 0x10, 0, 1),
	PIN_FIELD_BASE(142, 142, 1, 0x0030, 0x10, 15, 1),
	PIN_FIELD_BASE(143, 143, 5, 0x0020, 0x10, 15, 1),
	PIN_FIELD_BASE(144, 144, 5, 0x0020, 0x10, 17, 1),
	PIN_FIELD_BASE(145, 145, 5, 0x0020, 0x10, 16, 1),
	PIN_FIELD_BASE(146, 146, 5, 0x0020, 0x10, 12, 1),
	PIN_FIELD_BASE(147, 155, 5, 0x0020, 0x10, 0, 1),
	PIN_FIELD_BASE(156, 157, 5, 0x0020, 0x10, 22, 1),
	PIN_FIELD_BASE(158, 158, 5, 0x0020, 0x10, 21, 1),
	PIN_FIELD_BASE(159, 159, 5, 0x0020, 0x10, 24, 1),
	PIN_FIELD_BASE(160, 161, 5, 0x0020, 0x10, 19, 1),
	PIN_FIELD_BASE(162, 166, 5, 0x0020, 0x10, 25, 1),
	PIN_FIELD_BASE(167, 168, 7, 0x0010, 0x10, 1, 1),
	PIN_FIELD_BASE(169, 169, 7, 0x0010, 0x10, 4, 1),
	PIN_FIELD_BASE(170, 170, 7, 0x0010, 0x10, 6, 1),
	PIN_FIELD_BASE(171, 171, 7, 0x0010, 0x10, 8, 1),
	PIN_FIELD_BASE(172, 172, 7, 0x0010, 0x10, 3, 1),
	PIN_FIELD_BASE(173, 173, 7, 0x0010, 0x10, 7, 1),
	PIN_FIELD_BASE(174, 175, 7, 0x0010, 0x10, 9, 1),
	PIN_FIELD_BASE(176, 176, 7, 0x0010, 0x10, 0, 1),
	PIN_FIELD_BASE(177, 177, 7, 0x0010, 0x10, 5, 1),
	PIN_FIELD_BASE(178, 178, 7, 0x0010, 0x10, 11, 1),
	PIN_FIELD_BASE(179, 179, 4, 0x0020, 0x10, 13, 1),
	PIN_FIELD_BASE(180, 180, 4, 0x0020, 0x10, 10, 1),
	PIN_FIELD_BASE(181, 183, 1, 0x0030, 0x10, 22, 1),
	PIN_FIELD_BASE(184, 184, 1, 0x0030, 0x10, 12, 1),
	PIN_FIELD_BASE(185, 185, 1, 0x0030, 0x10, 11, 1),
	PIN_FIELD_BASE(186, 186, 1, 0x0030, 0x10, 13, 1),
	PIN_FIELD_BASE(187, 187, 1, 0x0030, 0x10, 10, 1),
	PIN_FIELD_BASE(188, 188, 1, 0x0030, 0x10, 14, 1),
	PIN_FIELD_BASE(189, 189, 5, 0x0020, 0x10, 9, 1),
	PIN_FIELD_BASE(190, 190, 5, 0x0020, 0x10, 18, 1),
	PIN_FIELD_BASE(191, 192, 5, 0x0020, 0x10, 13, 1),
	PIN_FIELD_BASE(193, 194, 5, 0x0020, 0x10, 10, 1),
	PIN_FIELD_BASE(195, 195, 2, 0x0050, 0x10, 30, 1),
	PIN_FIELD_BASE(196, 196, 2, 0x0050, 0x10, 25, 1),
	PIN_FIELD_BASE(197, 197, 2, 0x0060, 0x10, 3, 1),
	PIN_FIELD_BASE(198, 199, 4, 0x0020, 0x10, 14, 1),
	PIN_FIELD_BASE(200, 201, 6, 0x0040, 0x10, 6, 1),
	PIN_FIELD_BASE(202, 202, 4, 0x0020, 0x10, 9, 1),
};

static const struct mtk_pin_field_calc mt6779_pin_smt_range[] = {
	PINS_FIELD_BASE(0, 9, 6, 0x00c0, 0x10, 3, 1),
	PIN_FIELD_BASE(10, 11, 3, 0x00e0, 0x10, 0, 1),
	PINS_FIELD_BASE(12, 15, 3, 0x00e0, 0x10, 2, 1),
	PIN_FIELD_BASE(16, 16, 3, 0x00e0, 0x10, 3, 1),
	PINS_FIELD_BASE(17, 20, 6, 0x00c0, 0x10, 11, 1),
	PINS_FIELD_BASE(21, 24, 6, 0x00c0, 0x10, 7, 1),
	PIN_FIELD_BASE(25, 25, 6, 0x00c0, 0x10, 12, 1),
	PIN_FIELD_BASE(26, 26, 6, 0x00c0, 0x10, 8, 1),
	PIN_FIELD_BASE(27, 27, 6, 0x00c0, 0x10, 0, 1),
	PIN_FIELD_BASE(28, 29, 6, 0x00c0, 0x10, 9, 1),
	PINS_FIELD_BASE(30, 32, 6, 0x00c0, 0x10, 4, 1),
	PIN_FIELD_BASE(33, 33, 6, 0x00c0, 0x10, 5, 1),
	PIN_FIELD_BASE(34, 34, 6, 0x00c0, 0x10, 4, 1),
	PINS_FIELD_BASE(35, 41, 6, 0x00c0, 0x10, 13, 1),
	PIN_FIELD_BASE(42, 43, 6, 0x00c0, 0x10, 1, 1),
	PIN_FIELD_BASE(44, 44, 6, 0x00c0, 0x10, 6, 1),
	PIN_FIELD_BASE(45, 45, 3, 0x00e0, 0x10, 8, 1),
	PIN_FIELD_BASE(46, 46, 3, 0x00e0, 0x10, 13, 1),
	PINS_FIELD_BASE(47, 50, 3, 0x00e0, 0x10, 14, 1),
	PIN_FIELD_BASE(51, 51, 3, 0x00e0, 0x10, 5, 1),
	PIN_FIELD_BASE(52, 52, 3, 0x00e0, 0x10, 10, 1),
	PIN_FIELD_BASE(53, 54, 3, 0x00e0, 0x10, 15, 1),
	PIN_FIELD_BASE(55, 55, 3, 0x00e0, 0x10, 7, 1),
	PIN_FIELD_BASE(56, 56, 3, 0x00e0, 0x10, 12, 1),
	PINS_FIELD_BASE(57, 60, 3, 0x00e0, 0x10, 4, 1),
	PIN_FIELD_BASE(61, 61, 3, 0x00e0, 0x10, 6, 1),
	PIN_FIELD_BASE(62, 62, 3, 0x00e0, 0x10, 11, 1),
	PINS_FIELD_BASE(63, 66, 3, 0x00e0, 0x10, 9, 1),
	PINS_FIELD_BASE(67, 69, 2, 0x00e0, 0x10, 11, 1),
	PIN_FIELD_BASE(70, 71, 2, 0x00e0, 0x10, 10, 1),
	PINS_FIELD_BASE(72, 75, 4, 0x0070, 0x10, 1, 1),
	PINS_FIELD_BASE(76, 77, 4, 0x0070, 0x10, 4, 1),
	PINS_FIELD_BASE(78, 86, 2, 0x00e0, 0x10, 1, 1),
	PINS_FIELD_BASE(87, 92, 2, 0x00e0, 0x10, 2, 1),
	PIN_FIELD_BASE(93, 93, 4, 0x0070, 0x10, 0, 1),
	PIN_FIELD_BASE(94, 94, 2, 0x00e0, 0x10, 2, 1),
	PINS_FIELD_BASE(95, 98, 4, 0x0070, 0x10, 2, 1),
	PINS_FIELD_BASE(99, 104, 2, 0x00e0, 0x10, 12, 1),
	PINS_FIELD_BASE(105, 109, 2, 0x00e0, 0x10, 0, 1),
	PIN_FIELD_BASE(110, 110, 2, 0x00e0, 0x10, 14, 1),
	PIN_FIELD_BASE(111, 111, 2, 0x00e0, 0x10, 16, 1),
	PIN_FIELD_BASE(112, 112, 2, 0x00e0, 0x10, 13, 1),
	PIN_FIELD_BASE(113, 113, 2, 0x00e0, 0x10, 15, 1),
	PINS_FIELD_BASE(114, 115, 2, 0x00e0, 0x10, 4, 1),
	PIN_FIELD_BASE(116, 117, 2, 0x00e0, 0x10, 5, 1),
	PINS_FIELD_BASE(118, 119, 2, 0x00e0, 0x10, 4, 1),
	PIN_FIELD_BASE(120, 121, 2, 0x00e0, 0x10, 7, 1),
	PINS_FIELD_BASE(122, 125, 2, 0x00e0, 0x10, 3, 1),
	PINS_FIELD_BASE(126, 127, 1, 0x00c0, 0x10, 5, 1),
	PINS_FIELD_BASE(128, 130, 1, 0x00c0, 0x10, 9, 1),
	PINS_FIELD_BASE(131, 133, 1, 0x00c0, 0x10, 10, 1),
	PIN_FIELD_BASE(134, 135, 1, 0x00c0, 0x10, 2, 1),
	PINS_FIELD_BASE(136, 139, 1, 0x00c0, 0x10, 4, 1),
	PIN_FIELD_BASE(140, 141, 1, 0x00c0, 0x10, 0, 1),
	PIN_FIELD_BASE(142, 142, 1, 0x00c0, 0x10, 8, 1),
	PINS_FIELD_BASE(143, 146, 5, 0x0060, 0x10, 1, 1),
	PINS_FIELD_BASE(147, 155, 5, 0x0060, 0x10, 0, 1),
	PIN_FIELD_BASE(156, 157, 5, 0x0060, 0x10, 6, 1),
	PIN_FIELD_BASE(158, 158, 5, 0x0060, 0x10, 5, 1),
	PIN_FIELD_BASE(159, 159, 5, 0x0060, 0x10, 8, 1),
	PIN_FIELD_BASE(160, 161, 5, 0x0060, 0x10, 3, 1),
	PINS_FIELD_BASE(162, 166, 5, 0x0060, 0x10, 2, 1),
	PIN_FIELD_BASE(167, 167, 7, 0x0060, 0x10, 1, 1),
	PINS_FIELD_BASE(168, 174, 7, 0x0060, 0x10, 2, 1),
	PIN_FIELD_BASE(175, 175, 7, 0x0060, 0x10, 3, 1),
	PIN_FIELD_BASE(176, 176, 7, 0x0060, 0x10, 0, 1),
	PINS_FIELD_BASE(177, 178, 7, 0x0060, 0x10, 2, 1),
	PINS_FIELD_BASE(179, 180, 4, 0x0070, 0x10, 4, 1),
	PIN_FIELD_BASE(181, 183, 1, 0x00c0, 0x10, 11, 1),
	PINS_FIELD_BASE(184, 187, 1, 0x00c0, 0x10, 6, 1),
	PIN_FIELD_BASE(188, 188, 1, 0x00c0, 0x10, 7, 1),
	PINS_FIELD_BASE(189, 194, 5, 0x0060, 0x10, 1, 1),
	PIN_FIELD_BASE(195, 195, 2, 0x00e0, 0x10, 3, 1),
	PIN_FIELD_BASE(196, 196, 2, 0x00e0, 0x10, 9, 1),
	PIN_FIELD_BASE(197, 197, 2, 0x00e0, 0x10, 3, 1),
	PIN_FIELD_BASE(198, 199, 4, 0x0070, 0x10, 5, 1),
	PIN_FIELD_BASE(200, 201, 6, 0x00c0, 0x10, 14, 1),
	PIN_FIELD_BASE(202, 202, 4, 0x0070, 0x10, 3, 1),
};

static const struct mtk_pin_field_calc mt6779_pin_pu_range[] = {
	PIN_FIELD_BASE(0, 9, 6, 0x0070, 0x10, 3, 1),
	PIN_FIELD_BASE(16, 16, 3, 0x0080, 0x10, 0, 1),
	PIN_FIELD_BASE(17, 18, 6, 0x0070, 0x10, 28, 1),
	PIN_FIELD_BASE(19, 19, 6, 0x0070, 0x10, 27, 1),
	PIN_FIELD_BASE(20, 20, 6, 0x0070, 0x10, 26, 1),
	PIN_FIELD_BASE(21, 24, 6, 0x0070, 0x10, 19, 1),
	PIN_FIELD_BASE(25, 25, 6, 0x0070, 0x10, 30, 1),
	PIN_FIELD_BASE(26, 26, 6, 0x0070, 0x10, 23, 1),
	PIN_FIELD_BASE(27, 27, 6, 0x0070, 0x10, 0, 1),
	PIN_FIELD_BASE(28, 29, 6, 0x0070, 0x10, 24, 1),
	PIN_FIELD_BASE(30, 30, 6, 0x0070, 0x10, 16, 1),
	PIN_FIELD_BASE(31, 31, 6, 0x0070, 0x10, 13, 1),
	PIN_FIELD_BASE(32, 32, 6, 0x0070, 0x10, 15, 1),
	PIN_FIELD_BASE(33, 33, 6, 0x0070, 0x10, 17, 1),
	PIN_FIELD_BASE(34, 34, 6, 0x0070, 0x10, 14, 1),
	PIN_FIELD_BASE(35, 35, 6, 0x0080, 0x10, 5, 1),
	PIN_FIELD_BASE(36, 36, 6, 0x0080, 0x10, 0, 1),
	PIN_FIELD_BASE(37, 37, 6, 0x0080, 0x10, 6, 1),
	PIN_FIELD_BASE(38, 41, 6, 0x0080, 0x10, 1, 1),
	PIN_FIELD_BASE(42, 43, 6, 0x0070, 0x10, 1, 1),
	PIN_FIELD_BASE(44, 44, 6, 0x0070, 0x10, 18, 1),
	PIN_FIELD_BASE(45, 45, 3, 0x0080, 0x10, 4, 1),
	PIN_FIELD_BASE(46, 46, 3, 0x0080, 0x10, 12, 1),
	PIN_FIELD_BASE(47, 47, 3, 0x0080, 0x10, 15, 1),
	PIN_FIELD_BASE(48, 48, 3, 0x0080, 0x10, 14, 1),
	PIN_FIELD_BASE(49, 49, 3, 0x0080, 0x10, 16, 1),
	PIN_FIELD_BASE(50, 50, 3, 0x0080, 0x10, 13, 1),
	PIN_FIELD_BASE(51, 51, 3, 0x0080, 0x10, 1, 1),
	PIN_FIELD_BASE(52, 52, 3, 0x0080, 0x10, 9, 1),
	PIN_FIELD_BASE(53, 54, 3, 0x0080, 0x10, 18, 1),
	PIN_FIELD_BASE(55, 55, 3, 0x0080, 0x10, 3, 1),
	PIN_FIELD_BASE(56, 56, 3, 0x0080, 0x10, 11, 1),
	PIN_FIELD_BASE(61, 61, 3, 0x0080, 0x10, 2, 1),
	PIN_FIELD_BASE(62, 62, 3, 0x0080, 0x10, 10, 1),
	PIN_FIELD_BASE(63, 63, 3, 0x0080, 0x10, 7, 1),
	PIN_FIELD_BASE(64, 64, 3, 0x0080, 0x10, 6, 1),
	PIN_FIELD_BASE(65, 65, 3, 0x0080, 0x10, 8, 1),
	PIN_FIELD_BASE(66, 66, 3, 0x0080, 0x10, 5, 1),
	PIN_FIELD_BASE(67, 67, 2, 0x00a0, 0x10, 7, 1),
	PIN_FIELD_BASE(68, 68, 2, 0x00a0, 0x10, 6, 1),
	PIN_FIELD_BASE(69, 69, 2, 0x00a0, 0x10, 8, 1),
	PIN_FIELD_BASE(70, 71, 2, 0x00a0, 0x10, 4, 1),
	PIN_FIELD_BASE(72, 72, 4, 0x0040, 0x10, 3, 1),
	PIN_FIELD_BASE(73, 73, 4, 0x0040, 0x10, 2, 1),
	PIN_FIELD_BASE(74, 74, 4, 0x0040, 0x10, 1, 1),
	PIN_FIELD_BASE(75, 75, 4, 0x0040, 0x10, 4, 1),
	PIN_FIELD_BASE(76, 76, 4, 0x0040, 0x10, 12, 1),
	PIN_FIELD_BASE(77, 77, 4, 0x0040, 0x10, 11, 1),
	PIN_FIELD_BASE(78, 78, 2, 0x0090, 0x10, 18, 1),
	PIN_FIELD_BASE(79, 79, 2, 0x0090, 0x10, 17, 1),
	PIN_FIELD_BASE(80, 81, 2, 0x0090, 0x10, 19, 1),
	PIN_FIELD_BASE(82, 88, 2, 0x0090, 0x10, 1, 1),
	PIN_FIELD_BASE(89, 89, 2, 0x0090, 0x10, 16, 1),
	PIN_FIELD_BASE(90, 90, 2, 0x0090, 0x10, 15, 1),
	PIN_FIELD_BASE(91, 91, 2, 0x0090, 0x10, 14, 1),
	PIN_FIELD_BASE(92, 92, 2, 0x0090, 0x10, 8, 1),
	PIN_FIELD_BASE(93, 93, 4, 0x0040, 0x10, 0, 1),
	PIN_FIELD_BASE(94, 94, 2, 0x0090, 0x10, 0, 1),
	PIN_FIELD_BASE(95, 95, 4, 0x0040, 0x10, 7, 1),
	PIN_FIELD_BASE(96, 96, 4, 0x0040, 0x10, 5, 1),
	PIN_FIELD_BASE(97, 97, 4, 0x0040, 0x10, 8, 1),
	PIN_FIELD_BASE(98, 98, 4, 0x0040, 0x10, 6, 1),
	PIN_FIELD_BASE(99, 99, 2, 0x00a0, 0x10, 9, 1),
	PIN_FIELD_BASE(100, 100, 2, 0x00a0, 0x10, 12, 1),
	PIN_FIELD_BASE(101, 101, 2, 0x00a0, 0x10, 10, 1),
	PIN_FIELD_BASE(102, 102, 2, 0x00a0, 0x10, 13, 1),
	PIN_FIELD_BASE(103, 103, 2, 0x00a0, 0x10, 11, 1),
	PIN_FIELD_BASE(104, 104, 2, 0x00a0, 0x10, 14, 1),
	PIN_FIELD_BASE(105, 105, 2, 0x0090, 0x10, 10, 1),
	PIN_FIELD_BASE(106, 106, 2, 0x0090, 0x10, 9, 1),
	PIN_FIELD_BASE(107, 108, 2, 0x0090, 0x10, 12, 1),
	PIN_FIELD_BASE(109, 109, 2, 0x0090, 0x10, 11, 1),
	PIN_FIELD_BASE(110, 110, 2, 0x00a0, 0x10, 16, 1),
	PIN_FIELD_BASE(111, 111, 2, 0x00a0, 0x10, 18, 1),
	PIN_FIELD_BASE(112, 112, 2, 0x00a0, 0x10, 15, 1),
	PIN_FIELD_BASE(113, 113, 2, 0x00a0, 0x10, 17, 1),
	PIN_FIELD_BASE(114, 115, 2, 0x0090, 0x10, 26, 1),
	PIN_FIELD_BASE(116, 117, 2, 0x0090, 0x10, 21, 1),
	PIN_FIELD_BASE(118, 118, 2, 0x0090, 0x10, 31, 1),
	PIN_FIELD_BASE(119, 119, 2, 0x00a0, 0x10, 0, 1),
	PIN_FIELD_BASE(120, 121, 2, 0x0090, 0x10, 23, 1),
	PIN_FIELD_BASE(122, 123, 2, 0x0090, 0x10, 28, 1),
	PIN_FIELD_BASE(124, 125, 2, 0x00a0, 0x10, 1, 1),
	PIN_FIELD_BASE(126, 127, 1, 0x0070, 0x10, 2, 1),
	PIN_FIELD_BASE(140, 141, 1, 0x0070, 0x10, 0, 1),
	PIN_FIELD_BASE(142, 142, 1, 0x0070, 0x10, 9, 1),
	PIN_FIELD_BASE(143, 143, 5, 0x0040, 0x10, 15, 1),
	PIN_FIELD_BASE(144, 144, 5, 0x0040, 0x10, 17, 1),
	PIN_FIELD_BASE(145, 145, 5, 0x0040, 0x10, 16, 1),
	PIN_FIELD_BASE(146, 146, 5, 0x0040, 0x10, 12, 1),
	PIN_FIELD_BASE(147, 155, 5, 0x0040, 0x10, 0, 1),
	PIN_FIELD_BASE(156, 157, 5, 0x0040, 0x10, 22, 1),
	PIN_FIELD_BASE(158, 158, 5, 0x0040, 0x10, 21, 1),
	PIN_FIELD_BASE(159, 159, 5, 0x0040, 0x10, 24, 1),
	PIN_FIELD_BASE(160, 161, 5, 0x0040, 0x10, 19, 1),
	PIN_FIELD_BASE(162, 166, 5, 0x0040, 0x10, 25, 1),
	PIN_FIELD_BASE(179, 179, 4, 0x0040, 0x10, 13, 1),
	PIN_FIELD_BASE(180, 180, 4, 0x0040, 0x10, 10, 1),
	PIN_FIELD_BASE(181, 183, 1, 0x0070, 0x10, 10, 1),
	PIN_FIELD_BASE(184, 184, 1, 0x0070, 0x10, 6, 1),
	PIN_FIELD_BASE(185, 185, 1, 0x0070, 0x10, 5, 1),
	PIN_FIELD_BASE(186, 186, 1, 0x0070, 0x10, 7, 1),
	PIN_FIELD_BASE(187, 187, 1, 0x0070, 0x10, 4, 1),
	PIN_FIELD_BASE(188, 188, 1, 0x0070, 0x10, 8, 1),
	PIN_FIELD_BASE(189, 189, 5, 0x0040, 0x10, 9, 1),
	PIN_FIELD_BASE(190, 190, 5, 0x0040, 0x10, 18, 1),
	PIN_FIELD_BASE(191, 192, 5, 0x0040, 0x10, 13, 1),
	PIN_FIELD_BASE(193, 194, 5, 0x0040, 0x10, 10, 1),
	PIN_FIELD_BASE(195, 195, 2, 0x0090, 0x10, 30, 1),
	PIN_FIELD_BASE(196, 196, 2, 0x0090, 0x10, 25, 1),
	PIN_FIELD_BASE(197, 197, 2, 0x00a0, 0x10, 3, 1),
	PIN_FIELD_BASE(198, 199, 4, 0x0040, 0x10, 14, 1),
	PIN_FIELD_BASE(200, 201, 6, 0x0080, 0x10, 7, 1),
	PIN_FIELD_BASE(202, 202, 4, 0x0040, 0x10, 9, 1),
};

static const struct mtk_pin_field_calc mt6779_pin_pd_range[] = {
	PIN_FIELD_BASE(0, 9, 6, 0x0050, 0x10, 3, 1),
	PIN_FIELD_BASE(16, 16, 3, 0x0060, 0x10, 0, 1),
	PIN_FIELD_BASE(17, 18, 6, 0x0050, 0x10, 28, 1),
	PIN_FIELD_BASE(19, 19, 6, 0x0050, 0x10, 27, 1),
	PIN_FIELD_BASE(20, 20, 6, 0x0050, 0x10, 26, 1),
	PIN_FIELD_BASE(21, 24, 6, 0x0050, 0x10, 19, 1),
	PIN_FIELD_BASE(25, 25, 6, 0x0050, 0x10, 30, 1),
	PIN_FIELD_BASE(26, 26, 6, 0x0050, 0x10, 23, 1),
	PIN_FIELD_BASE(27, 27, 6, 0x0050, 0x10, 0, 1),
	PIN_FIELD_BASE(28, 29, 6, 0x0050, 0x10, 24, 1),
	PIN_FIELD_BASE(30, 30, 6, 0x0050, 0x10, 16, 1),
	PIN_FIELD_BASE(31, 31, 6, 0x0050, 0x10, 13, 1),
	PIN_FIELD_BASE(32, 32, 6, 0x0050, 0x10, 15, 1),
	PIN_FIELD_BASE(33, 33, 6, 0x0050, 0x10, 17, 1),
	PIN_FIELD_BASE(34, 34, 6, 0x0050, 0x10, 14, 1),
	PIN_FIELD_BASE(35, 35, 6, 0x0060, 0x10, 5, 1),
	PIN_FIELD_BASE(36, 36, 6, 0x0060, 0x10, 0, 1),
	PIN_FIELD_BASE(37, 37, 6, 0x0060, 0x10, 6, 1),
	PIN_FIELD_BASE(38, 41, 6, 0x0060, 0x10, 1, 1),
	PIN_FIELD_BASE(42, 43, 6, 0x0050, 0x10, 1, 1),
	PIN_FIELD_BASE(44, 44, 6, 0x0050, 0x10, 18, 1),
	PIN_FIELD_BASE(45, 45, 3, 0x0060, 0x10, 4, 1),
	PIN_FIELD_BASE(46, 46, 3, 0x0060, 0x10, 12, 1),
	PIN_FIELD_BASE(47, 47, 3, 0x0060, 0x10, 15, 1),
	PIN_FIELD_BASE(48, 48, 3, 0x0060, 0x10, 14, 1),
	PIN_FIELD_BASE(49, 49, 3, 0x0060, 0x10, 16, 1),
	PIN_FIELD_BASE(50, 50, 3, 0x0060, 0x10, 13, 1),
	PIN_FIELD_BASE(51, 51, 3, 0x0060, 0x10, 1, 1),
	PIN_FIELD_BASE(52, 52, 3, 0x0060, 0x10, 9, 1),
	PIN_FIELD_BASE(53, 54, 3, 0x0060, 0x10, 18, 1),
	PIN_FIELD_BASE(55, 55, 3, 0x0060, 0x10, 3, 1),
	PIN_FIELD_BASE(56, 56, 3, 0x0060, 0x10, 11, 1),
	PIN_FIELD_BASE(61, 61, 3, 0x0060, 0x10, 2, 1),
	PIN_FIELD_BASE(62, 62, 3, 0x0060, 0x10, 10, 1),
	PIN_FIELD_BASE(63, 63, 3, 0x0060, 0x10, 7, 1),
	PIN_FIELD_BASE(64, 64, 3, 0x0060, 0x10, 6, 1),
	PIN_FIELD_BASE(65, 65, 3, 0x0060, 0x10, 8, 1),
	PIN_FIELD_BASE(66, 66, 3, 0x0060, 0x10, 5, 1),
	PIN_FIELD_BASE(67, 67, 2, 0x0080, 0x10, 7, 1),
	PIN_FIELD_BASE(68, 68, 2, 0x0080, 0x10, 6, 1),
	PIN_FIELD_BASE(69, 69, 2, 0x0080, 0x10, 8, 1),
	PIN_FIELD_BASE(70, 71, 2, 0x0080, 0x10, 4, 1),
	PIN_FIELD_BASE(72, 72, 4, 0x0030, 0x10, 3, 1),
	PIN_FIELD_BASE(73, 73, 4, 0x0030, 0x10, 2, 1),
	PIN_FIELD_BASE(74, 74, 4, 0x0030, 0x10, 1, 1),
	PIN_FIELD_BASE(75, 75, 4, 0x0030, 0x10, 4, 1),
	PIN_FIELD_BASE(76, 76, 4, 0x0030, 0x10, 12, 1),
	PIN_FIELD_BASE(77, 77, 4, 0x0030, 0x10, 11, 1),
	PIN_FIELD_BASE(78, 78, 2, 0x0070, 0x10, 18, 1),
	PIN_FIELD_BASE(79, 79, 2, 0x0070, 0x10, 17, 1),
	PIN_FIELD_BASE(80, 81, 2, 0x0070, 0x10, 19, 1),
	PIN_FIELD_BASE(82, 88, 2, 0x0070, 0x10, 1, 1),
	PIN_FIELD_BASE(89, 89, 2, 0x0070, 0x10, 16, 1),
	PIN_FIELD_BASE(90, 90, 2, 0x0070, 0x10, 15, 1),
	PIN_FIELD_BASE(91, 91, 2, 0x0070, 0x10, 14, 1),
	PIN_FIELD_BASE(92, 92, 2, 0x0070, 0x10, 8, 1),
	PIN_FIELD_BASE(93, 93, 4, 0x0030, 0x10, 0, 1),
	PIN_FIELD_BASE(94, 94, 2, 0x0070, 0x10, 0, 1),
	PIN_FIELD_BASE(95, 95, 4, 0x0030, 0x10, 7, 1),
	PIN_FIELD_BASE(96, 96, 4, 0x0030, 0x10, 5, 1),
	PIN_FIELD_BASE(97, 97, 4, 0x0030, 0x10, 8, 1),
	PIN_FIELD_BASE(98, 98, 4, 0x0030, 0x10, 6, 1),
	PIN_FIELD_BASE(99, 99, 2, 0x0080, 0x10, 9, 1),
	PIN_FIELD_BASE(100, 100, 2, 0x0080, 0x10, 12, 1),
	PIN_FIELD_BASE(101, 101, 2, 0x0080, 0x10, 10, 1),
	PIN_FIELD_BASE(102, 102, 2, 0x0080, 0x10, 13, 1),
	PIN_FIELD_BASE(103, 103, 2, 0x0080, 0x10, 11, 1),
	PIN_FIELD_BASE(104, 104, 2, 0x0080, 0x10, 14, 1),
	PIN_FIELD_BASE(105, 105, 2, 0x0070, 0x10, 10, 1),
	PIN_FIELD_BASE(106, 106, 2, 0x0070, 0x10, 9, 1),
	PIN_FIELD_BASE(107, 108, 2, 0x0070, 0x10, 12, 1),
	PIN_FIELD_BASE(109, 109, 2, 0x0070, 0x10, 11, 1),
	PIN_FIELD_BASE(110, 110, 2, 0x0080, 0x10, 16, 1),
	PIN_FIELD_BASE(111, 111, 2, 0x0080, 0x10, 18, 1),
	PIN_FIELD_BASE(112, 112, 2, 0x0080, 0x10, 15, 1),
	PIN_FIELD_BASE(113, 113, 2, 0x0080, 0x10, 17, 1),
	PIN_FIELD_BASE(114, 115, 2, 0x0070, 0x10, 26, 1),
	PIN_FIELD_BASE(116, 117, 2, 0x0070, 0x10, 21, 1),
	PIN_FIELD_BASE(118, 118, 2, 0x0070, 0x10, 31, 1),
	PIN_FIELD_BASE(119, 119, 2, 0x0080, 0x10, 0, 1),
	PIN_FIELD_BASE(120, 121, 2, 0x0070, 0x10, 23, 1),
	PIN_FIELD_BASE(122, 123, 2, 0x0070, 0x10, 28, 1),
	PIN_FIELD_BASE(124, 125, 2, 0x0080, 0x10, 1, 1),
	PIN_FIELD_BASE(126, 127, 1, 0x0050, 0x10, 2, 1),
	PIN_FIELD_BASE(140, 141, 1, 0x0050, 0x10, 0, 1),
	PIN_FIELD_BASE(142, 142, 1, 0x0050, 0x10, 9, 1),
	PIN_FIELD_BASE(143, 143, 5, 0x0030, 0x10, 15, 1),
	PIN_FIELD_BASE(144, 144, 5, 0x0030, 0x10, 17, 1),
	PIN_FIELD_BASE(145, 145, 5, 0x0030, 0x10, 16, 1),
	PIN_FIELD_BASE(146, 146, 5, 0x0030, 0x10, 12, 1),
	PIN_FIELD_BASE(147, 155, 5, 0x0030, 0x10, 0, 1),
	PIN_FIELD_BASE(156, 157, 5, 0x0030, 0x10, 22, 1),
	PIN_FIELD_BASE(158, 158, 5, 0x0030, 0x10, 21, 1),
	PIN_FIELD_BASE(159, 159, 5, 0x0030, 0x10, 24, 1),
	PIN_FIELD_BASE(160, 161, 5, 0x0030, 0x10, 19, 1),
	PIN_FIELD_BASE(162, 166, 5, 0x0030, 0x10, 25, 1),
	PIN_FIELD_BASE(179, 179, 4, 0x0030, 0x10, 13, 1),
	PIN_FIELD_BASE(180, 180, 4, 0x0030, 0x10, 10, 1),
	PIN_FIELD_BASE(181, 183, 1, 0x0050, 0x10, 10, 1),
	PIN_FIELD_BASE(184, 184, 1, 0x0050, 0x10, 6, 1),
	PIN_FIELD_BASE(185, 185, 1, 0x0050, 0x10, 5, 1),
	PIN_FIELD_BASE(186, 186, 1, 0x0050, 0x10, 7, 1),
	PIN_FIELD_BASE(187, 187, 1, 0x0050, 0x10, 4, 1),
	PIN_FIELD_BASE(188, 188, 1, 0x0050, 0x10, 8, 1),
	PIN_FIELD_BASE(189, 189, 5, 0x0030, 0x10, 9, 1),
	PIN_FIELD_BASE(190, 190, 5, 0x0030, 0x10, 18, 1),
	PIN_FIELD_BASE(191, 192, 5, 0x0030, 0x10, 13, 1),
	PIN_FIELD_BASE(193, 194, 5, 0x0030, 0x10, 10, 1),
	PIN_FIELD_BASE(195, 195, 2, 0x0070, 0x10, 30, 1),
	PIN_FIELD_BASE(196, 196, 2, 0x0070, 0x10, 25, 1),
	PIN_FIELD_BASE(197, 197, 2, 0x0080, 0x10, 3, 1),
	PIN_FIELD_BASE(198, 199, 4, 0x0030, 0x10, 14, 1),
	PIN_FIELD_BASE(200, 201, 6, 0x0060, 0x10, 7, 1),
	PIN_FIELD_BASE(202, 202, 4, 0x0030, 0x10, 9, 1),
};

static const struct mtk_pin_field_calc mt6779_pin_drv_range[] = {
	PINS_FIELD_BASE(0, 9, 6, 0x0000, 0x10, 9, 3),
	PIN_FIELD_BASE(10, 16, 3, 0x0000, 0x10, 0, 3),
	PINS_FIELD_BASE(17, 19, 6, 0x0010, 0x10, 3, 3),
	PIN_FIELD_BASE(20, 20, 6, 0x0010, 0x10, 6, 3),
	PINS_FIELD_BASE(21, 24, 6, 0x0000, 0x10, 21, 3),
	PIN_FIELD_BASE(25, 25, 6, 0x0010, 0x10, 9, 3),
	PIN_FIELD_BASE(26, 26, 6, 0x0000, 0x10, 24, 3),
	PIN_FIELD_BASE(27, 27, 6, 0x0000, 0x10, 0, 3),
	PIN_FIELD_BASE(28, 28, 6, 0x0000, 0x10, 27, 3),
	PIN_FIELD_BASE(29, 29, 6, 0x0010, 0x10, 0, 3),
	PINS_FIELD_BASE(30, 32, 6, 0x0000, 0x10, 12, 3),
	PIN_FIELD_BASE(33, 33, 6, 0x0000, 0x10, 15, 3),
	PIN_FIELD_BASE(34, 34, 6, 0x0000, 0x10, 12, 3),
	PINS_FIELD_BASE(35, 41, 6, 0x0010, 0x10, 12, 3),
	PIN_FIELD_BASE(42, 43, 6, 0x0000, 0x10, 3, 3),
	PIN_FIELD_BASE(44, 44, 6, 0x0000, 0x10, 18, 3),
	PIN_FIELD_BASE(45, 45, 3, 0x0010, 0x10, 12, 3),
	PIN_FIELD_BASE(46, 46, 3, 0x0020, 0x10, 0, 3),
	PINS_FIELD_BASE(47, 49, 3, 0x0020, 0x10, 3, 3),
	PIN_FIELD_BASE(50, 50, 3, 0x0020, 0x10, 6, 3),
	PIN_FIELD_BASE(51, 51, 3, 0x0010, 0x10, 3, 3),
	PIN_FIELD_BASE(52, 52, 3, 0x0010, 0x10, 21, 3),
	PINS_FIELD_BASE(53, 54, 3, 0x0020, 0x10, 9, 3),
	PIN_FIELD_BASE(55, 55, 3, 0x0010, 0x10, 9, 3),
	PIN_FIELD_BASE(56, 56, 3, 0x0010, 0x10, 27, 3),
	PIN_FIELD_BASE(57, 57, 3, 0x0010, 0x10, 0, 3),
	PIN_FIELD_BASE(58, 58, 3, 0x0000, 0x10, 27, 3),
	PIN_FIELD_BASE(59, 60, 3, 0x0000, 0x10, 21, 3),
	PIN_FIELD_BASE(61, 61, 3, 0x0010, 0x10, 6, 3),
	PIN_FIELD_BASE(62, 62, 3, 0x0010, 0x10, 24, 3),
	PINS_FIELD_BASE(63, 65, 3, 0x0010, 0x10, 15, 3),
	PIN_FIELD_BASE(66, 66, 3, 0x0010, 0x10, 18, 3),
	PINS_FIELD_BASE(67, 69, 2, 0x0010, 0x10, 3, 3),
	PIN_FIELD_BASE(70, 71, 2, 0x0010, 0x10, 0, 3),
	PINS_FIELD_BASE(72, 75, 4, 0x0000, 0x10, 0, 3),
	PINS_FIELD_BASE(76, 77, 4, 0x0000, 0x10, 15, 3),
	PINS_FIELD_BASE(78, 86, 2, 0x0000, 0x10, 3, 3),
	PINS_FIELD_BASE(87, 92, 2, 0x0000, 0x10, 6, 3),
	PIN_FIELD_BASE(93, 93, 4, 0x0000, 0x10, 3, 3),
	PIN_FIELD_BASE(94, 94, 2, 0x0000, 0x10, 6, 3),
	PINS_FIELD_BASE(95, 96, 4, 0x0000, 0x10, 6, 3),
	PINS_FIELD_BASE(97, 98, 4, 0x0000, 0x10, 9, 3),
	PINS_FIELD_BASE(99, 100, 2, 0x0010, 0x10, 6, 3),
	PINS_FIELD_BASE(101, 102, 2, 0x0010, 0x10, 9, 3),
	PINS_FIELD_BASE(103, 104, 2, 0x0010, 0x10, 12, 3),
	PINS_FIELD_BASE(105, 109, 2, 0x0000, 0x10, 0, 3),
	PIN_FIELD_BASE(110, 110, 2, 0x0010, 0x10, 18, 3),
	PIN_FIELD_BASE(111, 111, 2, 0x0010, 0x10, 24, 3),
	PIN_FIELD_BASE(112, 112, 2, 0x0010, 0x10, 15, 3),
	PIN_FIELD_BASE(113, 113, 2, 0x0010, 0x10, 21, 3),
	PINS_FIELD_BASE(114, 115, 2, 0x0000, 0x10, 12, 3),
	PIN_FIELD_BASE(116, 117, 2, 0x0000, 0x10, 15, 3),
	PINS_FIELD_BASE(118, 119, 2, 0x0000, 0x10, 12, 3),
	PIN_FIELD_BASE(120, 121, 2, 0x0000, 0x10, 21, 3),
	PINS_FIELD_BASE(122, 125, 2, 0x0000, 0x10, 9, 3),
	PINS_FIELD_BASE(126, 127, 1, 0x0000, 0x10, 12, 3),
	PIN_FIELD_BASE(128, 128, 1, 0x0000, 0x10, 29, 2),
	PIN_FIELD_BASE(129, 129, 1, 0x0010, 0x10, 0, 2),
	PIN_FIELD_BASE(130, 130, 1, 0x0000, 0x10, 27, 2),
	PIN_FIELD_BASE(131, 131, 1, 0x0010, 0x10, 2, 2),
	PIN_FIELD_BASE(132, 132, 1, 0x0010, 0x10, 6, 2),
	PIN_FIELD_BASE(133, 133, 1, 0x0010, 0x10, 4, 2),
	PIN_FIELD_BASE(134, 135, 1, 0x0000, 0x10, 3, 3),
	PINS_FIELD_BASE(136, 139, 1, 0x0000, 0x10, 9, 3),
	PINS_FIELD_BASE(140, 141, 1, 0x0000, 0x10, 0, 3),
	PIN_FIELD_BASE(142, 142, 1, 0x0000, 0x10, 24, 3),
	PINS_FIELD_BASE(143, 146, 5, 0x0000, 0x10, 3, 3),
	PINS_FIELD_BASE(147, 155, 5, 0x0000, 0x10, 0, 3),
	PIN_FIELD_BASE(156, 157, 5, 0x0000, 0x10, 21, 3),
	PIN_FIELD_BASE(158, 158, 5, 0x0000, 0x10, 15, 3),
	PIN_FIELD_BASE(159, 159, 5, 0x0000, 0x10, 27, 3),
	PIN_FIELD_BASE(160, 161, 5, 0x0000, 0x10, 9, 3),
	PINS_FIELD_BASE(162, 166, 5, 0x0000, 0x10, 18, 3),
	PIN_FIELD_BASE(167, 167, 7, 0x0000, 0x10, 3, 3),
	PINS_FIELD_BASE(168, 174, 7, 0x0000, 0x10, 6, 3),
	PIN_FIELD_BASE(175, 175, 7, 0x0000, 0x10, 9, 3),
	PIN_FIELD_BASE(176, 176, 7, 0x0000, 0x10, 0, 3),
	PINS_FIELD_BASE(177, 178, 7, 0x0000, 0x10, 6, 3),
	PIN_FIELD_BASE(179, 180, 4, 0x0000, 0x10, 15, 3),
	PIN_FIELD_BASE(181, 183, 1, 0x0010, 0x10, 8, 3),
	PINS_FIELD_BASE(184, 186, 1, 0x0000, 0x10, 15, 3),
	PIN_FIELD_BASE(187, 188, 1, 0x0000, 0x10, 18, 3),
	PIN_FIELD_BASE(189, 189, 5, 0x0000, 0x10, 6, 3),
	PINS_FIELD_BASE(190, 194, 5, 0x0000, 0x10, 3, 3),
	PIN_FIELD_BASE(195, 195, 2, 0x0000, 0x10, 9, 3),
	PIN_FIELD_BASE(196, 196, 2, 0x0000, 0x10, 27, 3),
	PIN_FIELD_BASE(197, 197, 2, 0x0000, 0x10, 9, 3),
	PIN_FIELD_BASE(198, 199, 4, 0x0000, 0x10, 21, 3),
	PINS_FIELD_BASE(200, 201, 6, 0x0010, 0x10, 15, 3),
	PIN_FIELD_BASE(202, 202, 4, 0x0000, 0x10, 12, 3),
};

static const struct mtk_pin_field_calc mt6779_pin_pupd_range[] = {
	PIN_FIELD_BASE(10, 15, 3, 0x0070, 0x10, 0, 1),
	PIN_FIELD_BASE(57, 57, 3, 0x0070, 0x10, 9, 1),
	PIN_FIELD_BASE(58, 58, 3, 0x0070, 0x10, 8, 1),
	PIN_FIELD_BASE(59, 60, 3, 0x0070, 0x10, 6, 1),
	PIN_FIELD_BASE(128, 129, 1, 0x0060, 0x10, 7, 1),
	PIN_FIELD_BASE(130, 130, 1, 0x0060, 0x10, 6, 1),
	PIN_FIELD_BASE(131, 131, 1, 0x0060, 0x10, 9, 1),
	PIN_FIELD_BASE(132, 132, 1, 0x0060, 0x10, 11, 1),
	PIN_FIELD_BASE(133, 133, 1, 0x0060, 0x10, 10, 1),
	PIN_FIELD_BASE(134, 135, 1, 0x0060, 0x10, 0, 1),
	PIN_FIELD_BASE(136, 136, 1, 0x0060, 0x10, 5, 1),
	PIN_FIELD_BASE(137, 137, 1, 0x0060, 0x10, 2, 1),
	PIN_FIELD_BASE(138, 138, 1, 0x0060, 0x10, 4, 1),
	PIN_FIELD_BASE(139, 139, 1, 0x0060, 0x10, 3, 1),
	PIN_FIELD_BASE(167, 168, 7, 0x0020, 0x10, 1, 1),
	PIN_FIELD_BASE(169, 169, 7, 0x0020, 0x10, 4, 1),
	PIN_FIELD_BASE(170, 170, 7, 0x0020, 0x10, 6, 1),
	PIN_FIELD_BASE(171, 171, 7, 0x0020, 0x10, 8, 1),
	PIN_FIELD_BASE(172, 172, 7, 0x0020, 0x10, 3, 1),
	PIN_FIELD_BASE(173, 173, 7, 0x0020, 0x10, 7, 1),
	PIN_FIELD_BASE(174, 175, 7, 0x0020, 0x10, 9, 1),
	PIN_FIELD_BASE(176, 176, 7, 0x0020, 0x10, 0, 1),
	PIN_FIELD_BASE(177, 177, 7, 0x0020, 0x10, 5, 1),
	PIN_FIELD_BASE(178, 178, 7, 0x0020, 0x10, 11, 1),
};

static const struct mtk_pin_field_calc mt6779_pin_r0_range[] = {
	PIN_FIELD_BASE(10, 15, 3, 0x0090, 0x10, 0, 1),
	PIN_FIELD_BASE(57, 57, 3, 0x0090, 0x10, 9, 1),
	PIN_FIELD_BASE(58, 58, 3, 0x0090, 0x10, 8, 1),
	PIN_FIELD_BASE(59, 60, 3, 0x0090, 0x10, 6, 1),
	PIN_FIELD_BASE(128, 129, 1, 0x0080, 0x10, 7, 1),
	PIN_FIELD_BASE(130, 130, 1, 0x0080, 0x10, 6, 1),
	PIN_FIELD_BASE(131, 131, 1, 0x0080, 0x10, 9, 1),
	PIN_FIELD_BASE(132, 132, 1, 0x0080, 0x10, 11, 1),
	PIN_FIELD_BASE(133, 133, 1, 0x0080, 0x10, 10, 1),
	PIN_FIELD_BASE(134, 135, 1, 0x0080, 0x10, 0, 1),
	PIN_FIELD_BASE(136, 136, 1, 0x0080, 0x10, 5, 1),
	PIN_FIELD_BASE(137, 137, 1, 0x0080, 0x10, 2, 1),
	PIN_FIELD_BASE(138, 138, 1, 0x0080, 0x10, 4, 1),
	PIN_FIELD_BASE(139, 139, 1, 0x0080, 0x10, 3, 1),
	PIN_FIELD_BASE(167, 168, 7, 0x0030, 0x10, 1, 1),
	PIN_FIELD_BASE(169, 169, 7, 0x0030, 0x10, 4, 1),
	PIN_FIELD_BASE(170, 170, 7, 0x0030, 0x10, 6, 1),
	PIN_FIELD_BASE(171, 171, 7, 0x0030, 0x10, 8, 1),
	PIN_FIELD_BASE(172, 172, 7, 0x0030, 0x10, 3, 1),
	PIN_FIELD_BASE(173, 173, 7, 0x0030, 0x10, 7, 1),
	PIN_FIELD_BASE(174, 175, 7, 0x0030, 0x10, 9, 1),
	PIN_FIELD_BASE(176, 176, 7, 0x0030, 0x10, 0, 1),
	PIN_FIELD_BASE(177, 177, 7, 0x0030, 0x10, 5, 1),
	PIN_FIELD_BASE(178, 178, 7, 0x0030, 0x10, 11, 1),
};

static const struct mtk_pin_field_calc mt6779_pin_r1_range[] = {
	PIN_FIELD_BASE(10, 15, 3, 0x00a0, 0x10, 0, 1),
	PIN_FIELD_BASE(57, 57, 3, 0x00a0, 0x10, 9, 1),
	PIN_FIELD_BASE(58, 58, 3, 0x00a0, 0x10, 8, 1),
	PIN_FIELD_BASE(59, 60, 3, 0x00a0, 0x10, 6, 1),
	PIN_FIELD_BASE(128, 129, 1, 0x0090, 0x10, 7, 1),
	PIN_FIELD_BASE(130, 130, 1, 0x0090, 0x10, 6, 1),
	PIN_FIELD_BASE(131, 131, 1, 0x0090, 0x10, 9, 1),
	PIN_FIELD_BASE(132, 132, 1, 0x0090, 0x10, 11, 1),
	PIN_FIELD_BASE(133, 133, 1, 0x0090, 0x10, 10, 1),
	PIN_FIELD_BASE(134, 135, 1, 0x0090, 0x10, 0, 1),
	PIN_FIELD_BASE(136, 136, 1, 0x0090, 0x10, 5, 1),
	PIN_FIELD_BASE(137, 137, 1, 0x0090, 0x10, 2, 1),
	PIN_FIELD_BASE(138, 138, 1, 0x0090, 0x10, 4, 1),
	PIN_FIELD_BASE(139, 139, 1, 0x0090, 0x10, 3, 1),
	PIN_FIELD_BASE(167, 168, 7, 0x0040, 0x10, 1, 1),
	PIN_FIELD_BASE(169, 169, 7, 0x0040, 0x10, 4, 1),
	PIN_FIELD_BASE(170, 170, 7, 0x0040, 0x10, 6, 1),
	PIN_FIELD_BASE(171, 171, 7, 0x0040, 0x10, 8, 1),
	PIN_FIELD_BASE(172, 172, 7, 0x0040, 0x10, 3, 1),
	PIN_FIELD_BASE(173, 173, 7, 0x0040, 0x10, 7, 1),
	PIN_FIELD_BASE(174, 175, 7, 0x0040, 0x10, 9, 1),
	PIN_FIELD_BASE(176, 176, 7, 0x0040, 0x10, 0, 1),
	PIN_FIELD_BASE(177, 177, 7, 0x0040, 0x10, 5, 1),
	PIN_FIELD_BASE(178, 178, 7, 0x0040, 0x10, 11, 1),
};

static const struct mtk_pin_reg_calc mt6779_reg_cals[PINCTRL_PIN_REG_MAX] = {
	[PINCTRL_PIN_REG_MODE] = MTK_RANGE(mt6779_pin_mode_range),
	[PINCTRL_PIN_REG_DIR] = MTK_RANGE(mt6779_pin_dir_range),
	[PINCTRL_PIN_REG_DI] = MTK_RANGE(mt6779_pin_di_range),
	[PINCTRL_PIN_REG_DO] = MTK_RANGE(mt6779_pin_do_range),
	[PINCTRL_PIN_REG_SMT] = MTK_RANGE(mt6779_pin_smt_range),
	[PINCTRL_PIN_REG_IES] = MTK_RANGE(mt6779_pin_ies_range),
	[PINCTRL_PIN_REG_PU] = MTK_RANGE(mt6779_pin_pu_range),
	[PINCTRL_PIN_REG_PD] = MTK_RANGE(mt6779_pin_pd_range),
	[PINCTRL_PIN_REG_DRV] = MTK_RANGE(mt6779_pin_drv_range),
	[PINCTRL_PIN_REG_PUPD] = MTK_RANGE(mt6779_pin_pupd_range),
	[PINCTRL_PIN_REG_R0] = MTK_RANGE(mt6779_pin_r0_range),
	[PINCTRL_PIN_REG_R1] = MTK_RANGE(mt6779_pin_r1_range),
};

static const char * const mt6779_pinctrl_register_base_names[] = {
	"gpio", "iocfg_rm", "iocfg_br", "iocfg_lm", "iocfg_lb",
	"iocfg_rt", "iocfg_lt", "iocfg_tl",
};

static const struct mtk_eint_hw mt6779_eint_hw = {
	.port_mask = 7,
	.ports     = 6,
	.ap_num    = 195,
	.db_cnt    = 13,
};

static const struct mtk_pin_soc mt6779_data = {
	.reg_cal = mt6779_reg_cals,
	.pins = mtk_pins_mt6779,
	.npins = ARRAY_SIZE(mtk_pins_mt6779),
	.ngrps = ARRAY_SIZE(mtk_pins_mt6779),
	.eint_hw = &mt6779_eint_hw,
	.gpio_m = 0,
	.ies_present = true,
	.base_names = mt6779_pinctrl_register_base_names,
	.nbase_names = ARRAY_SIZE(mt6779_pinctrl_register_base_names),
	.bias_set_combo = mtk_pinconf_bias_set_combo,
	.bias_get_combo = mtk_pinconf_bias_get_combo,
	.drive_set = mtk_pinconf_drive_set_raw,
	.drive_get = mtk_pinconf_drive_get_raw,
	.adv_pull_get = mtk_pinconf_adv_pull_get,
	.adv_pull_set = mtk_pinconf_adv_pull_set,
};

static const struct of_device_id mt6779_pinctrl_of_match[] = {
	{ .compatible = "mediatek,mt6779-pinctrl", },
	{ }
};

static int mt6779_pinctrl_probe(struct platform_device *pdev)
{
	return mtk_paris_pinctrl_probe(pdev, &mt6779_data);
}

static struct platform_driver mt6779_pinctrl_driver = {
	.driver = {
		.name = "mt6779-pinctrl",
		.of_match_table = mt6779_pinctrl_of_match,
	},
	.probe = mt6779_pinctrl_probe,
};

static int __init mt6779_pinctrl_init(void)
{
	return platform_driver_register(&mt6779_pinctrl_driver);
}
arch_initcall(mt6779_pinctrl_init);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("MediaTek MT6779 Pinctrl Driver");
