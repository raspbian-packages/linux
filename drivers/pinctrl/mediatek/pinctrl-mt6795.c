// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022 Collabora Ltd.
 * Author: AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>
 */

#include "pinctrl-mtk-mt6795.h"
#include "pinctrl-paris.h"

#define PIN_FIELD15(_s_pin, _e_pin, _s_addr, _x_addrs, _s_bit, _x_bits)	\
	PIN_FIELD_CALC(_s_pin, _e_pin, 0, _s_addr, _x_addrs, _s_bit,	\
		       _x_bits, 15, 0)

#define PIN_FIELD16(_s_pin, _e_pin, _s_addr, _x_addrs, _s_bit, _x_bits)	\
	PIN_FIELD_CALC(_s_pin, _e_pin, 0, _s_addr, _x_addrs, _s_bit,	\
		       _x_bits, 16, 0)

#define PINS_FIELD16(_s_pin, _e_pin, _s_addr, _x_addrs, _s_bit, _x_bits)\
	PIN_FIELD_CALC(_s_pin, _e_pin, 0, _s_addr, _x_addrs, _s_bit,	\
		       _x_bits, 16, 1)

static const struct mtk_pin_field_calc mt6795_pin_dir_range[] = {
	PIN_FIELD16(0, 196, 0x0, 0x10, 0, 1),
};

static const struct mtk_pin_field_calc mt6795_pin_pullen_range[] = {
	PIN_FIELD16(0, 196, 0x100, 0x10, 0, 1),
};

static const struct mtk_pin_field_calc mt6795_pin_pullsel_range[] = {
	PIN_FIELD16(0, 196, 0x200, 0x10, 0, 1),
};

static const struct mtk_pin_field_calc mt6795_pin_do_range[] = {
	PIN_FIELD16(0, 196, 0x400, 0x10, 0, 1),
};

static const struct mtk_pin_field_calc mt6795_pin_di_range[] = {
	PIN_FIELD16(0, 196, 0x500, 0x10, 0, 1),
};

static const struct mtk_pin_field_calc mt6795_pin_mode_range[] = {
	PIN_FIELD15(0, 196, 0x600, 0x10, 0, 3),
};

static const struct mtk_pin_field_calc mt6795_pin_ies_range[] = {
	PINS_FIELD16(0, 4, 0x900, 0x10, 1, 1),
	PINS_FIELD16(5, 9, 0x900, 0x10, 2, 1),
	PINS_FIELD16(10, 15, 0x900, 0x10, 10, 1),
	PINS_FIELD16(16, 16, 0x900, 0x10, 2, 1),
	PINS_FIELD16(17, 19, 0x910, 0x10, 3, 1),
	PINS_FIELD16(20, 22, 0x910, 0x10, 4, 1),
	PINS_FIELD16(23, 26, 0xce0, 0x10, 14, 1),
	PINS_FIELD16(27, 27, 0xcc0, 0x10, 14, 1),
	PINS_FIELD16(28, 28, 0xcd0, 0x10, 14, 1),
	PINS_FIELD16(29, 32, 0x900, 0x10, 3, 1),
	PINS_FIELD16(33, 33, 0x900, 0x10, 4, 1),
	PINS_FIELD16(34, 36, 0x900, 0x10, 5, 1),
	PINS_FIELD16(37, 38, 0x900, 0x10, 6, 1),
	PINS_FIELD16(39, 39, 0x900, 0x10, 7, 1),
	PINS_FIELD16(40, 40, 0x900, 0x10, 8, 1),
	PINS_FIELD16(41, 42, 0x900, 0x10, 9, 1),
	PINS_FIELD16(43, 46, 0x900, 0x10, 11, 1),
	PINS_FIELD16(47, 61, 0x920, 0x10, 3, 1),
	PINS_FIELD16(62, 66, 0x920, 0x10, 4, 1),
	PINS_FIELD16(67, 67, 0x920, 0x10, 3, 1),
	PINS_FIELD16(68, 72, 0x920, 0x10, 5, 1),
	PINS_FIELD16(73, 77, 0x920, 0x10, 6, 1),
	PINS_FIELD16(78, 91, 0x920, 0x10, 7, 1),
	PINS_FIELD16(92, 92, 0x900, 0x10, 13, 1),
	PINS_FIELD16(93, 95, 0x900, 0x10, 14, 1),
	PINS_FIELD16(96, 99, 0x900, 0x10, 15, 1),
	PINS_FIELD16(100, 103, 0xca0, 0x10, 14, 1),
	PINS_FIELD16(104, 104, 0xc80, 0x10, 14, 1),
	PINS_FIELD16(105, 105, 0xc90, 0x10, 14, 1),
	PINS_FIELD16(106, 107, 0x910, 0x10, 0, 1),
	PINS_FIELD16(108, 112, 0x910, 0x10, 1, 1),
	PINS_FIELD16(113, 116, 0x910, 0x10, 2, 1),
	PINS_FIELD16(117, 118, 0x910, 0x10, 5, 1),
	PINS_FIELD16(119, 124, 0x910, 0x10, 6, 1),
	PINS_FIELD16(125, 126, 0x910, 0x10, 7, 1),
	PINS_FIELD16(129, 129, 0x910, 0x10, 8, 1),
	PINS_FIELD16(130, 131, 0x910, 0x10, 9, 1),
	PINS_FIELD16(132, 135, 0x910, 0x10, 8, 1),
	PINS_FIELD16(136, 137, 0x910, 0x10, 7, 1),
	PINS_FIELD16(154, 161, 0xc20, 0x10, 14, 1),
	PINS_FIELD16(162, 162, 0xc10, 0x10, 14, 1),
	PINS_FIELD16(163, 163, 0xc00, 0x10, 14, 1),
	PINS_FIELD16(164, 164, 0xd10, 0x10, 14, 1),
	PINS_FIELD16(165, 165, 0xd00, 0x10, 14, 1),
	PINS_FIELD16(166, 169, 0x910, 0x10, 14, 1),
	PINS_FIELD16(176, 179, 0x910, 0x10, 15, 1),
	PINS_FIELD16(180, 180, 0x920, 0x10, 0, 1),
	PINS_FIELD16(181, 184, 0x920, 0x10, 1, 1),
	PINS_FIELD16(185, 191, 0x920, 0x10, 2, 1),
	PINS_FIELD16(192, 192, 0x920, 0x10, 8, 1),
	PINS_FIELD16(193, 194, 0x920, 0x10, 9, 1),
	PINS_FIELD16(195, 196, 0x920, 0x10, 8, 1),
};

static const struct mtk_pin_field_calc mt6795_pin_smt_range[] = {
	PINS_FIELD16(0, 4, 0x930, 0x10, 1, 1),
	PINS_FIELD16(5, 9, 0x930, 0x10, 2, 1),
	PINS_FIELD16(10, 15, 0x930, 0x10, 10, 1),
	PINS_FIELD16(16, 16, 0x930, 0x10, 2, 1),
	PINS_FIELD16(17, 19, 0x940, 0x10, 3, 1),
	PINS_FIELD16(20, 22, 0x940, 0x10, 4, 1),
	PINS_FIELD16(23, 26, 0xce0, 0x10, 13, 1),
	PINS_FIELD16(27, 27, 0xcc0, 0x10, 13, 1),
	PINS_FIELD16(28, 28, 0xcd0, 0x10, 13, 1),
	PINS_FIELD16(29, 32, 0x930, 0x10, 3, 1),
	PINS_FIELD16(33, 33, 0x930, 0x10, 4, 1),
	PINS_FIELD16(34, 36, 0x930, 0x10, 5, 1),
	PINS_FIELD16(37, 38, 0x930, 0x10, 6, 1),
	PINS_FIELD16(39, 39, 0x930, 0x10, 7, 1),
	PINS_FIELD16(40, 40, 0x930, 0x10, 8, 1),
	PINS_FIELD16(41, 42, 0x930, 0x10, 9, 1),
	PINS_FIELD16(43, 46, 0x930, 0x10, 11, 1),
	PINS_FIELD16(47, 61, 0x950, 0x10, 3, 1),
	PINS_FIELD16(62, 66, 0x950, 0x10, 4, 1),
	PINS_FIELD16(67, 67, 0x950, 0x10, 3, 1),
	PINS_FIELD16(68, 72, 0x950, 0x10, 5, 1),
	PINS_FIELD16(73, 77, 0x950, 0x10, 6, 1),
	PINS_FIELD16(78, 91, 0x950, 0x10, 7, 1),
	PINS_FIELD16(92, 92, 0x930, 0x10, 13, 1),
	PINS_FIELD16(93, 95, 0x930, 0x10, 14, 1),
	PINS_FIELD16(96, 99, 0x930, 0x10, 15, 1),
	PINS_FIELD16(100, 103, 0xca0, 0x10, 13, 1),
	PINS_FIELD16(104, 104, 0xc80, 0x10, 13, 1),
	PINS_FIELD16(105, 105, 0xc90, 0x10, 13, 1),
	PINS_FIELD16(106, 107, 0x940, 0x10, 0, 1),
	PINS_FIELD16(108, 112, 0x940, 0x10, 1, 1),
	PINS_FIELD16(113, 116, 0x940, 0x10, 2, 1),
	PINS_FIELD16(117, 118, 0x940, 0x10, 5, 1),
	PINS_FIELD16(119, 124, 0x940, 0x10, 6, 1),
	PINS_FIELD16(125, 126, 0x940, 0x10, 7, 1),
	PINS_FIELD16(129, 129, 0x940, 0x10, 8, 1),
	PINS_FIELD16(130, 131, 0x940, 0x10, 9, 1),
	PINS_FIELD16(132, 135, 0x940, 0x10, 8, 1),
	PINS_FIELD16(136, 137, 0x940, 0x10, 7, 1),
	PINS_FIELD16(154, 161, 0xc20, 0x10, 13, 1),
	PINS_FIELD16(162, 162, 0xc10, 0x10, 13, 1),
	PINS_FIELD16(163, 163, 0xc00, 0x10, 13, 1),
	PINS_FIELD16(164, 164, 0xd10, 0x10, 13, 1),
	PINS_FIELD16(165, 165, 0xd00, 0x10, 13, 1),
	PINS_FIELD16(166, 169, 0x940, 0x10, 14, 1),
	PINS_FIELD16(176, 179, 0x940, 0x10, 15, 1),
	PINS_FIELD16(180, 180, 0x950, 0x10, 0, 1),
	PINS_FIELD16(181, 184, 0x950, 0x10, 1, 1),
	PINS_FIELD16(185, 191, 0x950, 0x10, 2, 1),
	PINS_FIELD16(192, 192, 0x950, 0x10, 8, 1),
	PINS_FIELD16(193, 194, 0x950, 0x10, 9, 1),
	PINS_FIELD16(195, 196, 0x950, 0x10, 8, 1),
};


static const struct mtk_pin_field_calc mt6795_pin_pupd_range[] = {
	/* KROW */
	PIN_FIELD16(119, 119, 0xe00, 0x10, 2, 1),	/* KROW0 */
	PIN_FIELD16(120, 120, 0xe00, 0x10, 6, 1),	/* KROW1 */
	PIN_FIELD16(121, 121, 0xe00, 0x10, 10, 1),	/* KROW2 */
	PIN_FIELD16(122, 122, 0xe10, 0x10, 2, 1),	/* KCOL0 */
	PIN_FIELD16(123, 123, 0xe10, 0x10, 6, 1),	/* KCOL1 */
	PIN_FIELD16(124, 124, 0xe10, 0x10, 10, 1),	/* KCOL2 */

	/* DPI */
	PIN_FIELD16(138, 138, 0xd50, 0x10, 2, 1),	/* CK */
	PIN_FIELD16(139, 139, 0xd60, 0x10, 1, 1),	/* DE */
	PIN_FIELD16(140, 140, 0xd70, 0x10, 1, 1),	/* data0 */
	PIN_FIELD16(141, 141, 0xd70, 0x10, 3, 1),	/* data1 */
	PIN_FIELD16(142, 142, 0xd70, 0x10, 5, 1),	/* data2 */
	PIN_FIELD16(143, 143, 0xd70, 0x10, 7, 1),	/* data3 */
	PIN_FIELD16(144, 144, 0xd50, 0x10, 5, 1),	/* data4 */
	PIN_FIELD16(145, 145, 0xd50, 0x10, 7, 1),	/* data5 */
	PIN_FIELD16(146, 146, 0xd60, 0x10, 7, 1),	/* data6 */
	PIN_FIELD16(147, 147, 0xed0, 0x10, 6, 1),	/* data7 */
	PIN_FIELD16(148, 148, 0xed0, 0x10, 8, 1),	/* data8 */
	PIN_FIELD16(149, 149, 0xed0, 0x10, 10, 1),	/* data9 */
	PIN_FIELD16(150, 150, 0xed0, 0x10, 12, 1),	/* data10 */
	PIN_FIELD16(151, 151, 0xed0, 0x10, 14, 1),	/* data11 */
	PIN_FIELD16(152, 152, 0xd60, 0x10, 3, 1),	/* hsync */
	PIN_FIELD16(153, 153, 0xd60, 0x10, 5, 1),	/* vsync */

	/* MSDC0 */
	PIN_FIELD16(154, 154, 0xc20, 0x10, 2, 1),	/* DATA 0-7 */
	PIN_FIELD16(155, 155, 0xc20, 0x10, 2, 1),	/* DATA 0-7 */
	PIN_FIELD16(156, 156, 0xc20, 0x10, 2, 1),	/* DATA 0-7 */
	PIN_FIELD16(157, 157, 0xc20, 0x10, 2, 1),	/* DATA 0-7 */
	PIN_FIELD16(158, 158, 0xc20, 0x10, 2, 1),	/* DATA 0-7 */
	PIN_FIELD16(159, 159, 0xc20, 0x10, 2, 1),	/* DATA 0-7 */
	PIN_FIELD16(160, 160, 0xc20, 0x10, 2, 1),	/* DATA 0-7 */
	PIN_FIELD16(161, 161, 0xc20, 0x10, 2, 1),	/* DATA 0-7 */
	PIN_FIELD16(162, 162, 0xc10, 0x10, 2, 1),	/* CMD */
	PIN_FIELD16(163, 163, 0xc00, 0x10, 2, 1),	/* CLK */
	PIN_FIELD16(164, 164, 0xd10, 0x10, 2, 1),	/* DS  */
	PIN_FIELD16(165, 165, 0xd00, 0x10, 2, 1),	/* RST */

	/* MSDC1 */
	PIN_FIELD16(170, 170, 0xc50, 0x10, 2, 1),	/* CMD */
	PIN_FIELD16(171, 171, 0xd20, 0x10, 2, 1),	/* DAT0 */
	PIN_FIELD16(172, 172, 0xd20, 0x10, 6, 1),	/* DAT1 */
	PIN_FIELD16(173, 173, 0xd20, 0x10, 10, 1),	/* DAT2 */
	PIN_FIELD16(174, 174, 0xd20, 0x10, 14, 1),	/* DAT3 */
	PIN_FIELD16(175, 175, 0xc40, 0x10, 2, 1),	/* CLK */

	/* MSDC2 */
	PIN_FIELD16(100, 100, 0xd30, 0x10, 2, 1),	/* DAT0 */
	PIN_FIELD16(101, 101, 0xd30, 0x10, 6, 1),	/* DAT1 */
	PIN_FIELD16(102, 102, 0xd30, 0x10, 10, 1),	/* DAT2 */
	PIN_FIELD16(103, 103, 0xd30, 0x10, 14, 1),	/* DAT3 */
	PIN_FIELD16(104, 104, 0xc80, 0x10, 2, 1),	/* CLK */
	PIN_FIELD16(105, 105, 0xc90, 0x10, 2, 1),	/* CMD */

	/* MSDC3 */
	PIN_FIELD16(23, 23, 0xd40, 0x10, 2, 1),		/* DAT0 */
	PIN_FIELD16(24, 24, 0xd40, 0x10, 6, 5),		/* DAT1 */
	PIN_FIELD16(25, 25, 0xd40, 0x10, 10, 9),	/* DAT2 */
	PIN_FIELD16(26, 26, 0xd40, 0x10, 14, 13),	/* DAT3 */
	PIN_FIELD16(27, 27, 0xcc0, 0x10, 2, 1),		/* CLK */
	PIN_FIELD16(28, 28, 0xcd0, 0x10, 2, 1)		/* CMD */
};

static const struct mtk_pin_field_calc mt6795_pin_r0_range[] = {
	PIN_FIELD16(23, 23, 0xd40, 0x10, 0, 1),
	PIN_FIELD16(24, 24, 0xd40, 0x10, 4, 1),
	PIN_FIELD16(25, 25, 0xd40, 0x10, 8, 1),
	PIN_FIELD16(26, 26, 0xd40, 0x10, 12, 1),
	PIN_FIELD16(27, 27, 0xcc0, 0x10, 0, 1),
	PIN_FIELD16(28, 28, 0xcd0, 0x10, 0, 1),
	PIN_FIELD16(100, 100, 0xd30, 0x10, 0, 1),
	PIN_FIELD16(101, 101, 0xd30, 0x10, 4, 1),
	PIN_FIELD16(102, 102, 0xd30, 0x10, 8, 1),
	PIN_FIELD16(103, 103, 0xd30, 0x10, 12, 1),
	PIN_FIELD16(104, 104, 0xc80, 0x10, 0, 1),
	PIN_FIELD16(105, 105, 0xc90, 0x10, 0, 1),
	PIN_FIELD16(119, 119, 0xe00, 0x10, 0, 1),
	PIN_FIELD16(120, 120, 0xe00, 0x10, 4, 1),
	PIN_FIELD16(121, 121, 0xe00, 0x10, 8, 1),
	PIN_FIELD16(122, 122, 0xe10, 0x10, 0, 1),
	PIN_FIELD16(123, 123, 0xe10, 0x10, 4, 1),
	PIN_FIELD16(124, 124, 0xe10, 0x10, 8, 1),
	PIN_FIELD16(138, 138, 0xd50, 0x10, 0, 1),
	PIN_FIELD16(139, 139, 0xd60, 0x10, 0, 1),
	PIN_FIELD16(140, 140, 0xd70, 0x10, 0, 1),
	PIN_FIELD16(141, 141, 0xd70, 0x10, 1, 1),
	PIN_FIELD16(142, 142, 0xd70, 0x10, 3, 1),
	PIN_FIELD16(143, 143, 0xd70, 0x10, 5, 1),
	PIN_FIELD16(144, 144, 0xd50, 0x10, 3, 1),
	PIN_FIELD16(145, 145, 0xd50, 0x10, 5, 1),
	PIN_FIELD16(146, 146, 0xd60, 0x10, 5, 1),
	PIN_FIELD16(147, 147, 0xed0, 0x10, 4, 1),
	PIN_FIELD16(148, 148, 0xed0, 0x10, 6, 1),
	PIN_FIELD16(149, 149, 0xed0, 0x10, 8, 1),
	PIN_FIELD16(150, 150, 0xed0, 0x10, 10, 1),
	PIN_FIELD16(151, 151, 0xed0, 0x10, 12, 1),
	PIN_FIELD16(152, 152, 0xd60, 0x10, 1, 1),
	PIN_FIELD16(153, 153, 0xd60, 0x10, 3, 1),
	PIN_FIELD16(154, 155, 0xc20, 0x10, 0, 1),
	PIN_FIELD16(155, 156, 0xc20, 0x10, 0, 1),
	PIN_FIELD16(156, 157, 0xc20, 0x10, 0, 1),
	PIN_FIELD16(157, 158, 0xc20, 0x10, 0, 1),
	PIN_FIELD16(158, 159, 0xc20, 0x10, 0, 1),
	PIN_FIELD16(159, 160, 0xc20, 0x10, 0, 1),
	PIN_FIELD16(160, 161, 0xc20, 0x10, 0, 1),
	PIN_FIELD16(161, 161, 0xc20, 0x10, 0, 1),
	PIN_FIELD16(162, 162, 0xc10, 0x10, 0, 1),
	PIN_FIELD16(163, 163, 0xc00, 0x10, 0, 1),
	PIN_FIELD16(164, 164, 0xd10, 0x10, 0, 1),
	PIN_FIELD16(165, 165, 0xd00, 0x10, 0, 1),
	PIN_FIELD16(170, 170, 0xc50, 0x10, 0, 1),
	PIN_FIELD16(171, 171, 0xd20, 0x10, 0, 1),
	PIN_FIELD16(172, 172, 0xd20, 0x10, 4, 1),
	PIN_FIELD16(173, 173, 0xd20, 0x10, 8, 1),
	PIN_FIELD16(174, 174, 0xd20, 0x10, 12, 1),
	PIN_FIELD16(175, 175, 0xc40, 0x10, 0, 1),
};

static const struct mtk_pin_field_calc mt6795_pin_r1_range[] = {
	PIN_FIELD16(23, 23, 0xd40, 0x10, 1, 1),
	PIN_FIELD16(24, 24, 0xd40, 0x10, 5, 1),
	PIN_FIELD16(25, 25, 0xd40, 0x10, 9, 1),
	PIN_FIELD16(26, 26, 0xd40, 0x10, 13, 1),
	PIN_FIELD16(27, 27, 0xcc0, 0x10, 1, 1),
	PIN_FIELD16(28, 28, 0xcd0, 0x10, 1, 1),
	PIN_FIELD16(100, 100, 0xd30, 0x10, 1, 1),
	PIN_FIELD16(101, 101, 0xd30, 0x10, 5, 1),
	PIN_FIELD16(102, 102, 0xd30, 0x10, 9, 1),
	PIN_FIELD16(103, 103, 0xd30, 0x10, 13, 1),
	PIN_FIELD16(104, 104, 0xc80, 0x10, 1, 1),
	PIN_FIELD16(105, 105, 0xc90, 0x10, 1, 1),
	PIN_FIELD16(119, 119, 0xe00, 0x10, 1, 1),
	PIN_FIELD16(120, 120, 0xe00, 0x10, 5, 1),
	PIN_FIELD16(121, 121, 0xe00, 0x10, 9, 1),
	PIN_FIELD16(122, 122, 0xe10, 0x10, 1, 1),
	PIN_FIELD16(123, 123, 0xe10, 0x10, 5, 1),
	PIN_FIELD16(124, 124, 0xe10, 0x10, 9, 1),
	PIN_FIELD16(138, 138, 0xd50, 0x10, 1, 1),
	PIN_FIELD16(139, 139, 0xd60, 0x10, 0, 1),
	PIN_FIELD16(140, 140, 0xd70, 0x10, 0, 1),
	PIN_FIELD16(141, 141, 0xd70, 0x10, 2, 1),
	PIN_FIELD16(142, 142, 0xd70, 0x10, 4, 1),
	PIN_FIELD16(143, 143, 0xd70, 0x10, 6, 1),
	PIN_FIELD16(144, 144, 0xd50, 0x10, 4, 1),
	PIN_FIELD16(145, 145, 0xd50, 0x10, 6, 1),
	PIN_FIELD16(146, 146, 0xd60, 0x10, 6, 1),
	PIN_FIELD16(147, 147, 0xed0, 0x10, 5, 1),
	PIN_FIELD16(148, 148, 0xed0, 0x10, 7, 1),
	PIN_FIELD16(149, 149, 0xed0, 0x10, 9, 1),
	PIN_FIELD16(150, 150, 0xed0, 0x10, 11, 1),
	PIN_FIELD16(151, 151, 0xed0, 0x10, 13, 1),
	PIN_FIELD16(152, 152, 0xd60, 0x10, 2, 1),
	PIN_FIELD16(153, 153, 0xd60, 0x10, 4, 1),
	PIN_FIELD16(154, 155, 0xc20, 0x10, 1, 1),
	PIN_FIELD16(155, 156, 0xc20, 0x10, 1, 1),
	PIN_FIELD16(156, 157, 0xc20, 0x10, 1, 1),
	PIN_FIELD16(157, 158, 0xc20, 0x10, 1, 1),
	PIN_FIELD16(158, 159, 0xc20, 0x10, 1, 1),
	PIN_FIELD16(159, 160, 0xc20, 0x10, 1, 1),
	PIN_FIELD16(160, 161, 0xc20, 0x10, 1, 1),
	PIN_FIELD16(161, 161, 0xc20, 0x10, 1, 1),
	PIN_FIELD16(162, 162, 0xc10, 0x10, 1, 1),
	PIN_FIELD16(163, 163, 0xc00, 0x10, 1, 1),
	PIN_FIELD16(164, 164, 0xd10, 0x10, 1, 1),
	PIN_FIELD16(165, 165, 0xd00, 0x10, 1, 1),
	PIN_FIELD16(170, 170, 0xc50, 0x10, 1, 1),
	PIN_FIELD16(171, 171, 0xd20, 0x10, 1, 1),
	PIN_FIELD16(172, 172, 0xd20, 0x10, 5, 1),
	PIN_FIELD16(173, 173, 0xd20, 0x10, 9, 1),
	PIN_FIELD16(174, 174, 0xd20, 0x10, 13, 1),
	PIN_FIELD16(175, 175, 0xc40, 0x10, 1, 1),
};

static const struct mtk_pin_field_calc mt6795_pin_drv_range[] = {
	PINS_FIELD16(0, 4, 0xb30, 0x10, 13, 2),
	PINS_FIELD16(5, 9, 0xb30, 0x10, 1, 2),
	PINS_FIELD16(10, 15, 0xb30, 0x10, 5, 2),
	PIN_FIELD16(16, 16, 0xb30, 0x10, 1, 2),
	PINS_FIELD16(17, 19, 0xb70, 0x10, 5, 2),
	PINS_FIELD16(20, 22, 0xb70, 0x10, 9, 2),
	PINS_FIELD16(23, 26, 0xce0, 0x10, 8, 2),
	PIN_FIELD16(27, 27, 0xcc0, 0x10, 8, 2),
	PIN_FIELD16(28, 28, 0xcd0, 0x10, 8, 2),
	PINS_FIELD16(29, 32, 0xb80, 0x10, 13, 2),
	PIN_FIELD16(33, 33, 0xb10, 0x10, 13, 2),
	PINS_FIELD16(34, 36, 0xb10, 0x10, 9, 2),
	PINS_FIELD16(37, 38, 0xb10, 0x10, 5, 2),
	PIN_FIELD16(39, 39, 0xb20, 0x10, 1, 2),
	PIN_FIELD16(40, 40, 0xb20, 0x10, 5, 2),
	PINS_FIELD16(41, 42, 0xb20, 0x10, 9, 2),
	PINS_FIELD16(47, 61, 0xb00, 0x10, 9, 2),
	PINS_FIELD16(62, 66, 0xb70, 0x10, 1, 2),
	PINS_FIELD16(67, 67, 0xb00, 0x10, 9, 2),
	PINS_FIELD16(68, 72, 0xb60, 0x10, 13, 2),
	PINS_FIELD16(73, 77, 0xb40, 0x10, 13, 2),
	PIN_FIELD16(78, 78, 0xb00, 0x10, 12, 3),
	PINS_FIELD16(79, 91, 0xb00, 0x10, 13, 2),
	PIN_FIELD16(92, 92, 0xb60, 0x10, 5, 2),
	PINS_FIELD16(93, 95, 0xb60, 0x10, 1, 2),
	PINS_FIELD16(96, 99, 0xb80, 0x10, 9, 2),
	PINS_FIELD16(100, 103, 0xca0, 0x10, 8, 2),
	PIN_FIELD16(104, 104, 0xc80, 0x10, 8, 2),
	PIN_FIELD16(105, 105, 0xc90, 0x10, 8, 2),
	PINS_FIELD16(106, 107, 0xb50, 0x10, 9, 2),
	PINS_FIELD16(108, 112, 0xb50, 0x10, 1, 2),
	PINS_FIELD16(113, 116, 0xb80, 0x10, 5, 2),
	PINS_FIELD16(117, 118, 0xb90, 0x10, 1, 2),
	PINS_FIELD16(119, 124, 0xb50, 0x10, 5, 2),
	PIN_FIELD16(127, 127, 0xb70, 0x10, 5, 2),
	PIN_FIELD16(128, 128, 0xb70, 0x10, 9, 2),
	PIN_FIELD16(129, 129, 0xb40, 0x10, 9, 2),
	PINS_FIELD16(130, 131, 0xb40, 0x10, 13, 2),
	PINS_FIELD16(132, 135, 0xb40, 0x10, 9, 2),
	PIN_FIELD16(138, 138, 0xb50, 0x10, 8, 2),
	PIN_FIELD16(139, 139, 0xb60, 0x10, 8, 2),
	PINS_FIELD16(140, 151, 0xb70, 0x10, 8, 2),
	PINS_FIELD16(152, 153, 0xb60, 0x10, 8, 2),
	PINS_FIELD16(153, 153, 0xb60, 0x10, 8, 2),
	PINS_FIELD16(154, 161, 0xc20, 0x10, 8, 2),
	PIN_FIELD16(162, 162, 0xc10, 0x10, 8, 2),
	PIN_FIELD16(163, 163, 0xc00, 0x10, 8, 2),
	PIN_FIELD16(164, 164, 0xd10, 0x10, 8, 2),
	PIN_FIELD16(165, 165, 0xd00, 0x10, 8, 2),
	PINS_FIELD16(166, 169, 0xb80, 0x10, 1, 2),
	PINS_FIELD16(170, 173, 0xc60, 0x10, 8, 2),
	PIN_FIELD16(174, 174, 0xc40, 0x10, 8, 2),
	PIN_FIELD16(175, 175, 0xc50, 0x10, 8, 2),
	PINS_FIELD16(176, 179, 0xb70, 0x10, 13, 2),
	PIN_FIELD16(180, 180, 0xb00, 0x10, 5, 2),
	PINS_FIELD16(181, 184, 0xb00, 0x10, 1, 2),
	PINS_FIELD16(185, 191, 0xb60, 0x10, 9, 2),
	PIN_FIELD16(192, 192, 0xb40, 0x10, 1, 2),
	PINS_FIELD16(193, 194, 0xb40, 0x10, 5, 2),
	PINS_FIELD16(195, 196, 0xb40, 0x10, 1, 2),
};

static const struct mtk_pin_field_calc mt6795_pin_sr_range[] = {
	PINS_FIELD16(0, 4, 0xb30, 0x10, 15, 1),
	PINS_FIELD16(5, 9, 0xb30, 0x10, 3, 1),
	PINS_FIELD16(10, 15, 0xb30, 0x10, 7, 1),
	PIN_FIELD16(16, 16, 0xb30, 0x10, 5, 1),
	PINS_FIELD16(23, 26, 0xce0, 0x10, 12, 1),
	PIN_FIELD16(27, 27, 0xcc0, 0x10, 12, 1),
	PIN_FIELD16(28, 28, 0xcd0, 0x10, 12, 1),
	PINS_FIELD16(29, 32, 0xb80, 0x10, 15, 1),
	PIN_FIELD16(33, 33, 0xb10, 0x10, 15, 1),
	PINS_FIELD16(34, 36, 0xb10, 0x10, 11, 1),
	PINS_FIELD16(37, 38, 0xb10, 0x10, 7, 1),
	PIN_FIELD16(39, 39, 0xb20, 0x10, 3, 1),
	PIN_FIELD16(40, 40, 0xb20, 0x10, 7, 1),
	PINS_FIELD16(41, 42, 0xb20, 0x10, 11, 1),
	PINS_FIELD16(47, 61, 0xb00, 0x10, 11, 1),
	PINS_FIELD16(62, 66, 0xb70, 0x10, 3, 1),
	PINS_FIELD16(67, 67, 0xb00, 0x10, 11, 1),
	PINS_FIELD16(68, 72, 0xb60, 0x10, 15, 1),
	PINS_FIELD16(73, 77, 0xb40, 0x10, 15, 1),
	PIN_FIELD16(78, 78, 0xb00, 0x10, 15, 3),
	PINS_FIELD16(79, 91, 0xb00, 0x10, 15, 1),
	PIN_FIELD16(92, 92, 0xb60, 0x10, 7, 1),
	PINS_FIELD16(93, 95, 0xb60, 0x10, 3, 1),
	PINS_FIELD16(96, 99, 0xb80, 0x10, 11, 1),
	PINS_FIELD16(100, 103, 0xca0, 0x10, 12, 1),
	PIN_FIELD16(104, 104, 0xc80, 0x10, 12, 1),
	PIN_FIELD16(105, 105, 0xc90, 0x10, 12, 1),
	PINS_FIELD16(106, 107, 0xb50, 0x10, 11, 1),
	PINS_FIELD16(108, 112, 0xb50, 0x10, 3, 1),
	PINS_FIELD16(113, 116, 0xb80, 0x10, 7, 1),
	PINS_FIELD16(117, 118, 0xb90, 0x10, 3, 1),
	PINS_FIELD16(119, 124, 0xb50, 0x10, 7, 1),
	PIN_FIELD16(127, 127, 0xb70, 0x10, 7, 1),
	PIN_FIELD16(128, 128, 0xb70, 0x10, 11, 1),
	PIN_FIELD16(129, 129, 0xb40, 0x10, 11, 1),
	PINS_FIELD16(130, 131, 0xb40, 0x10, 15, 1),
	PINS_FIELD16(132, 135, 0xb40, 0x10, 11, 1),
	PIN_FIELD16(138, 138, 0xb50, 0x10, 12, 1),
	PIN_FIELD16(139, 139, 0xb60, 0x10, 12, 1),
	PINS_FIELD16(140, 151, 0xb70, 0x10, 12, 1),
	PINS_FIELD16(152, 153, 0xb60, 0x10, 12, 1),
	PINS_FIELD16(153, 153, 0xb60, 0x10, 12, 1),
	PINS_FIELD16(154, 161, 0xc20, 0x10, 12, 1),
	PIN_FIELD16(162, 162, 0xc10, 0x10, 12, 1),
	PIN_FIELD16(163, 163, 0xc00, 0x10, 12, 1),
	PIN_FIELD16(164, 164, 0xd10, 0x10, 12, 1),
	PIN_FIELD16(165, 165, 0xd00, 0x10, 12, 1),
	PINS_FIELD16(166, 169, 0xb80, 0x10, 3, 1),
	PINS_FIELD16(170, 173, 0xc60, 0x10, 12, 1),
	PIN_FIELD16(174, 174, 0xc40, 0x10, 12, 1),
	PIN_FIELD16(175, 175, 0xc50, 0x10, 12, 1),
	PINS_FIELD16(176, 179, 0xb70, 0x10, 15, 1),
	PIN_FIELD16(180, 180, 0xb00, 0x10, 7, 1),
	PINS_FIELD16(181, 184, 0xb00, 0x10, 3, 1),
	PINS_FIELD16(185, 191, 0xb60, 0x10, 11, 1),
	PIN_FIELD16(192, 192, 0xb40, 0x10, 3, 1),
	PINS_FIELD16(193, 194, 0xb40, 0x10, 7, 1),
	PINS_FIELD16(195, 196, 0xb40, 0x10, 3, 1),
};

static const struct mtk_pin_reg_calc mt6795_reg_cals[PINCTRL_PIN_REG_MAX] = {
	[PINCTRL_PIN_REG_MODE] = MTK_RANGE(mt6795_pin_mode_range),
	[PINCTRL_PIN_REG_DIR] = MTK_RANGE(mt6795_pin_dir_range),
	[PINCTRL_PIN_REG_DI] = MTK_RANGE(mt6795_pin_di_range),
	[PINCTRL_PIN_REG_DO] = MTK_RANGE(mt6795_pin_do_range),
	[PINCTRL_PIN_REG_SR] = MTK_RANGE(mt6795_pin_sr_range),
	[PINCTRL_PIN_REG_SMT] = MTK_RANGE(mt6795_pin_smt_range),
	[PINCTRL_PIN_REG_DRV] = MTK_RANGE(mt6795_pin_drv_range),
	[PINCTRL_PIN_REG_PUPD] = MTK_RANGE(mt6795_pin_pupd_range),
	[PINCTRL_PIN_REG_R0] = MTK_RANGE(mt6795_pin_r0_range),
	[PINCTRL_PIN_REG_R1] = MTK_RANGE(mt6795_pin_r1_range),
	[PINCTRL_PIN_REG_IES] = MTK_RANGE(mt6795_pin_ies_range),
	[PINCTRL_PIN_REG_PULLEN] = MTK_RANGE(mt6795_pin_pullen_range),
	[PINCTRL_PIN_REG_PULLSEL] = MTK_RANGE(mt6795_pin_pullsel_range),
};

static const struct mtk_eint_hw mt6795_eint_hw = {
	.port_mask = 7,
	.ports     = 7,
	.ap_num    = 224,
	.db_cnt    = 32,
	.db_time   = debounce_time_mt6795,
};

static const unsigned int mt6795_pull_type[] = {
	MTK_PULL_PULLSEL_TYPE,/*0*/		MTK_PULL_PULLSEL_TYPE,/*1*/
	MTK_PULL_PULLSEL_TYPE,/*2*/		MTK_PULL_PULLSEL_TYPE,/*3*/
	MTK_PULL_PULLSEL_TYPE,/*4*/		MTK_PULL_PULLSEL_TYPE,/*5*/
	MTK_PULL_PULLSEL_TYPE,/*6*/		MTK_PULL_PULLSEL_TYPE,/*7*/
	MTK_PULL_PULLSEL_TYPE,/*8*/		MTK_PULL_PULLSEL_TYPE,/*9*/
	MTK_PULL_PULLSEL_TYPE,/*10*/		MTK_PULL_PULLSEL_TYPE,/*11*/
	MTK_PULL_PULLSEL_TYPE,/*12*/		MTK_PULL_PULLSEL_TYPE,/*13*/
	MTK_PULL_PULLSEL_TYPE,/*14*/		MTK_PULL_PULLSEL_TYPE,/*15*/
	MTK_PULL_PULLSEL_TYPE,/*16*/		MTK_PULL_PULLSEL_TYPE,/*17*/
	MTK_PULL_PULLSEL_TYPE,/*18*/		MTK_PULL_PULLSEL_TYPE,/*19*/
	MTK_PULL_PULLSEL_TYPE,/*20*/		MTK_PULL_PULLSEL_TYPE,/*21*/
	MTK_PULL_PULLSEL_TYPE,/*22*/		MTK_PULL_PUPD_R1R0_TYPE,/*23*/
	MTK_PULL_PUPD_R1R0_TYPE,/*24*/		MTK_PULL_PUPD_R1R0_TYPE,/*25*/
	MTK_PULL_PUPD_R1R0_TYPE,/*26*/		MTK_PULL_PUPD_R1R0_TYPE,/*27*/
	MTK_PULL_PUPD_R1R0_TYPE,/*28*/		MTK_PULL_PULLSEL_TYPE,/*29*/
	MTK_PULL_PULLSEL_TYPE,/*30*/		MTK_PULL_PULLSEL_TYPE,/*31*/
	MTK_PULL_PULLSEL_TYPE,/*32*/		MTK_PULL_PULLSEL_TYPE,/*33*/
	MTK_PULL_PULLSEL_TYPE,/*34*/		MTK_PULL_PULLSEL_TYPE,/*35*/
	MTK_PULL_PULLSEL_TYPE,/*36*/		MTK_PULL_PULLSEL_TYPE,/*37*/
	MTK_PULL_PULLSEL_TYPE,/*38*/		MTK_PULL_PULLSEL_TYPE,/*39*/
	MTK_PULL_PULLSEL_TYPE,/*40*/		MTK_PULL_PULLSEL_TYPE,/*41*/
	MTK_PULL_PULLSEL_TYPE,/*42*/		MTK_PULL_PULLSEL_TYPE,/*43*/
	MTK_PULL_PULLSEL_TYPE,/*44*/		MTK_PULL_PULLSEL_TYPE,/*45*/
	MTK_PULL_PULLSEL_TYPE,/*46*/		MTK_PULL_PULLSEL_TYPE,/*47*/
	MTK_PULL_PULLSEL_TYPE,/*48*/		MTK_PULL_PULLSEL_TYPE,/*49*/
	MTK_PULL_PULLSEL_TYPE,/*50*/		MTK_PULL_PULLSEL_TYPE,/*51*/
	MTK_PULL_PULLSEL_TYPE,/*52*/		MTK_PULL_PULLSEL_TYPE,/*53*/
	MTK_PULL_PULLSEL_TYPE,/*54*/		MTK_PULL_PULLSEL_TYPE,/*55*/
	MTK_PULL_PULLSEL_TYPE,/*56*/		MTK_PULL_PULLSEL_TYPE,/*57*/
	MTK_PULL_PULLSEL_TYPE,/*58*/		MTK_PULL_PULLSEL_TYPE,/*59*/
	MTK_PULL_PULLSEL_TYPE,/*60*/		MTK_PULL_PULLSEL_TYPE,/*61*/
	MTK_PULL_PULLSEL_TYPE,/*62*/		MTK_PULL_PULLSEL_TYPE,/*63*/
	MTK_PULL_PULLSEL_TYPE,/*64*/		MTK_PULL_PULLSEL_TYPE,/*65*/
	MTK_PULL_PULLSEL_TYPE,/*66*/		MTK_PULL_PUPD_R1R0_TYPE,/*67*/
	MTK_PULL_PUPD_R1R0_TYPE,/*68*/		MTK_PULL_PUPD_R1R0_TYPE,/*69*/
	MTK_PULL_PUPD_R1R0_TYPE,/*70*/		MTK_PULL_PUPD_R1R0_TYPE,/*71*/
	MTK_PULL_PUPD_R1R0_TYPE,/*72*/		MTK_PULL_PUPD_R1R0_TYPE,/*73*/
	MTK_PULL_PUPD_R1R0_TYPE,/*74*/		MTK_PULL_PUPD_R1R0_TYPE,/*75*/
	MTK_PULL_PUPD_R1R0_TYPE,/*76*/		MTK_PULL_PUPD_R1R0_TYPE,/*77*/
	MTK_PULL_PUPD_R1R0_TYPE,/*78*/		MTK_PULL_PUPD_R1R0_TYPE,/*79*/
	MTK_PULL_PUPD_R1R0_TYPE,/*80*/		MTK_PULL_PUPD_R1R0_TYPE,/*81*/
	MTK_PULL_PUPD_R1R0_TYPE,/*82*/		MTK_PULL_PULLSEL_TYPE,/*83*/
	MTK_PULL_PUPD_R1R0_TYPE,/*84*/		MTK_PULL_PUPD_R1R0_TYPE,/*85*/
	MTK_PULL_PUPD_R1R0_TYPE,/*86*/		MTK_PULL_PUPD_R1R0_TYPE,/*87*/
	MTK_PULL_PUPD_R1R0_TYPE,/*88*/		MTK_PULL_PUPD_R1R0_TYPE,/*89*/
	MTK_PULL_PULLSEL_TYPE,/*90*/		MTK_PULL_PULLSEL_TYPE,/*91*/
	MTK_PULL_PULLSEL_TYPE,/*92*/		MTK_PULL_PULLSEL_TYPE,/*93*/
	MTK_PULL_PULLSEL_TYPE,/*94*/		MTK_PULL_PULLSEL_TYPE,/*95*/
	MTK_PULL_PULLSEL_TYPE,/*96*/		MTK_PULL_PULLSEL_TYPE,/*97*/
	MTK_PULL_PULLSEL_TYPE,/*98*/		MTK_PULL_PULLSEL_TYPE,/*99*/
	MTK_PULL_PUPD_R1R0_TYPE,/*100*/		MTK_PULL_PUPD_R1R0_TYPE,/*101*/
	MTK_PULL_PUPD_R1R0_TYPE,/*102*/		MTK_PULL_PUPD_R1R0_TYPE,/*103*/
	MTK_PULL_PUPD_R1R0_TYPE,/*104*/		MTK_PULL_PUPD_R1R0_TYPE,/*105*/
	MTK_PULL_PULLSEL_TYPE,/*106*/		MTK_PULL_PULLSEL_TYPE,/*107*/
	MTK_PULL_PULLSEL_TYPE,/*108*/		MTK_PULL_PULLSEL_TYPE,/*109*/
	MTK_PULL_PULLSEL_TYPE,/*110*/		MTK_PULL_PULLSEL_TYPE,/*111*/
	MTK_PULL_PULLSEL_TYPE,/*112*/		MTK_PULL_PULLSEL_TYPE,/*113*/
	MTK_PULL_PULLSEL_TYPE,/*114*/		MTK_PULL_PULLSEL_TYPE,/*115*/
	MTK_PULL_PULLSEL_TYPE,/*116*/		MTK_PULL_PULLSEL_TYPE,/*117*/
	MTK_PULL_PULLSEL_TYPE,/*118*/		MTK_PULL_PUPD_R1R0_TYPE,/*119*/
	MTK_PULL_PUPD_R1R0_TYPE,/*120*/		MTK_PULL_PUPD_R1R0_TYPE,/*121*/
	MTK_PULL_PUPD_R1R0_TYPE,/*122*/		MTK_PULL_PUPD_R1R0_TYPE,/*123*/
	MTK_PULL_PUPD_R1R0_TYPE,/*124*/		MTK_PULL_PULLSEL_TYPE,/*125*/
	MTK_PULL_PULLSEL_TYPE,/*126*/		MTK_PULL_PULLSEL_TYPE,/*127*/
	MTK_PULL_PULLSEL_TYPE,/*128*/		MTK_PULL_PULLSEL_TYPE,/*129*/
	MTK_PULL_PULLSEL_TYPE,/*130*/		MTK_PULL_PULLSEL_TYPE,/*131*/
	MTK_PULL_PULLSEL_TYPE,/*132*/		MTK_PULL_PULLSEL_TYPE,/*133*/
	MTK_PULL_PULLSEL_TYPE,/*134*/		MTK_PULL_PULLSEL_TYPE,/*135*/
	MTK_PULL_PULLSEL_TYPE,/*136*/		MTK_PULL_PULLSEL_TYPE,/*137*/
	MTK_PULL_PUPD_R1R0_TYPE,/*138*/		MTK_PULL_PUPD_R1R0_TYPE,/*139*/
	MTK_PULL_PUPD_R1R0_TYPE,/*140*/		MTK_PULL_PUPD_R1R0_TYPE,/*141*/
	MTK_PULL_PUPD_R1R0_TYPE,/*142*/		MTK_PULL_PUPD_R1R0_TYPE,/*143*/
	MTK_PULL_PUPD_R1R0_TYPE,/*144*/		MTK_PULL_PUPD_R1R0_TYPE,/*145*/
	MTK_PULL_PUPD_R1R0_TYPE,/*146*/		MTK_PULL_PUPD_R1R0_TYPE,/*147*/
	MTK_PULL_PUPD_R1R0_TYPE,/*148*/		MTK_PULL_PUPD_R1R0_TYPE,/*149*/
	MTK_PULL_PUPD_R1R0_TYPE,/*150*/		MTK_PULL_PUPD_R1R0_TYPE,/*151*/
	MTK_PULL_PUPD_R1R0_TYPE,/*152*/		MTK_PULL_PUPD_R1R0_TYPE,/*153*/
	MTK_PULL_PUPD_R1R0_TYPE,/*154*/		MTK_PULL_PUPD_R1R0_TYPE,/*155*/
	MTK_PULL_PUPD_R1R0_TYPE,/*156*/		MTK_PULL_PUPD_R1R0_TYPE,/*157*/
	MTK_PULL_PUPD_R1R0_TYPE,/*158*/		MTK_PULL_PUPD_R1R0_TYPE,/*159*/
	MTK_PULL_PUPD_R1R0_TYPE,/*160*/		MTK_PULL_PUPD_R1R0_TYPE,/*161*/
	MTK_PULL_PUPD_R1R0_TYPE,/*162*/		MTK_PULL_PUPD_R1R0_TYPE,/*163*/
	MTK_PULL_PUPD_R1R0_TYPE,/*164*/		MTK_PULL_PUPD_R1R0_TYPE,/*165*/
	MTK_PULL_PULLSEL_TYPE,/*166*/		MTK_PULL_PULLSEL_TYPE,/*167*/
	MTK_PULL_PULLSEL_TYPE,/*168*/		MTK_PULL_PULLSEL_TYPE,/*169*/
	MTK_PULL_PUPD_R1R0_TYPE,/*170*/		MTK_PULL_PUPD_R1R0_TYPE,/*171*/
	MTK_PULL_PUPD_R1R0_TYPE,/*172*/		MTK_PULL_PUPD_R1R0_TYPE,/*173*/
	MTK_PULL_PUPD_R1R0_TYPE,/*174*/		MTK_PULL_PUPD_R1R0_TYPE,/*175*/
	MTK_PULL_PULLSEL_TYPE,/*176*/		MTK_PULL_PULLSEL_TYPE,/*177*/
	MTK_PULL_PULLSEL_TYPE,/*178*/		MTK_PULL_PULLSEL_TYPE,/*179*/
	MTK_PULL_PULLSEL_TYPE,/*180*/		MTK_PULL_PULLSEL_TYPE,/*181*/
	MTK_PULL_PULLSEL_TYPE,/*182*/		MTK_PULL_PULLSEL_TYPE,/*183*/
	MTK_PULL_PULLSEL_TYPE,/*184*/		MTK_PULL_PULLSEL_TYPE,/*185*/
	MTK_PULL_PULLSEL_TYPE,/*186*/		MTK_PULL_PULLSEL_TYPE,/*187*/
	MTK_PULL_PULLSEL_TYPE,/*188*/		MTK_PULL_PULLSEL_TYPE,/*189*/
	MTK_PULL_PULLSEL_TYPE,/*190*/		MTK_PULL_PULLSEL_TYPE,/*191*/
	MTK_PULL_PULLSEL_TYPE,/*192*/		MTK_PULL_PULLSEL_TYPE,/*193*/
	MTK_PULL_PULLSEL_TYPE,/*194*/		MTK_PULL_PULLSEL_TYPE,/*195*/
	MTK_PULL_PULLSEL_TYPE,/*196*/
};

static const struct mtk_pin_soc mt6795_data = {
	.reg_cal = mt6795_reg_cals,
	.pins = mtk_pins_mt6795,
	.npins = ARRAY_SIZE(mtk_pins_mt6795),
	.ngrps = ARRAY_SIZE(mtk_pins_mt6795),
	.nfuncs = 8,
	.eint_hw = &mt6795_eint_hw,
	.gpio_m = 0,
	.base_names = mtk_default_register_base_names,
	.nbase_names = ARRAY_SIZE(mtk_default_register_base_names),
	.pull_type = mt6795_pull_type,
	.bias_disable_set = mtk_pinconf_bias_disable_set_rev1,
	.bias_disable_get = mtk_pinconf_bias_disable_get_rev1,
	.bias_set = mtk_pinconf_bias_set_rev1,
	.bias_get = mtk_pinconf_bias_get_rev1,
	.bias_set_combo = mtk_pinconf_bias_set_combo,
	.bias_get_combo = mtk_pinconf_bias_get_combo,
	.drive_set = mtk_pinconf_drive_set_rev1,
	.drive_get = mtk_pinconf_drive_get_rev1,
	.adv_pull_get = mtk_pinconf_adv_pull_get,
	.adv_pull_set = mtk_pinconf_adv_pull_set,
};

static const struct of_device_id mt6795_pctrl_match[] = {
	{ .compatible = "mediatek,mt6795-pinctrl", .data = &mt6795_data },
	{ }
};

static struct platform_driver mt6795_pinctrl_driver = {
	.driver = {
		.name = "mt6795-pinctrl",
		.of_match_table = mt6795_pctrl_match,
		.pm = pm_sleep_ptr(&mtk_paris_pinctrl_pm_ops),
	},
	.probe = mtk_paris_pinctrl_probe,
};

static int __init mtk_pinctrl_init(void)
{
	return platform_driver_register(&mt6795_pinctrl_driver);
}
arch_initcall(mtk_pinctrl_init);
