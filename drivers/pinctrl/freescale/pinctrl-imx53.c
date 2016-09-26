/*
 * imx53 pinctrl driver based on imx pinmux core
 *
 * Copyright (C) 2012 Freescale Semiconductor, Inc.
 * Copyright (C) 2012 Linaro, Inc.
 *
 * Author: Dong Aisheng <dong.aisheng@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/err.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/pinctrl/pinctrl.h>

#include "pinctrl-imx.h"

enum imx53_pads {
	MX53_PAD_RESERVE0 = 0,
	MX53_PAD_RESERVE1 = 1,
	MX53_PAD_RESERVE2 = 2,
	MX53_PAD_RESERVE3 = 3,
	MX53_PAD_RESERVE4 = 4,
	MX53_PAD_RESERVE5 = 5,
	MX53_PAD_RESERVE6 = 6,
	MX53_PAD_RESERVE7 = 7,
	MX53_PAD_GPIO_19 = 8,
	MX53_PAD_KEY_COL0 = 9,
	MX53_PAD_KEY_ROW0 = 10,
	MX53_PAD_KEY_COL1 = 11,
	MX53_PAD_KEY_ROW1 = 12,
	MX53_PAD_KEY_COL2 = 13,
	MX53_PAD_KEY_ROW2 = 14,
	MX53_PAD_KEY_COL3 = 15,
	MX53_PAD_KEY_ROW3 = 16,
	MX53_PAD_KEY_COL4 = 17,
	MX53_PAD_KEY_ROW4 = 18,
	MX53_PAD_DI0_DISP_CLK = 19,
	MX53_PAD_DI0_PIN15 = 20,
	MX53_PAD_DI0_PIN2 = 21,
	MX53_PAD_DI0_PIN3 = 22,
	MX53_PAD_DI0_PIN4 = 23,
	MX53_PAD_DISP0_DAT0 = 24,
	MX53_PAD_DISP0_DAT1 = 25,
	MX53_PAD_DISP0_DAT2 = 26,
	MX53_PAD_DISP0_DAT3 = 27,
	MX53_PAD_DISP0_DAT4 = 28,
	MX53_PAD_DISP0_DAT5 = 29,
	MX53_PAD_DISP0_DAT6 = 30,
	MX53_PAD_DISP0_DAT7 = 31,
	MX53_PAD_DISP0_DAT8 = 32,
	MX53_PAD_DISP0_DAT9 = 33,
	MX53_PAD_DISP0_DAT10 = 34,
	MX53_PAD_DISP0_DAT11 = 35,
	MX53_PAD_DISP0_DAT12 = 36,
	MX53_PAD_DISP0_DAT13 = 37,
	MX53_PAD_DISP0_DAT14 = 38,
	MX53_PAD_DISP0_DAT15 = 39,
	MX53_PAD_DISP0_DAT16 = 40,
	MX53_PAD_DISP0_DAT17 = 41,
	MX53_PAD_DISP0_DAT18 = 42,
	MX53_PAD_DISP0_DAT19 = 43,
	MX53_PAD_DISP0_DAT20 = 44,
	MX53_PAD_DISP0_DAT21 = 45,
	MX53_PAD_DISP0_DAT22 = 46,
	MX53_PAD_DISP0_DAT23 = 47,
	MX53_PAD_CSI0_PIXCLK = 48,
	MX53_PAD_CSI0_MCLK = 49,
	MX53_PAD_CSI0_DATA_EN = 50,
	MX53_PAD_CSI0_VSYNC = 51,
	MX53_PAD_CSI0_DAT4 = 52,
	MX53_PAD_CSI0_DAT5 = 53,
	MX53_PAD_CSI0_DAT6 = 54,
	MX53_PAD_CSI0_DAT7 = 55,
	MX53_PAD_CSI0_DAT8 = 56,
	MX53_PAD_CSI0_DAT9 = 57,
	MX53_PAD_CSI0_DAT10 = 58,
	MX53_PAD_CSI0_DAT11 = 59,
	MX53_PAD_CSI0_DAT12 = 60,
	MX53_PAD_CSI0_DAT13 = 61,
	MX53_PAD_CSI0_DAT14 = 62,
	MX53_PAD_CSI0_DAT15 = 63,
	MX53_PAD_CSI0_DAT16 = 64,
	MX53_PAD_CSI0_DAT17 = 65,
	MX53_PAD_CSI0_DAT18 = 66,
	MX53_PAD_CSI0_DAT19 = 67,
	MX53_PAD_EIM_A25 = 68,
	MX53_PAD_EIM_EB2 = 69,
	MX53_PAD_EIM_D16 = 70,
	MX53_PAD_EIM_D17 = 71,
	MX53_PAD_EIM_D18 = 72,
	MX53_PAD_EIM_D19 = 73,
	MX53_PAD_EIM_D20 = 74,
	MX53_PAD_EIM_D21 = 75,
	MX53_PAD_EIM_D22 = 76,
	MX53_PAD_EIM_D23 = 77,
	MX53_PAD_EIM_EB3 = 78,
	MX53_PAD_EIM_D24 = 79,
	MX53_PAD_EIM_D25 = 80,
	MX53_PAD_EIM_D26 = 81,
	MX53_PAD_EIM_D27 = 82,
	MX53_PAD_EIM_D28 = 83,
	MX53_PAD_EIM_D29 = 84,
	MX53_PAD_EIM_D30 = 85,
	MX53_PAD_EIM_D31 = 86,
	MX53_PAD_EIM_A24 = 87,
	MX53_PAD_EIM_A23 = 88,
	MX53_PAD_EIM_A22 = 89,
	MX53_PAD_EIM_A21 = 90,
	MX53_PAD_EIM_A20 = 91,
	MX53_PAD_EIM_A19 = 92,
	MX53_PAD_EIM_A18 = 93,
	MX53_PAD_EIM_A17 = 94,
	MX53_PAD_EIM_A16 = 95,
	MX53_PAD_EIM_CS0 = 96,
	MX53_PAD_EIM_CS1 = 97,
	MX53_PAD_EIM_OE = 98,
	MX53_PAD_EIM_RW = 99,
	MX53_PAD_EIM_LBA = 100,
	MX53_PAD_EIM_EB0 = 101,
	MX53_PAD_EIM_EB1 = 102,
	MX53_PAD_EIM_DA0 = 103,
	MX53_PAD_EIM_DA1 = 104,
	MX53_PAD_EIM_DA2 = 105,
	MX53_PAD_EIM_DA3 = 106,
	MX53_PAD_EIM_DA4 = 107,
	MX53_PAD_EIM_DA5 = 108,
	MX53_PAD_EIM_DA6 = 109,
	MX53_PAD_EIM_DA7 = 110,
	MX53_PAD_EIM_DA8 = 111,
	MX53_PAD_EIM_DA9 = 112,
	MX53_PAD_EIM_DA10 = 113,
	MX53_PAD_EIM_DA11 = 114,
	MX53_PAD_EIM_DA12 = 115,
	MX53_PAD_EIM_DA13 = 116,
	MX53_PAD_EIM_DA14 = 117,
	MX53_PAD_EIM_DA15 = 118,
	MX53_PAD_NANDF_WE_B = 119,
	MX53_PAD_NANDF_RE_B = 120,
	MX53_PAD_EIM_WAIT = 121,
	MX53_PAD_RESERVE8 = 122,
	MX53_PAD_LVDS1_TX3_P = 123,
	MX53_PAD_LVDS1_TX2_P = 124,
	MX53_PAD_LVDS1_CLK_P = 125,
	MX53_PAD_LVDS1_TX1_P = 126,
	MX53_PAD_LVDS1_TX0_P = 127,
	MX53_PAD_LVDS0_TX3_P = 128,
	MX53_PAD_LVDS0_CLK_P = 129,
	MX53_PAD_LVDS0_TX2_P = 130,
	MX53_PAD_LVDS0_TX1_P = 131,
	MX53_PAD_LVDS0_TX0_P = 132,
	MX53_PAD_GPIO_10 = 133,
	MX53_PAD_GPIO_11 = 134,
	MX53_PAD_GPIO_12 = 135,
	MX53_PAD_GPIO_13 = 136,
	MX53_PAD_GPIO_14 = 137,
	MX53_PAD_NANDF_CLE = 138,
	MX53_PAD_NANDF_ALE = 139,
	MX53_PAD_NANDF_WP_B = 140,
	MX53_PAD_NANDF_RB0 = 141,
	MX53_PAD_NANDF_CS0 = 142,
	MX53_PAD_NANDF_CS1 = 143,
	MX53_PAD_NANDF_CS2 = 144,
	MX53_PAD_NANDF_CS3 = 145,
	MX53_PAD_FEC_MDIO = 146,
	MX53_PAD_FEC_REF_CLK = 147,
	MX53_PAD_FEC_RX_ER = 148,
	MX53_PAD_FEC_CRS_DV = 149,
	MX53_PAD_FEC_RXD1 = 150,
	MX53_PAD_FEC_RXD0 = 151,
	MX53_PAD_FEC_TX_EN = 152,
	MX53_PAD_FEC_TXD1 = 153,
	MX53_PAD_FEC_TXD0 = 154,
	MX53_PAD_FEC_MDC = 155,
	MX53_PAD_PATA_DIOW = 156,
	MX53_PAD_PATA_DMACK = 157,
	MX53_PAD_PATA_DMARQ = 158,
	MX53_PAD_PATA_BUFFER_EN = 159,
	MX53_PAD_PATA_INTRQ = 160,
	MX53_PAD_PATA_DIOR = 161,
	MX53_PAD_PATA_RESET_B = 162,
	MX53_PAD_PATA_IORDY = 163,
	MX53_PAD_PATA_DA_0 = 164,
	MX53_PAD_PATA_DA_1 = 165,
	MX53_PAD_PATA_DA_2 = 166,
	MX53_PAD_PATA_CS_0 = 167,
	MX53_PAD_PATA_CS_1 = 168,
	MX53_PAD_PATA_DATA0 = 169,
	MX53_PAD_PATA_DATA1 = 170,
	MX53_PAD_PATA_DATA2 = 171,
	MX53_PAD_PATA_DATA3 = 172,
	MX53_PAD_PATA_DATA4 = 173,
	MX53_PAD_PATA_DATA5 = 174,
	MX53_PAD_PATA_DATA6 = 175,
	MX53_PAD_PATA_DATA7 = 176,
	MX53_PAD_PATA_DATA8 = 177,
	MX53_PAD_PATA_DATA9 = 178,
	MX53_PAD_PATA_DATA10 = 179,
	MX53_PAD_PATA_DATA11 = 180,
	MX53_PAD_PATA_DATA12 = 181,
	MX53_PAD_PATA_DATA13 = 182,
	MX53_PAD_PATA_DATA14 = 183,
	MX53_PAD_PATA_DATA15 = 184,
	MX53_PAD_SD1_DATA0 = 185,
	MX53_PAD_SD1_DATA1 = 186,
	MX53_PAD_SD1_CMD = 187,
	MX53_PAD_SD1_DATA2 = 188,
	MX53_PAD_SD1_CLK = 189,
	MX53_PAD_SD1_DATA3 = 190,
	MX53_PAD_SD2_CLK = 191,
	MX53_PAD_SD2_CMD = 192,
	MX53_PAD_SD2_DATA3 = 193,
	MX53_PAD_SD2_DATA2 = 194,
	MX53_PAD_SD2_DATA1 = 195,
	MX53_PAD_SD2_DATA0 = 196,
	MX53_PAD_GPIO_0 = 197,
	MX53_PAD_GPIO_1 = 198,
	MX53_PAD_GPIO_9 = 199,
	MX53_PAD_GPIO_3 = 200,
	MX53_PAD_GPIO_6 = 201,
	MX53_PAD_GPIO_2 = 202,
	MX53_PAD_GPIO_4 = 203,
	MX53_PAD_GPIO_5 = 204,
	MX53_PAD_GPIO_7 = 205,
	MX53_PAD_GPIO_8 = 206,
	MX53_PAD_GPIO_16 = 207,
	MX53_PAD_GPIO_17 = 208,
	MX53_PAD_GPIO_18 = 209,
};

/* Pad names for the pinmux subsystem */
static const struct pinctrl_pin_desc imx53_pinctrl_pads[] = {
	IMX_PINCTRL_PIN(MX53_PAD_RESERVE0),
	IMX_PINCTRL_PIN(MX53_PAD_RESERVE1),
	IMX_PINCTRL_PIN(MX53_PAD_RESERVE2),
	IMX_PINCTRL_PIN(MX53_PAD_RESERVE3),
	IMX_PINCTRL_PIN(MX53_PAD_RESERVE4),
	IMX_PINCTRL_PIN(MX53_PAD_RESERVE5),
	IMX_PINCTRL_PIN(MX53_PAD_RESERVE6),
	IMX_PINCTRL_PIN(MX53_PAD_RESERVE7),
	IMX_PINCTRL_PIN(MX53_PAD_GPIO_19),
	IMX_PINCTRL_PIN(MX53_PAD_KEY_COL0),
	IMX_PINCTRL_PIN(MX53_PAD_KEY_ROW0),
	IMX_PINCTRL_PIN(MX53_PAD_KEY_COL1),
	IMX_PINCTRL_PIN(MX53_PAD_KEY_ROW1),
	IMX_PINCTRL_PIN(MX53_PAD_KEY_COL2),
	IMX_PINCTRL_PIN(MX53_PAD_KEY_ROW2),
	IMX_PINCTRL_PIN(MX53_PAD_KEY_COL3),
	IMX_PINCTRL_PIN(MX53_PAD_KEY_ROW3),
	IMX_PINCTRL_PIN(MX53_PAD_KEY_COL4),
	IMX_PINCTRL_PIN(MX53_PAD_KEY_ROW4),
	IMX_PINCTRL_PIN(MX53_PAD_DI0_DISP_CLK),
	IMX_PINCTRL_PIN(MX53_PAD_DI0_PIN15),
	IMX_PINCTRL_PIN(MX53_PAD_DI0_PIN2),
	IMX_PINCTRL_PIN(MX53_PAD_DI0_PIN3),
	IMX_PINCTRL_PIN(MX53_PAD_DI0_PIN4),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT0),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT1),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT2),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT3),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT4),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT5),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT6),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT7),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT8),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT9),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT10),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT11),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT12),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT13),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT14),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT15),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT16),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT17),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT18),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT19),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT20),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT21),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT22),
	IMX_PINCTRL_PIN(MX53_PAD_DISP0_DAT23),
	IMX_PINCTRL_PIN(MX53_PAD_CSI0_PIXCLK),
	IMX_PINCTRL_PIN(MX53_PAD_CSI0_MCLK),
	IMX_PINCTRL_PIN(MX53_PAD_CSI0_DATA_EN),
	IMX_PINCTRL_PIN(MX53_PAD_CSI0_VSYNC),
	IMX_PINCTRL_PIN(MX53_PAD_CSI0_DAT4),
	IMX_PINCTRL_PIN(MX53_PAD_CSI0_DAT5),
	IMX_PINCTRL_PIN(MX53_PAD_CSI0_DAT6),
	IMX_PINCTRL_PIN(MX53_PAD_CSI0_DAT7),
	IMX_PINCTRL_PIN(MX53_PAD_CSI0_DAT8),
	IMX_PINCTRL_PIN(MX53_PAD_CSI0_DAT9),
	IMX_PINCTRL_PIN(MX53_PAD_CSI0_DAT10),
	IMX_PINCTRL_PIN(MX53_PAD_CSI0_DAT11),
	IMX_PINCTRL_PIN(MX53_PAD_CSI0_DAT12),
	IMX_PINCTRL_PIN(MX53_PAD_CSI0_DAT13),
	IMX_PINCTRL_PIN(MX53_PAD_CSI0_DAT14),
	IMX_PINCTRL_PIN(MX53_PAD_CSI0_DAT15),
	IMX_PINCTRL_PIN(MX53_PAD_CSI0_DAT16),
	IMX_PINCTRL_PIN(MX53_PAD_CSI0_DAT17),
	IMX_PINCTRL_PIN(MX53_PAD_CSI0_DAT18),
	IMX_PINCTRL_PIN(MX53_PAD_CSI0_DAT19),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_A25),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_EB2),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_D16),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_D17),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_D18),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_D19),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_D20),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_D21),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_D22),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_D23),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_EB3),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_D24),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_D25),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_D26),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_D27),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_D28),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_D29),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_D30),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_D31),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_A24),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_A23),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_A22),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_A21),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_A20),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_A19),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_A18),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_A17),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_A16),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_CS0),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_CS1),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_OE),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_RW),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_LBA),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_EB0),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_EB1),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_DA0),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_DA1),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_DA2),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_DA3),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_DA4),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_DA5),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_DA6),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_DA7),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_DA8),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_DA9),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_DA10),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_DA11),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_DA12),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_DA13),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_DA14),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_DA15),
	IMX_PINCTRL_PIN(MX53_PAD_NANDF_WE_B),
	IMX_PINCTRL_PIN(MX53_PAD_NANDF_RE_B),
	IMX_PINCTRL_PIN(MX53_PAD_EIM_WAIT),
	IMX_PINCTRL_PIN(MX53_PAD_RESERVE8),
	IMX_PINCTRL_PIN(MX53_PAD_LVDS1_TX3_P),
	IMX_PINCTRL_PIN(MX53_PAD_LVDS1_TX2_P),
	IMX_PINCTRL_PIN(MX53_PAD_LVDS1_CLK_P),
	IMX_PINCTRL_PIN(MX53_PAD_LVDS1_TX1_P),
	IMX_PINCTRL_PIN(MX53_PAD_LVDS1_TX0_P),
	IMX_PINCTRL_PIN(MX53_PAD_LVDS0_TX3_P),
	IMX_PINCTRL_PIN(MX53_PAD_LVDS0_CLK_P),
	IMX_PINCTRL_PIN(MX53_PAD_LVDS0_TX2_P),
	IMX_PINCTRL_PIN(MX53_PAD_LVDS0_TX1_P),
	IMX_PINCTRL_PIN(MX53_PAD_LVDS0_TX0_P),
	IMX_PINCTRL_PIN(MX53_PAD_GPIO_10),
	IMX_PINCTRL_PIN(MX53_PAD_GPIO_11),
	IMX_PINCTRL_PIN(MX53_PAD_GPIO_12),
	IMX_PINCTRL_PIN(MX53_PAD_GPIO_13),
	IMX_PINCTRL_PIN(MX53_PAD_GPIO_14),
	IMX_PINCTRL_PIN(MX53_PAD_NANDF_CLE),
	IMX_PINCTRL_PIN(MX53_PAD_NANDF_ALE),
	IMX_PINCTRL_PIN(MX53_PAD_NANDF_WP_B),
	IMX_PINCTRL_PIN(MX53_PAD_NANDF_RB0),
	IMX_PINCTRL_PIN(MX53_PAD_NANDF_CS0),
	IMX_PINCTRL_PIN(MX53_PAD_NANDF_CS1),
	IMX_PINCTRL_PIN(MX53_PAD_NANDF_CS2),
	IMX_PINCTRL_PIN(MX53_PAD_NANDF_CS3),
	IMX_PINCTRL_PIN(MX53_PAD_FEC_MDIO),
	IMX_PINCTRL_PIN(MX53_PAD_FEC_REF_CLK),
	IMX_PINCTRL_PIN(MX53_PAD_FEC_RX_ER),
	IMX_PINCTRL_PIN(MX53_PAD_FEC_CRS_DV),
	IMX_PINCTRL_PIN(MX53_PAD_FEC_RXD1),
	IMX_PINCTRL_PIN(MX53_PAD_FEC_RXD0),
	IMX_PINCTRL_PIN(MX53_PAD_FEC_TX_EN),
	IMX_PINCTRL_PIN(MX53_PAD_FEC_TXD1),
	IMX_PINCTRL_PIN(MX53_PAD_FEC_TXD0),
	IMX_PINCTRL_PIN(MX53_PAD_FEC_MDC),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DIOW),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DMACK),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DMARQ),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_BUFFER_EN),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_INTRQ),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DIOR),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_RESET_B),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_IORDY),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DA_0),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DA_1),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DA_2),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_CS_0),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_CS_1),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DATA0),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DATA1),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DATA2),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DATA3),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DATA4),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DATA5),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DATA6),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DATA7),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DATA8),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DATA9),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DATA10),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DATA11),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DATA12),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DATA13),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DATA14),
	IMX_PINCTRL_PIN(MX53_PAD_PATA_DATA15),
	IMX_PINCTRL_PIN(MX53_PAD_SD1_DATA0),
	IMX_PINCTRL_PIN(MX53_PAD_SD1_DATA1),
	IMX_PINCTRL_PIN(MX53_PAD_SD1_CMD),
	IMX_PINCTRL_PIN(MX53_PAD_SD1_DATA2),
	IMX_PINCTRL_PIN(MX53_PAD_SD1_CLK),
	IMX_PINCTRL_PIN(MX53_PAD_SD1_DATA3),
	IMX_PINCTRL_PIN(MX53_PAD_SD2_CLK),
	IMX_PINCTRL_PIN(MX53_PAD_SD2_CMD),
	IMX_PINCTRL_PIN(MX53_PAD_SD2_DATA3),
	IMX_PINCTRL_PIN(MX53_PAD_SD2_DATA2),
	IMX_PINCTRL_PIN(MX53_PAD_SD2_DATA1),
	IMX_PINCTRL_PIN(MX53_PAD_SD2_DATA0),
	IMX_PINCTRL_PIN(MX53_PAD_GPIO_0),
	IMX_PINCTRL_PIN(MX53_PAD_GPIO_1),
	IMX_PINCTRL_PIN(MX53_PAD_GPIO_9),
	IMX_PINCTRL_PIN(MX53_PAD_GPIO_3),
	IMX_PINCTRL_PIN(MX53_PAD_GPIO_6),
	IMX_PINCTRL_PIN(MX53_PAD_GPIO_2),
	IMX_PINCTRL_PIN(MX53_PAD_GPIO_4),
	IMX_PINCTRL_PIN(MX53_PAD_GPIO_5),
	IMX_PINCTRL_PIN(MX53_PAD_GPIO_7),
	IMX_PINCTRL_PIN(MX53_PAD_GPIO_8),
	IMX_PINCTRL_PIN(MX53_PAD_GPIO_16),
	IMX_PINCTRL_PIN(MX53_PAD_GPIO_17),
	IMX_PINCTRL_PIN(MX53_PAD_GPIO_18),
};

static struct imx_pinctrl_soc_info imx53_pinctrl_info = {
	.pins = imx53_pinctrl_pads,
	.npins = ARRAY_SIZE(imx53_pinctrl_pads),
	.gpr_compatible = "fsl,imx53-iomuxc-gpr",
};

static const struct of_device_id imx53_pinctrl_of_match[] = {
	{ .compatible = "fsl,imx53-iomuxc", },
	{ /* sentinel */ }
};

static int imx53_pinctrl_probe(struct platform_device *pdev)
{
	return imx_pinctrl_probe(pdev, &imx53_pinctrl_info);
}

static struct platform_driver imx53_pinctrl_driver = {
	.driver = {
		.name = "imx53-pinctrl",
		.of_match_table = imx53_pinctrl_of_match,
	},
	.probe = imx53_pinctrl_probe,
};

static int __init imx53_pinctrl_init(void)
{
	return platform_driver_register(&imx53_pinctrl_driver);
}
arch_initcall(imx53_pinctrl_init);

static void __exit imx53_pinctrl_exit(void)
{
	platform_driver_unregister(&imx53_pinctrl_driver);
}
module_exit(imx53_pinctrl_exit);
MODULE_AUTHOR("Dong Aisheng <dong.aisheng@linaro.org>");
MODULE_DESCRIPTION("Freescale IMX53 pinctrl driver");
MODULE_LICENSE("GPL v2");
