/*
 * imx51 pinctrl driver based on imx pinmux core
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

enum imx51_pads {
	MX51_PAD_RESERVE0 = 0,
	MX51_PAD_RESERVE1 = 1,
	MX51_PAD_RESERVE2 = 2,
	MX51_PAD_RESERVE3 = 3,
	MX51_PAD_RESERVE4 = 4,
	MX51_PAD_RESERVE5 = 5,
	MX51_PAD_RESERVE6 = 6,
	MX51_PAD_EIM_DA0 = 7,
	MX51_PAD_EIM_DA1 = 8,
	MX51_PAD_EIM_DA2 = 9,
	MX51_PAD_EIM_DA3 = 10,
	MX51_PAD_EIM_DA4 = 11,
	MX51_PAD_EIM_DA5 = 12,
	MX51_PAD_EIM_DA6 = 13,
	MX51_PAD_EIM_DA7 = 14,
	MX51_PAD_EIM_DA8 = 15,
	MX51_PAD_EIM_DA9 = 16,
	MX51_PAD_EIM_DA10 = 17,
	MX51_PAD_EIM_DA11 = 18,
	MX51_PAD_EIM_DA12 = 19,
	MX51_PAD_EIM_DA13 = 20,
	MX51_PAD_EIM_DA14 = 21,
	MX51_PAD_EIM_DA15 = 22,
	MX51_PAD_EIM_D16 = 23,
	MX51_PAD_EIM_D17 = 24,
	MX51_PAD_EIM_D18 = 25,
	MX51_PAD_EIM_D19 = 26,
	MX51_PAD_EIM_D20 = 27,
	MX51_PAD_EIM_D21 = 28,
	MX51_PAD_EIM_D22 = 29,
	MX51_PAD_EIM_D23 = 30,
	MX51_PAD_EIM_D24 = 31,
	MX51_PAD_EIM_D25 = 32,
	MX51_PAD_EIM_D26 = 33,
	MX51_PAD_EIM_D27 = 34,
	MX51_PAD_EIM_D28 = 35,
	MX51_PAD_EIM_D29 = 36,
	MX51_PAD_EIM_D30 = 37,
	MX51_PAD_EIM_D31 = 38,
	MX51_PAD_EIM_A16 = 39,
	MX51_PAD_EIM_A17 = 40,
	MX51_PAD_EIM_A18 = 41,
	MX51_PAD_EIM_A19 = 42,
	MX51_PAD_EIM_A20 = 43,
	MX51_PAD_EIM_A21 = 44,
	MX51_PAD_EIM_A22 = 45,
	MX51_PAD_EIM_A23 = 46,
	MX51_PAD_EIM_A24 = 47,
	MX51_PAD_EIM_A25 = 48,
	MX51_PAD_EIM_A26 = 49,
	MX51_PAD_EIM_A27 = 50,
	MX51_PAD_EIM_EB0 = 51,
	MX51_PAD_EIM_EB1 = 52,
	MX51_PAD_EIM_EB2 = 53,
	MX51_PAD_EIM_EB3 = 54,
	MX51_PAD_EIM_OE = 55,
	MX51_PAD_EIM_CS0 = 56,
	MX51_PAD_EIM_CS1 = 57,
	MX51_PAD_EIM_CS2 = 58,
	MX51_PAD_EIM_CS3 = 59,
	MX51_PAD_EIM_CS4 = 60,
	MX51_PAD_EIM_CS5 = 61,
	MX51_PAD_EIM_DTACK = 62,
	MX51_PAD_EIM_LBA = 63,
	MX51_PAD_EIM_CRE = 64,
	MX51_PAD_DRAM_CS1 = 65,
	MX51_PAD_NANDF_WE_B = 66,
	MX51_PAD_NANDF_RE_B = 67,
	MX51_PAD_NANDF_ALE = 68,
	MX51_PAD_NANDF_CLE = 69,
	MX51_PAD_NANDF_WP_B = 70,
	MX51_PAD_NANDF_RB0 = 71,
	MX51_PAD_NANDF_RB1 = 72,
	MX51_PAD_NANDF_RB2 = 73,
	MX51_PAD_NANDF_RB3 = 74,
	MX51_PAD_GPIO_NAND = 75,
	MX51_PAD_NANDF_CS0 = 76,
	MX51_PAD_NANDF_CS1 = 77,
	MX51_PAD_NANDF_CS2 = 78,
	MX51_PAD_NANDF_CS3 = 79,
	MX51_PAD_NANDF_CS4 = 80,
	MX51_PAD_NANDF_CS5 = 81,
	MX51_PAD_NANDF_CS6 = 82,
	MX51_PAD_NANDF_CS7 = 83,
	MX51_PAD_NANDF_RDY_INT = 84,
	MX51_PAD_NANDF_D15 = 85,
	MX51_PAD_NANDF_D14 = 86,
	MX51_PAD_NANDF_D13 = 87,
	MX51_PAD_NANDF_D12 = 88,
	MX51_PAD_NANDF_D11 = 89,
	MX51_PAD_NANDF_D10 = 90,
	MX51_PAD_NANDF_D9 = 91,
	MX51_PAD_NANDF_D8 = 92,
	MX51_PAD_NANDF_D7 = 93,
	MX51_PAD_NANDF_D6 = 94,
	MX51_PAD_NANDF_D5 = 95,
	MX51_PAD_NANDF_D4 = 96,
	MX51_PAD_NANDF_D3 = 97,
	MX51_PAD_NANDF_D2 = 98,
	MX51_PAD_NANDF_D1 = 99,
	MX51_PAD_NANDF_D0 = 100,
	MX51_PAD_CSI1_D8 = 101,
	MX51_PAD_CSI1_D9 = 102,
	MX51_PAD_CSI1_D10 = 103,
	MX51_PAD_CSI1_D11 = 104,
	MX51_PAD_CSI1_D12 = 105,
	MX51_PAD_CSI1_D13 = 106,
	MX51_PAD_CSI1_D14 = 107,
	MX51_PAD_CSI1_D15 = 108,
	MX51_PAD_CSI1_D16 = 109,
	MX51_PAD_CSI1_D17 = 110,
	MX51_PAD_CSI1_D18 = 111,
	MX51_PAD_CSI1_D19 = 112,
	MX51_PAD_CSI1_VSYNC = 113,
	MX51_PAD_CSI1_HSYNC = 114,
	MX51_PAD_CSI2_D12 = 115,
	MX51_PAD_CSI2_D13 = 116,
	MX51_PAD_CSI2_D14 = 117,
	MX51_PAD_CSI2_D15 = 118,
	MX51_PAD_CSI2_D16 = 119,
	MX51_PAD_CSI2_D17 = 120,
	MX51_PAD_CSI2_D18 = 121,
	MX51_PAD_CSI2_D19 = 122,
	MX51_PAD_CSI2_VSYNC = 123,
	MX51_PAD_CSI2_HSYNC = 124,
	MX51_PAD_CSI2_PIXCLK = 125,
	MX51_PAD_I2C1_CLK = 126,
	MX51_PAD_I2C1_DAT = 127,
	MX51_PAD_AUD3_BB_TXD = 128,
	MX51_PAD_AUD3_BB_RXD = 129,
	MX51_PAD_AUD3_BB_CK = 130,
	MX51_PAD_AUD3_BB_FS = 131,
	MX51_PAD_CSPI1_MOSI = 132,
	MX51_PAD_CSPI1_MISO = 133,
	MX51_PAD_CSPI1_SS0 = 134,
	MX51_PAD_CSPI1_SS1 = 135,
	MX51_PAD_CSPI1_RDY = 136,
	MX51_PAD_CSPI1_SCLK = 137,
	MX51_PAD_UART1_RXD = 138,
	MX51_PAD_UART1_TXD = 139,
	MX51_PAD_UART1_RTS = 140,
	MX51_PAD_UART1_CTS = 141,
	MX51_PAD_UART2_RXD = 142,
	MX51_PAD_UART2_TXD = 143,
	MX51_PAD_UART3_RXD = 144,
	MX51_PAD_UART3_TXD = 145,
	MX51_PAD_OWIRE_LINE = 146,
	MX51_PAD_KEY_ROW0 = 147,
	MX51_PAD_KEY_ROW1 = 148,
	MX51_PAD_KEY_ROW2 = 149,
	MX51_PAD_KEY_ROW3 = 150,
	MX51_PAD_KEY_COL0 = 151,
	MX51_PAD_KEY_COL1 = 152,
	MX51_PAD_KEY_COL2 = 153,
	MX51_PAD_KEY_COL3 = 154,
	MX51_PAD_KEY_COL4 = 155,
	MX51_PAD_KEY_COL5 = 156,
	MX51_PAD_RESERVE7 = 157,
	MX51_PAD_USBH1_CLK = 158,
	MX51_PAD_USBH1_DIR = 159,
	MX51_PAD_USBH1_STP = 160,
	MX51_PAD_USBH1_NXT = 161,
	MX51_PAD_USBH1_DATA0 = 162,
	MX51_PAD_USBH1_DATA1 = 163,
	MX51_PAD_USBH1_DATA2 = 164,
	MX51_PAD_USBH1_DATA3 = 165,
	MX51_PAD_USBH1_DATA4 = 166,
	MX51_PAD_USBH1_DATA5 = 167,
	MX51_PAD_USBH1_DATA6 = 168,
	MX51_PAD_USBH1_DATA7 = 169,
	MX51_PAD_DI1_PIN11 = 170,
	MX51_PAD_DI1_PIN12 = 171,
	MX51_PAD_DI1_PIN13 = 172,
	MX51_PAD_DI1_D0_CS = 173,
	MX51_PAD_DI1_D1_CS = 174,
	MX51_PAD_DISPB2_SER_DIN = 175,
	MX51_PAD_DISPB2_SER_DIO = 176,
	MX51_PAD_DISPB2_SER_CLK = 177,
	MX51_PAD_DISPB2_SER_RS = 178,
	MX51_PAD_DISP1_DAT0 = 179,
	MX51_PAD_DISP1_DAT1 = 180,
	MX51_PAD_DISP1_DAT2 = 181,
	MX51_PAD_DISP1_DAT3 = 182,
	MX51_PAD_DISP1_DAT4 = 183,
	MX51_PAD_DISP1_DAT5 = 184,
	MX51_PAD_DISP1_DAT6 = 185,
	MX51_PAD_DISP1_DAT7 = 186,
	MX51_PAD_DISP1_DAT8 = 187,
	MX51_PAD_DISP1_DAT9 = 188,
	MX51_PAD_DISP1_DAT10 = 189,
	MX51_PAD_DISP1_DAT11 = 190,
	MX51_PAD_DISP1_DAT12 = 191,
	MX51_PAD_DISP1_DAT13 = 192,
	MX51_PAD_DISP1_DAT14 = 193,
	MX51_PAD_DISP1_DAT15 = 194,
	MX51_PAD_DISP1_DAT16 = 195,
	MX51_PAD_DISP1_DAT17 = 196,
	MX51_PAD_DISP1_DAT18 = 197,
	MX51_PAD_DISP1_DAT19 = 198,
	MX51_PAD_DISP1_DAT20 = 199,
	MX51_PAD_DISP1_DAT21 = 200,
	MX51_PAD_DISP1_DAT22 = 201,
	MX51_PAD_DISP1_DAT23 = 202,
	MX51_PAD_DI1_PIN3 = 203,
	MX51_PAD_DI1_PIN2 = 204,
	MX51_PAD_RESERVE8 = 205,
	MX51_PAD_DI_GP2 = 206,
	MX51_PAD_DI_GP3 = 207,
	MX51_PAD_DI2_PIN4 = 208,
	MX51_PAD_DI2_PIN2 = 209,
	MX51_PAD_DI2_PIN3 = 210,
	MX51_PAD_DI2_DISP_CLK = 211,
	MX51_PAD_DI_GP4 = 212,
	MX51_PAD_DISP2_DAT0 = 213,
	MX51_PAD_DISP2_DAT1 = 214,
	MX51_PAD_DISP2_DAT2 = 215,
	MX51_PAD_DISP2_DAT3 = 216,
	MX51_PAD_DISP2_DAT4 = 217,
	MX51_PAD_DISP2_DAT5 = 218,
	MX51_PAD_DISP2_DAT6 = 219,
	MX51_PAD_DISP2_DAT7 = 220,
	MX51_PAD_DISP2_DAT8 = 221,
	MX51_PAD_DISP2_DAT9 = 222,
	MX51_PAD_DISP2_DAT10 = 223,
	MX51_PAD_DISP2_DAT11 = 224,
	MX51_PAD_DISP2_DAT12 = 225,
	MX51_PAD_DISP2_DAT13 = 226,
	MX51_PAD_DISP2_DAT14 = 227,
	MX51_PAD_DISP2_DAT15 = 228,
	MX51_PAD_SD1_CMD = 229,
	MX51_PAD_SD1_CLK = 230,
	MX51_PAD_SD1_DATA0 = 231,
	MX51_PAD_SD1_DATA1 = 232,
	MX51_PAD_SD1_DATA2 = 233,
	MX51_PAD_SD1_DATA3 = 234,
	MX51_PAD_GPIO1_0 = 235,
	MX51_PAD_GPIO1_1 = 236,
	MX51_PAD_SD2_CMD = 237,
	MX51_PAD_SD2_CLK = 238,
	MX51_PAD_SD2_DATA0 = 239,
	MX51_PAD_SD2_DATA1 = 240,
	MX51_PAD_SD2_DATA2 = 241,
	MX51_PAD_SD2_DATA3 = 242,
	MX51_PAD_GPIO1_2 = 243,
	MX51_PAD_GPIO1_3 = 244,
	MX51_PAD_PMIC_INT_REQ = 245,
	MX51_PAD_GPIO1_4 = 246,
	MX51_PAD_GPIO1_5 = 247,
	MX51_PAD_GPIO1_6 = 248,
	MX51_PAD_GPIO1_7 = 249,
	MX51_PAD_GPIO1_8 = 250,
	MX51_PAD_GPIO1_9 = 251,
	MX51_PAD_RESERVE9 = 252,
	MX51_PAD_RESERVE10 = 253,
	MX51_PAD_RESERVE11 = 254,
	MX51_PAD_RESERVE12 = 255,
	MX51_PAD_RESERVE13 = 256,
	MX51_PAD_RESERVE14 = 257,
	MX51_PAD_RESERVE15 = 258,
	MX51_PAD_RESERVE16 = 259,
	MX51_PAD_RESERVE17 = 260,
	MX51_PAD_RESERVE18 = 261,
	MX51_PAD_RESERVE19 = 262,
	MX51_PAD_RESERVE20 = 263,
	MX51_PAD_RESERVE21 = 264,
	MX51_PAD_RESERVE22 = 265,
	MX51_PAD_RESERVE23 = 266,
	MX51_PAD_RESERVE24 = 267,
	MX51_PAD_RESERVE25 = 268,
	MX51_PAD_RESERVE26 = 269,
	MX51_PAD_RESERVE27 = 270,
	MX51_PAD_RESERVE28 = 271,
	MX51_PAD_RESERVE29 = 272,
	MX51_PAD_RESERVE30 = 273,
	MX51_PAD_RESERVE31 = 274,
	MX51_PAD_RESERVE32 = 275,
	MX51_PAD_RESERVE33 = 276,
	MX51_PAD_RESERVE34 = 277,
	MX51_PAD_RESERVE35 = 278,
	MX51_PAD_RESERVE36 = 279,
	MX51_PAD_RESERVE37 = 280,
	MX51_PAD_RESERVE38 = 281,
	MX51_PAD_RESERVE39 = 282,
	MX51_PAD_RESERVE40 = 283,
	MX51_PAD_RESERVE41 = 284,
	MX51_PAD_RESERVE42 = 285,
	MX51_PAD_RESERVE43 = 286,
	MX51_PAD_RESERVE44 = 287,
	MX51_PAD_RESERVE45 = 288,
	MX51_PAD_RESERVE46 = 289,
	MX51_PAD_RESERVE47 = 290,
	MX51_PAD_RESERVE48 = 291,
	MX51_PAD_RESERVE49 = 292,
	MX51_PAD_RESERVE50 = 293,
	MX51_PAD_RESERVE51 = 294,
	MX51_PAD_RESERVE52 = 295,
	MX51_PAD_RESERVE53 = 296,
	MX51_PAD_RESERVE54 = 297,
	MX51_PAD_RESERVE55 = 298,
	MX51_PAD_RESERVE56 = 299,
	MX51_PAD_RESERVE57 = 300,
	MX51_PAD_RESERVE58 = 301,
	MX51_PAD_RESERVE59 = 302,
	MX51_PAD_RESERVE60 = 303,
	MX51_PAD_RESERVE61 = 304,
	MX51_PAD_RESERVE62 = 305,
	MX51_PAD_RESERVE63 = 306,
	MX51_PAD_RESERVE64 = 307,
	MX51_PAD_RESERVE65 = 308,
	MX51_PAD_RESERVE66 = 309,
	MX51_PAD_RESERVE67 = 310,
	MX51_PAD_RESERVE68 = 311,
	MX51_PAD_RESERVE69 = 312,
	MX51_PAD_RESERVE70 = 313,
	MX51_PAD_RESERVE71 = 314,
	MX51_PAD_RESERVE72 = 315,
	MX51_PAD_RESERVE73 = 316,
	MX51_PAD_RESERVE74 = 317,
	MX51_PAD_RESERVE75 = 318,
	MX51_PAD_RESERVE76 = 319,
	MX51_PAD_RESERVE77 = 320,
	MX51_PAD_RESERVE78 = 321,
	MX51_PAD_RESERVE79 = 322,
	MX51_PAD_RESERVE80 = 323,
	MX51_PAD_RESERVE81 = 324,
	MX51_PAD_RESERVE82 = 325,
	MX51_PAD_RESERVE83 = 326,
	MX51_PAD_RESERVE84 = 327,
	MX51_PAD_RESERVE85 = 328,
	MX51_PAD_RESERVE86 = 329,
	MX51_PAD_RESERVE87 = 330,
	MX51_PAD_RESERVE88 = 331,
	MX51_PAD_RESERVE89 = 332,
	MX51_PAD_RESERVE90 = 333,
	MX51_PAD_RESERVE91 = 334,
	MX51_PAD_RESERVE92 = 335,
	MX51_PAD_RESERVE93 = 336,
	MX51_PAD_RESERVE94 = 337,
	MX51_PAD_RESERVE95 = 338,
	MX51_PAD_RESERVE96 = 339,
	MX51_PAD_RESERVE97 = 340,
	MX51_PAD_RESERVE98 = 341,
	MX51_PAD_RESERVE99 = 342,
	MX51_PAD_RESERVE100 = 343,
	MX51_PAD_RESERVE101 = 344,
	MX51_PAD_RESERVE102 = 345,
	MX51_PAD_RESERVE103 = 346,
	MX51_PAD_RESERVE104 = 347,
	MX51_PAD_RESERVE105 = 348,
	MX51_PAD_RESERVE106 = 349,
	MX51_PAD_RESERVE107 = 350,
	MX51_PAD_RESERVE108 = 351,
	MX51_PAD_RESERVE109 = 352,
	MX51_PAD_RESERVE110 = 353,
	MX51_PAD_RESERVE111 = 354,
	MX51_PAD_RESERVE112 = 355,
	MX51_PAD_RESERVE113 = 356,
	MX51_PAD_RESERVE114 = 357,
	MX51_PAD_RESERVE115 = 358,
	MX51_PAD_RESERVE116 = 359,
	MX51_PAD_RESERVE117 = 360,
	MX51_PAD_RESERVE118 = 361,
	MX51_PAD_RESERVE119 = 362,
	MX51_PAD_RESERVE120 = 363,
	MX51_PAD_RESERVE121 = 364,
	MX51_PAD_CSI1_PIXCLK = 365,
	MX51_PAD_CSI1_MCLK = 366,
};

/* Pad names for the pinmux subsystem */
static const struct pinctrl_pin_desc imx51_pinctrl_pads[] = {
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE0),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE1),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE2),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE3),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE4),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE5),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE6),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_DA0),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_DA1),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_DA2),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_DA3),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_DA4),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_DA5),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_DA6),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_DA7),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_DA8),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_DA9),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_DA10),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_DA11),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_DA12),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_DA13),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_DA14),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_DA15),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_D16),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_D17),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_D18),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_D19),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_D20),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_D21),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_D22),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_D23),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_D24),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_D25),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_D26),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_D27),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_D28),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_D29),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_D30),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_D31),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_A16),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_A17),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_A18),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_A19),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_A20),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_A21),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_A22),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_A23),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_A24),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_A25),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_A26),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_A27),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_EB0),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_EB1),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_EB2),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_EB3),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_OE),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_CS0),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_CS1),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_CS2),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_CS3),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_CS4),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_CS5),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_DTACK),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_LBA),
	IMX_PINCTRL_PIN(MX51_PAD_EIM_CRE),
	IMX_PINCTRL_PIN(MX51_PAD_DRAM_CS1),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_WE_B),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_RE_B),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_ALE),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_CLE),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_WP_B),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_RB0),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_RB1),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_RB2),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_RB3),
	IMX_PINCTRL_PIN(MX51_PAD_GPIO_NAND),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_CS0),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_CS1),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_CS2),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_CS3),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_CS4),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_CS5),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_CS6),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_CS7),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_RDY_INT),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_D15),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_D14),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_D13),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_D12),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_D11),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_D10),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_D9),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_D8),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_D7),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_D6),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_D5),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_D4),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_D3),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_D2),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_D1),
	IMX_PINCTRL_PIN(MX51_PAD_NANDF_D0),
	IMX_PINCTRL_PIN(MX51_PAD_CSI1_D8),
	IMX_PINCTRL_PIN(MX51_PAD_CSI1_D9),
	IMX_PINCTRL_PIN(MX51_PAD_CSI1_D10),
	IMX_PINCTRL_PIN(MX51_PAD_CSI1_D11),
	IMX_PINCTRL_PIN(MX51_PAD_CSI1_D12),
	IMX_PINCTRL_PIN(MX51_PAD_CSI1_D13),
	IMX_PINCTRL_PIN(MX51_PAD_CSI1_D14),
	IMX_PINCTRL_PIN(MX51_PAD_CSI1_D15),
	IMX_PINCTRL_PIN(MX51_PAD_CSI1_D16),
	IMX_PINCTRL_PIN(MX51_PAD_CSI1_D17),
	IMX_PINCTRL_PIN(MX51_PAD_CSI1_D18),
	IMX_PINCTRL_PIN(MX51_PAD_CSI1_D19),
	IMX_PINCTRL_PIN(MX51_PAD_CSI1_VSYNC),
	IMX_PINCTRL_PIN(MX51_PAD_CSI1_HSYNC),
	IMX_PINCTRL_PIN(MX51_PAD_CSI2_D12),
	IMX_PINCTRL_PIN(MX51_PAD_CSI2_D13),
	IMX_PINCTRL_PIN(MX51_PAD_CSI2_D14),
	IMX_PINCTRL_PIN(MX51_PAD_CSI2_D15),
	IMX_PINCTRL_PIN(MX51_PAD_CSI2_D16),
	IMX_PINCTRL_PIN(MX51_PAD_CSI2_D17),
	IMX_PINCTRL_PIN(MX51_PAD_CSI2_D18),
	IMX_PINCTRL_PIN(MX51_PAD_CSI2_D19),
	IMX_PINCTRL_PIN(MX51_PAD_CSI2_VSYNC),
	IMX_PINCTRL_PIN(MX51_PAD_CSI2_HSYNC),
	IMX_PINCTRL_PIN(MX51_PAD_CSI2_PIXCLK),
	IMX_PINCTRL_PIN(MX51_PAD_I2C1_CLK),
	IMX_PINCTRL_PIN(MX51_PAD_I2C1_DAT),
	IMX_PINCTRL_PIN(MX51_PAD_AUD3_BB_TXD),
	IMX_PINCTRL_PIN(MX51_PAD_AUD3_BB_RXD),
	IMX_PINCTRL_PIN(MX51_PAD_AUD3_BB_CK),
	IMX_PINCTRL_PIN(MX51_PAD_AUD3_BB_FS),
	IMX_PINCTRL_PIN(MX51_PAD_CSPI1_MOSI),
	IMX_PINCTRL_PIN(MX51_PAD_CSPI1_MISO),
	IMX_PINCTRL_PIN(MX51_PAD_CSPI1_SS0),
	IMX_PINCTRL_PIN(MX51_PAD_CSPI1_SS1),
	IMX_PINCTRL_PIN(MX51_PAD_CSPI1_RDY),
	IMX_PINCTRL_PIN(MX51_PAD_CSPI1_SCLK),
	IMX_PINCTRL_PIN(MX51_PAD_UART1_RXD),
	IMX_PINCTRL_PIN(MX51_PAD_UART1_TXD),
	IMX_PINCTRL_PIN(MX51_PAD_UART1_RTS),
	IMX_PINCTRL_PIN(MX51_PAD_UART1_CTS),
	IMX_PINCTRL_PIN(MX51_PAD_UART2_RXD),
	IMX_PINCTRL_PIN(MX51_PAD_UART2_TXD),
	IMX_PINCTRL_PIN(MX51_PAD_UART3_RXD),
	IMX_PINCTRL_PIN(MX51_PAD_UART3_TXD),
	IMX_PINCTRL_PIN(MX51_PAD_OWIRE_LINE),
	IMX_PINCTRL_PIN(MX51_PAD_KEY_ROW0),
	IMX_PINCTRL_PIN(MX51_PAD_KEY_ROW1),
	IMX_PINCTRL_PIN(MX51_PAD_KEY_ROW2),
	IMX_PINCTRL_PIN(MX51_PAD_KEY_ROW3),
	IMX_PINCTRL_PIN(MX51_PAD_KEY_COL0),
	IMX_PINCTRL_PIN(MX51_PAD_KEY_COL1),
	IMX_PINCTRL_PIN(MX51_PAD_KEY_COL2),
	IMX_PINCTRL_PIN(MX51_PAD_KEY_COL3),
	IMX_PINCTRL_PIN(MX51_PAD_KEY_COL4),
	IMX_PINCTRL_PIN(MX51_PAD_KEY_COL5),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE7),
	IMX_PINCTRL_PIN(MX51_PAD_USBH1_CLK),
	IMX_PINCTRL_PIN(MX51_PAD_USBH1_DIR),
	IMX_PINCTRL_PIN(MX51_PAD_USBH1_STP),
	IMX_PINCTRL_PIN(MX51_PAD_USBH1_NXT),
	IMX_PINCTRL_PIN(MX51_PAD_USBH1_DATA0),
	IMX_PINCTRL_PIN(MX51_PAD_USBH1_DATA1),
	IMX_PINCTRL_PIN(MX51_PAD_USBH1_DATA2),
	IMX_PINCTRL_PIN(MX51_PAD_USBH1_DATA3),
	IMX_PINCTRL_PIN(MX51_PAD_USBH1_DATA4),
	IMX_PINCTRL_PIN(MX51_PAD_USBH1_DATA5),
	IMX_PINCTRL_PIN(MX51_PAD_USBH1_DATA6),
	IMX_PINCTRL_PIN(MX51_PAD_USBH1_DATA7),
	IMX_PINCTRL_PIN(MX51_PAD_DI1_PIN11),
	IMX_PINCTRL_PIN(MX51_PAD_DI1_PIN12),
	IMX_PINCTRL_PIN(MX51_PAD_DI1_PIN13),
	IMX_PINCTRL_PIN(MX51_PAD_DI1_D0_CS),
	IMX_PINCTRL_PIN(MX51_PAD_DI1_D1_CS),
	IMX_PINCTRL_PIN(MX51_PAD_DISPB2_SER_DIN),
	IMX_PINCTRL_PIN(MX51_PAD_DISPB2_SER_DIO),
	IMX_PINCTRL_PIN(MX51_PAD_DISPB2_SER_CLK),
	IMX_PINCTRL_PIN(MX51_PAD_DISPB2_SER_RS),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT0),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT1),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT2),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT3),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT4),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT5),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT6),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT7),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT8),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT9),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT10),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT11),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT12),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT13),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT14),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT15),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT16),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT17),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT18),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT19),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT20),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT21),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT22),
	IMX_PINCTRL_PIN(MX51_PAD_DISP1_DAT23),
	IMX_PINCTRL_PIN(MX51_PAD_DI1_PIN3),
	IMX_PINCTRL_PIN(MX51_PAD_DI1_PIN2),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE8),
	IMX_PINCTRL_PIN(MX51_PAD_DI_GP2),
	IMX_PINCTRL_PIN(MX51_PAD_DI_GP3),
	IMX_PINCTRL_PIN(MX51_PAD_DI2_PIN4),
	IMX_PINCTRL_PIN(MX51_PAD_DI2_PIN2),
	IMX_PINCTRL_PIN(MX51_PAD_DI2_PIN3),
	IMX_PINCTRL_PIN(MX51_PAD_DI2_DISP_CLK),
	IMX_PINCTRL_PIN(MX51_PAD_DI_GP4),
	IMX_PINCTRL_PIN(MX51_PAD_DISP2_DAT0),
	IMX_PINCTRL_PIN(MX51_PAD_DISP2_DAT1),
	IMX_PINCTRL_PIN(MX51_PAD_DISP2_DAT2),
	IMX_PINCTRL_PIN(MX51_PAD_DISP2_DAT3),
	IMX_PINCTRL_PIN(MX51_PAD_DISP2_DAT4),
	IMX_PINCTRL_PIN(MX51_PAD_DISP2_DAT5),
	IMX_PINCTRL_PIN(MX51_PAD_DISP2_DAT6),
	IMX_PINCTRL_PIN(MX51_PAD_DISP2_DAT7),
	IMX_PINCTRL_PIN(MX51_PAD_DISP2_DAT8),
	IMX_PINCTRL_PIN(MX51_PAD_DISP2_DAT9),
	IMX_PINCTRL_PIN(MX51_PAD_DISP2_DAT10),
	IMX_PINCTRL_PIN(MX51_PAD_DISP2_DAT11),
	IMX_PINCTRL_PIN(MX51_PAD_DISP2_DAT12),
	IMX_PINCTRL_PIN(MX51_PAD_DISP2_DAT13),
	IMX_PINCTRL_PIN(MX51_PAD_DISP2_DAT14),
	IMX_PINCTRL_PIN(MX51_PAD_DISP2_DAT15),
	IMX_PINCTRL_PIN(MX51_PAD_SD1_CMD),
	IMX_PINCTRL_PIN(MX51_PAD_SD1_CLK),
	IMX_PINCTRL_PIN(MX51_PAD_SD1_DATA0),
	IMX_PINCTRL_PIN(MX51_PAD_SD1_DATA1),
	IMX_PINCTRL_PIN(MX51_PAD_SD1_DATA2),
	IMX_PINCTRL_PIN(MX51_PAD_SD1_DATA3),
	IMX_PINCTRL_PIN(MX51_PAD_GPIO1_0),
	IMX_PINCTRL_PIN(MX51_PAD_GPIO1_1),
	IMX_PINCTRL_PIN(MX51_PAD_SD2_CMD),
	IMX_PINCTRL_PIN(MX51_PAD_SD2_CLK),
	IMX_PINCTRL_PIN(MX51_PAD_SD2_DATA0),
	IMX_PINCTRL_PIN(MX51_PAD_SD2_DATA1),
	IMX_PINCTRL_PIN(MX51_PAD_SD2_DATA2),
	IMX_PINCTRL_PIN(MX51_PAD_SD2_DATA3),
	IMX_PINCTRL_PIN(MX51_PAD_GPIO1_2),
	IMX_PINCTRL_PIN(MX51_PAD_GPIO1_3),
	IMX_PINCTRL_PIN(MX51_PAD_PMIC_INT_REQ),
	IMX_PINCTRL_PIN(MX51_PAD_GPIO1_4),
	IMX_PINCTRL_PIN(MX51_PAD_GPIO1_5),
	IMX_PINCTRL_PIN(MX51_PAD_GPIO1_6),
	IMX_PINCTRL_PIN(MX51_PAD_GPIO1_7),
	IMX_PINCTRL_PIN(MX51_PAD_GPIO1_8),
	IMX_PINCTRL_PIN(MX51_PAD_GPIO1_9),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE9),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE10),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE11),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE12),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE13),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE14),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE15),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE16),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE17),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE18),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE19),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE20),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE21),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE22),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE23),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE24),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE25),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE26),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE27),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE28),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE29),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE30),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE31),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE32),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE33),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE34),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE35),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE36),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE37),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE38),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE39),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE40),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE41),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE42),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE43),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE44),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE45),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE46),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE47),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE48),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE49),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE50),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE51),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE52),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE53),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE54),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE55),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE56),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE57),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE58),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE59),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE60),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE61),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE62),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE63),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE64),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE65),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE66),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE67),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE68),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE69),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE70),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE71),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE72),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE73),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE74),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE75),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE76),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE77),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE78),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE79),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE80),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE81),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE82),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE83),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE84),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE85),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE86),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE87),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE88),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE89),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE90),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE91),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE92),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE93),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE94),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE95),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE96),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE97),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE98),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE99),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE100),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE101),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE102),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE103),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE104),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE105),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE106),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE107),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE108),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE109),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE110),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE111),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE112),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE113),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE114),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE115),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE116),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE117),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE118),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE119),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE120),
	IMX_PINCTRL_PIN(MX51_PAD_RESERVE121),
	IMX_PINCTRL_PIN(MX51_PAD_CSI1_PIXCLK),
	IMX_PINCTRL_PIN(MX51_PAD_CSI1_MCLK),
};

static struct imx_pinctrl_soc_info imx51_pinctrl_info = {
	.pins = imx51_pinctrl_pads,
	.npins = ARRAY_SIZE(imx51_pinctrl_pads),
};

static const struct of_device_id imx51_pinctrl_of_match[] = {
	{ .compatible = "fsl,imx51-iomuxc", },
	{ /* sentinel */ }
};

static int imx51_pinctrl_probe(struct platform_device *pdev)
{
	return imx_pinctrl_probe(pdev, &imx51_pinctrl_info);
}

static struct platform_driver imx51_pinctrl_driver = {
	.driver = {
		.name = "imx51-pinctrl",
		.of_match_table = imx51_pinctrl_of_match,
	},
	.probe = imx51_pinctrl_probe,
};

static int __init imx51_pinctrl_init(void)
{
	return platform_driver_register(&imx51_pinctrl_driver);
}
arch_initcall(imx51_pinctrl_init);

static void __exit imx51_pinctrl_exit(void)
{
	platform_driver_unregister(&imx51_pinctrl_driver);
}
module_exit(imx51_pinctrl_exit);
MODULE_AUTHOR("Dong Aisheng <dong.aisheng@linaro.org>");
MODULE_DESCRIPTION("Freescale IMX51 pinctrl driver");
MODULE_LICENSE("GPL v2");
