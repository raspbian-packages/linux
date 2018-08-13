// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2018 NXP.
 *
 */

#include <linux/err.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/pinctrl/pinctrl.h>

#include "pinctrl-imx.h"

enum imx6sll_pads {
	MX6SLL_PAD_RESERVE0 = 0,
	MX6SLL_PAD_RESERVE1 = 1,
	MX6SLL_PAD_RESERVE2 = 2,
	MX6SLL_PAD_RESERVE3 = 3,
	MX6SLL_PAD_RESERVE4 = 4,
	MX6SLL_PAD_WDOG_B = 5,
	MX6SLL_PAD_REF_CLK_24M = 6,
	MX6SLL_PAD_REF_CLK_32K = 7,
	MX6SLL_PAD_PWM1 = 8,
	MX6SLL_PAD_KEY_COL0 = 9,
	MX6SLL_PAD_KEY_ROW0 = 10,
	MX6SLL_PAD_KEY_COL1 = 11,
	MX6SLL_PAD_KEY_ROW1 = 12,
	MX6SLL_PAD_KEY_COL2 = 13,
	MX6SLL_PAD_KEY_ROW2 = 14,
	MX6SLL_PAD_KEY_COL3 = 15,
	MX6SLL_PAD_KEY_ROW3 = 16,
	MX6SLL_PAD_KEY_COL4 = 17,
	MX6SLL_PAD_KEY_ROW4 = 18,
	MX6SLL_PAD_KEY_COL5 = 19,
	MX6SLL_PAD_KEY_ROW5 = 20,
	MX6SLL_PAD_KEY_COL6 = 21,
	MX6SLL_PAD_KEY_ROW6 = 22,
	MX6SLL_PAD_KEY_COL7 = 23,
	MX6SLL_PAD_KEY_ROW7 = 24,
	MX6SLL_PAD_EPDC_DATA00 = 25,
	MX6SLL_PAD_EPDC_DATA01 = 26,
	MX6SLL_PAD_EPDC_DATA02 = 27,
	MX6SLL_PAD_EPDC_DATA03 = 28,
	MX6SLL_PAD_EPDC_DATA04 = 29,
	MX6SLL_PAD_EPDC_DATA05 = 30,
	MX6SLL_PAD_EPDC_DATA06 = 31,
	MX6SLL_PAD_EPDC_DATA07 = 32,
	MX6SLL_PAD_EPDC_DATA08 = 33,
	MX6SLL_PAD_EPDC_DATA09 = 34,
	MX6SLL_PAD_EPDC_DATA10 = 35,
	MX6SLL_PAD_EPDC_DATA11 = 36,
	MX6SLL_PAD_EPDC_DATA12 = 37,
	MX6SLL_PAD_EPDC_DATA13 = 38,
	MX6SLL_PAD_EPDC_DATA14 = 39,
	MX6SLL_PAD_EPDC_DATA15 = 40,
	MX6SLL_PAD_EPDC_SDCLK = 41,
	MX6SLL_PAD_EPDC_SDLE = 42,
	MX6SLL_PAD_EPDC_SDOE = 43,
	MX6SLL_PAD_EPDC_SDSHR = 44,
	MX6SLL_PAD_EPDC_SDCE0 = 45,
	MX6SLL_PAD_EPDC_SDCE1 = 46,
	MX6SLL_PAD_EPDC_SDCE2 = 47,
	MX6SLL_PAD_EPDC_SDCE3 = 48,
	MX6SLL_PAD_EPDC_GDCLK = 49,
	MX6SLL_PAD_EPDC_GDOE = 50,
	MX6SLL_PAD_EPDC_GDRL = 51,
	MX6SLL_PAD_EPDC_GDSP = 52,
	MX6SLL_PAD_EPDC_VCOM0 = 53,
	MX6SLL_PAD_EPDC_VCOM1 = 54,
	MX6SLL_PAD_EPDC_BDR0 = 55,
	MX6SLL_PAD_EPDC_BDR1 = 56,
	MX6SLL_PAD_EPDC_PWR_CTRL0 = 57,
	MX6SLL_PAD_EPDC_PWR_CTRL1 = 58,
	MX6SLL_PAD_EPDC_PWR_CTRL2 = 59,
	MX6SLL_PAD_EPDC_PWR_CTRL3 = 60,
	MX6SLL_PAD_EPDC_PWR_COM = 61,
	MX6SLL_PAD_EPDC_PWR_INT = 62,
	MX6SLL_PAD_EPDC_PWR_STAT = 63,
	MX6SLL_PAD_EPDC_PWR_WAKE = 64,
	MX6SLL_PAD_LCD_CLK = 65,
	MX6SLL_PAD_LCD_ENABLE = 66,
	MX6SLL_PAD_LCD_HSYNC = 67,
	MX6SLL_PAD_LCD_VSYNC = 68,
	MX6SLL_PAD_LCD_RESET = 69,
	MX6SLL_PAD_LCD_DATA00 = 70,
	MX6SLL_PAD_LCD_DATA01 = 71,
	MX6SLL_PAD_LCD_DATA02 = 72,
	MX6SLL_PAD_LCD_DATA03 = 73,
	MX6SLL_PAD_LCD_DATA04 = 74,
	MX6SLL_PAD_LCD_DATA05 = 75,
	MX6SLL_PAD_LCD_DATA06 = 76,
	MX6SLL_PAD_LCD_DATA07 = 77,
	MX6SLL_PAD_LCD_DATA08 = 78,
	MX6SLL_PAD_LCD_DATA09 = 79,
	MX6SLL_PAD_LCD_DATA10 = 80,
	MX6SLL_PAD_LCD_DATA11 = 81,
	MX6SLL_PAD_LCD_DATA12 = 82,
	MX6SLL_PAD_LCD_DATA13 = 83,
	MX6SLL_PAD_LCD_DATA14 = 84,
	MX6SLL_PAD_LCD_DATA15 = 85,
	MX6SLL_PAD_LCD_DATA16 = 86,
	MX6SLL_PAD_LCD_DATA17 = 87,
	MX6SLL_PAD_LCD_DATA18 = 88,
	MX6SLL_PAD_LCD_DATA19 = 89,
	MX6SLL_PAD_LCD_DATA20 = 90,
	MX6SLL_PAD_LCD_DATA21 = 91,
	MX6SLL_PAD_LCD_DATA22 = 92,
	MX6SLL_PAD_LCD_DATA23 = 93,
	MX6SLL_PAD_AUD_RXFS = 94,
	MX6SLL_PAD_AUD_RXC = 95,
	MX6SLL_PAD_AUD_RXD = 96,
	MX6SLL_PAD_AUD_TXC = 97,
	MX6SLL_PAD_AUD_TXFS = 98,
	MX6SLL_PAD_AUD_TXD = 99,
	MX6SLL_PAD_AUD_MCLK = 100,
	MX6SLL_PAD_UART1_RXD = 101,
	MX6SLL_PAD_UART1_TXD = 102,
	MX6SLL_PAD_I2C1_SCL = 103,
	MX6SLL_PAD_I2C1_SDA = 104,
	MX6SLL_PAD_I2C2_SCL = 105,
	MX6SLL_PAD_I2C2_SDA = 106,
	MX6SLL_PAD_ECSPI1_SCLK = 107,
	MX6SLL_PAD_ECSPI1_MOSI = 108,
	MX6SLL_PAD_ECSPI1_MISO = 109,
	MX6SLL_PAD_ECSPI1_SS0 = 110,
	MX6SLL_PAD_ECSPI2_SCLK = 111,
	MX6SLL_PAD_ECSPI2_MOSI = 112,
	MX6SLL_PAD_ECSPI2_MISO = 113,
	MX6SLL_PAD_ECSPI2_SS0 = 114,
	MX6SLL_PAD_SD1_CLK = 115,
	MX6SLL_PAD_SD1_CMD = 116,
	MX6SLL_PAD_SD1_DATA0 = 117,
	MX6SLL_PAD_SD1_DATA1 = 118,
	MX6SLL_PAD_SD1_DATA2 = 119,
	MX6SLL_PAD_SD1_DATA3 = 120,
	MX6SLL_PAD_SD1_DATA4 = 121,
	MX6SLL_PAD_SD1_DATA5 = 122,
	MX6SLL_PAD_SD1_DATA6 = 123,
	MX6SLL_PAD_SD1_DATA7 = 124,
	MX6SLL_PAD_SD2_RESET = 125,
	MX6SLL_PAD_SD2_CLK = 126,
	MX6SLL_PAD_SD2_CMD = 127,
	MX6SLL_PAD_SD2_DATA0 = 128,
	MX6SLL_PAD_SD2_DATA1 = 129,
	MX6SLL_PAD_SD2_DATA2 = 130,
	MX6SLL_PAD_SD2_DATA3 = 131,
	MX6SLL_PAD_SD2_DATA4 = 132,
	MX6SLL_PAD_SD2_DATA5 = 133,
	MX6SLL_PAD_SD2_DATA6 = 134,
	MX6SLL_PAD_SD2_DATA7 = 135,
	MX6SLL_PAD_SD3_CLK = 136,
	MX6SLL_PAD_SD3_CMD = 137,
	MX6SLL_PAD_SD3_DATA0 = 138,
	MX6SLL_PAD_SD3_DATA1 = 139,
	MX6SLL_PAD_SD3_DATA2 = 140,
	MX6SLL_PAD_SD3_DATA3 = 141,
	MX6SLL_PAD_GPIO4_IO20 = 142,
	MX6SLL_PAD_GPIO4_IO21 = 143,
	MX6SLL_PAD_GPIO4_IO19 = 144,
	MX6SLL_PAD_GPIO4_IO25 = 145,
	MX6SLL_PAD_GPIO4_IO18 = 146,
	MX6SLL_PAD_GPIO4_IO24 = 147,
	MX6SLL_PAD_GPIO4_IO23 = 148,
	MX6SLL_PAD_GPIO4_IO17 = 149,
	MX6SLL_PAD_GPIO4_IO22 = 150,
	MX6SLL_PAD_GPIO4_IO16 = 151,
	MX6SLL_PAD_GPIO4_IO26 = 152,
};

/* Pad names for the pinmux subsystem */
static const struct pinctrl_pin_desc imx6sll_pinctrl_pads[] = {
	IMX_PINCTRL_PIN(MX6SLL_PAD_RESERVE0),
	IMX_PINCTRL_PIN(MX6SLL_PAD_RESERVE1),
	IMX_PINCTRL_PIN(MX6SLL_PAD_RESERVE2),
	IMX_PINCTRL_PIN(MX6SLL_PAD_RESERVE3),
	IMX_PINCTRL_PIN(MX6SLL_PAD_RESERVE4),
	IMX_PINCTRL_PIN(MX6SLL_PAD_WDOG_B),
	IMX_PINCTRL_PIN(MX6SLL_PAD_REF_CLK_24M),
	IMX_PINCTRL_PIN(MX6SLL_PAD_REF_CLK_32K),
	IMX_PINCTRL_PIN(MX6SLL_PAD_PWM1),
	IMX_PINCTRL_PIN(MX6SLL_PAD_KEY_COL0),
	IMX_PINCTRL_PIN(MX6SLL_PAD_KEY_ROW0),
	IMX_PINCTRL_PIN(MX6SLL_PAD_KEY_COL1),
	IMX_PINCTRL_PIN(MX6SLL_PAD_KEY_ROW1),
	IMX_PINCTRL_PIN(MX6SLL_PAD_KEY_COL2),
	IMX_PINCTRL_PIN(MX6SLL_PAD_KEY_ROW2),
	IMX_PINCTRL_PIN(MX6SLL_PAD_KEY_COL3),
	IMX_PINCTRL_PIN(MX6SLL_PAD_KEY_ROW3),
	IMX_PINCTRL_PIN(MX6SLL_PAD_KEY_COL4),
	IMX_PINCTRL_PIN(MX6SLL_PAD_KEY_ROW4),
	IMX_PINCTRL_PIN(MX6SLL_PAD_KEY_COL5),
	IMX_PINCTRL_PIN(MX6SLL_PAD_KEY_ROW5),
	IMX_PINCTRL_PIN(MX6SLL_PAD_KEY_COL6),
	IMX_PINCTRL_PIN(MX6SLL_PAD_KEY_ROW6),
	IMX_PINCTRL_PIN(MX6SLL_PAD_KEY_COL7),
	IMX_PINCTRL_PIN(MX6SLL_PAD_KEY_ROW7),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_DATA00),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_DATA01),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_DATA02),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_DATA03),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_DATA04),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_DATA05),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_DATA06),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_DATA07),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_DATA08),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_DATA09),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_DATA10),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_DATA11),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_DATA12),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_DATA13),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_DATA14),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_DATA15),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_SDCLK),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_SDLE),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_SDOE),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_SDSHR),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_SDCE0),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_SDCE1),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_SDCE2),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_SDCE3),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_GDCLK),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_GDOE),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_GDRL),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_GDSP),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_VCOM0),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_VCOM1),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_BDR0),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_BDR1),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_PWR_CTRL0),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_PWR_CTRL1),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_PWR_CTRL2),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_PWR_CTRL3),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_PWR_COM),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_PWR_INT),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_PWR_STAT),
	IMX_PINCTRL_PIN(MX6SLL_PAD_EPDC_PWR_WAKE),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_CLK),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_ENABLE),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_HSYNC),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_VSYNC),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_RESET),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA00),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA01),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA02),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA03),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA04),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA05),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA06),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA07),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA08),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA09),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA10),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA11),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA12),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA13),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA14),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA15),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA16),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA17),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA18),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA19),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA20),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA21),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA22),
	IMX_PINCTRL_PIN(MX6SLL_PAD_LCD_DATA23),
	IMX_PINCTRL_PIN(MX6SLL_PAD_AUD_RXFS),
	IMX_PINCTRL_PIN(MX6SLL_PAD_AUD_RXC),
	IMX_PINCTRL_PIN(MX6SLL_PAD_AUD_RXD),
	IMX_PINCTRL_PIN(MX6SLL_PAD_AUD_TXC),
	IMX_PINCTRL_PIN(MX6SLL_PAD_AUD_TXFS),
	IMX_PINCTRL_PIN(MX6SLL_PAD_AUD_TXD),
	IMX_PINCTRL_PIN(MX6SLL_PAD_AUD_MCLK),
	IMX_PINCTRL_PIN(MX6SLL_PAD_UART1_RXD),
	IMX_PINCTRL_PIN(MX6SLL_PAD_UART1_TXD),
	IMX_PINCTRL_PIN(MX6SLL_PAD_I2C1_SCL),
	IMX_PINCTRL_PIN(MX6SLL_PAD_I2C1_SDA),
	IMX_PINCTRL_PIN(MX6SLL_PAD_I2C2_SCL),
	IMX_PINCTRL_PIN(MX6SLL_PAD_I2C2_SDA),
	IMX_PINCTRL_PIN(MX6SLL_PAD_ECSPI1_SCLK),
	IMX_PINCTRL_PIN(MX6SLL_PAD_ECSPI1_MOSI),
	IMX_PINCTRL_PIN(MX6SLL_PAD_ECSPI1_MISO),
	IMX_PINCTRL_PIN(MX6SLL_PAD_ECSPI1_SS0),
	IMX_PINCTRL_PIN(MX6SLL_PAD_ECSPI2_SCLK),
	IMX_PINCTRL_PIN(MX6SLL_PAD_ECSPI2_MOSI),
	IMX_PINCTRL_PIN(MX6SLL_PAD_ECSPI2_MISO),
	IMX_PINCTRL_PIN(MX6SLL_PAD_ECSPI2_SS0),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD1_CLK),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD1_CMD),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD1_DATA0),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD1_DATA1),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD1_DATA2),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD1_DATA3),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD1_DATA4),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD1_DATA5),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD1_DATA6),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD1_DATA7),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD2_RESET),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD2_CLK),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD2_CMD),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD2_DATA0),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD2_DATA1),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD2_DATA2),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD2_DATA3),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD2_DATA4),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD2_DATA5),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD2_DATA6),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD2_DATA7),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD3_CLK),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD3_CMD),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD3_DATA0),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD3_DATA1),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD3_DATA2),
	IMX_PINCTRL_PIN(MX6SLL_PAD_SD3_DATA3),
	IMX_PINCTRL_PIN(MX6SLL_PAD_GPIO4_IO20),
	IMX_PINCTRL_PIN(MX6SLL_PAD_GPIO4_IO21),
	IMX_PINCTRL_PIN(MX6SLL_PAD_GPIO4_IO19),
	IMX_PINCTRL_PIN(MX6SLL_PAD_GPIO4_IO25),
	IMX_PINCTRL_PIN(MX6SLL_PAD_GPIO4_IO18),
	IMX_PINCTRL_PIN(MX6SLL_PAD_GPIO4_IO24),
	IMX_PINCTRL_PIN(MX6SLL_PAD_GPIO4_IO23),
	IMX_PINCTRL_PIN(MX6SLL_PAD_GPIO4_IO17),
	IMX_PINCTRL_PIN(MX6SLL_PAD_GPIO4_IO22),
	IMX_PINCTRL_PIN(MX6SLL_PAD_GPIO4_IO16),
	IMX_PINCTRL_PIN(MX6SLL_PAD_GPIO4_IO26),
};

static const struct imx_pinctrl_soc_info imx6sll_pinctrl_info = {
	.pins = imx6sll_pinctrl_pads,
	.npins = ARRAY_SIZE(imx6sll_pinctrl_pads),
	.gpr_compatible = "fsl,imx6sll-iomuxc-gpr",
};

static const struct of_device_id imx6sll_pinctrl_of_match[] = {
	{ .compatible = "fsl,imx6sll-iomuxc", .data = &imx6sll_pinctrl_info, },
	{ /* sentinel */ }
};

static int imx6sll_pinctrl_probe(struct platform_device *pdev)
{
	return imx_pinctrl_probe(pdev, &imx6sll_pinctrl_info);
}

static struct platform_driver imx6sll_pinctrl_driver = {
	.driver = {
		.name = "imx6sll-pinctrl",
		.of_match_table = of_match_ptr(imx6sll_pinctrl_of_match),
		.suppress_bind_attrs = true,
	},
	.probe = imx6sll_pinctrl_probe,
};

static int __init imx6sll_pinctrl_init(void)
{
	return platform_driver_register(&imx6sll_pinctrl_driver);
}
arch_initcall(imx6sll_pinctrl_init);
