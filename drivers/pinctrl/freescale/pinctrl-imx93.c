// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2021 NXP
 */

#include <linux/err.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/pinctrl/pinctrl.h>

#include "pinctrl-imx.h"

enum imx93_pads {
	IMX93_IOMUXC_DAP_TDI = 0,
	IMX93_IOMUXC_DAP_TMS_SWDIO = 1,
	IMX93_IOMUXC_DAP_TCLK_SWCLK = 2,
	IMX93_IOMUXC_DAP_TDO_TRACESWO = 3,
	IMX93_IOMUXC_GPIO_IO00 = 4,
	IMX93_IOMUXC_GPIO_IO01 = 5,
	IMX93_IOMUXC_GPIO_IO02 = 6,
	IMX93_IOMUXC_GPIO_IO03 = 7,
	IMX93_IOMUXC_GPIO_IO04 = 8,
	IMX93_IOMUXC_GPIO_IO05 = 9,
	IMX93_IOMUXC_GPIO_IO06 = 10,
	IMX93_IOMUXC_GPIO_IO07 = 11,
	IMX93_IOMUXC_GPIO_IO08 = 12,
	IMX93_IOMUXC_GPIO_IO09 = 13,
	IMX93_IOMUXC_GPIO_IO10 = 14,
	IMX93_IOMUXC_GPIO_IO11 = 15,
	IMX93_IOMUXC_GPIO_IO12 = 16,
	IMX93_IOMUXC_GPIO_IO13 = 17,
	IMX93_IOMUXC_GPIO_IO14 = 18,
	IMX93_IOMUXC_GPIO_IO15 = 19,
	IMX93_IOMUXC_GPIO_IO16 = 20,
	IMX93_IOMUXC_GPIO_IO17 = 21,
	IMX93_IOMUXC_GPIO_IO18 = 22,
	IMX93_IOMUXC_GPIO_IO19 = 23,
	IMX93_IOMUXC_GPIO_IO20 = 24,
	IMX93_IOMUXC_GPIO_IO21 = 25,
	IMX93_IOMUXC_GPIO_IO22 = 26,
	IMX93_IOMUXC_GPIO_IO23 = 27,
	IMX93_IOMUXC_GPIO_IO24 = 28,
	IMX93_IOMUXC_GPIO_IO25 = 29,
	IMX93_IOMUXC_GPIO_IO26 = 30,
	IMX93_IOMUXC_GPIO_IO27 = 31,
	IMX93_IOMUXC_GPIO_IO28 = 32,
	IMX93_IOMUXC_GPIO_IO29 = 33,
	IMX93_IOMUXC_CCM_CLKO1 = 34,
	IMX93_IOMUXC_CCM_CLKO2 = 35,
	IMX93_IOMUXC_CCM_CLKO3 = 36,
	IMX93_IOMUXC_CCM_CLKO4 = 37,
	IMX93_IOMUXC_ENET1_MDC = 38,
	IMX93_IOMUXC_ENET1_MDIO = 39,
	IMX93_IOMUXC_ENET1_TD3 = 40,
	IMX93_IOMUXC_ENET1_TD2 = 41,
	IMX93_IOMUXC_ENET1_TD1 = 42,
	IMX93_IOMUXC_ENET1_TD0 = 43,
	IMX93_IOMUXC_ENET1_TX_CTL = 44,
	IMX93_IOMUXC_ENET1_TXC = 45,
	IMX93_IOMUXC_ENET1_RX_CTL = 46,
	IMX93_IOMUXC_ENET1_RXC = 47,
	IMX93_IOMUXC_ENET1_RD0 = 48,
	IMX93_IOMUXC_ENET1_RD1 = 49,
	IMX93_IOMUXC_ENET1_RD2 = 50,
	IMX93_IOMUXC_ENET1_RD3 = 51,
	IMX93_IOMUXC_ENET2_MDC = 52,
	IMX93_IOMUXC_ENET2_MDIO = 53,
	IMX93_IOMUXC_ENET2_TD3 = 54,
	IMX93_IOMUXC_ENET2_TD2 = 55,
	IMX93_IOMUXC_ENET2_TD1 = 56,
	IMX93_IOMUXC_ENET2_TD0 = 57,
	IMX93_IOMUXC_ENET2_TX_CTL = 58,
	IMX93_IOMUXC_ENET2_TXC = 59,
	IMX93_IOMUXC_ENET2_RX_CTL = 60,
	IMX93_IOMUXC_ENET2_RXC = 61,
	IMX93_IOMUXC_ENET2_RD0 = 62,
	IMX93_IOMUXC_ENET2_RD1 = 63,
	IMX93_IOMUXC_ENET2_RD2 = 64,
	IMX93_IOMUXC_ENET2_RD3 = 65,
	IMX93_IOMUXC_SD1_CLK = 66,
	IMX93_IOMUXC_SD1_CMD = 67,
	IMX93_IOMUXC_SD1_DATA0 = 68,
	IMX93_IOMUXC_SD1_DATA1 = 69,
	IMX93_IOMUXC_SD1_DATA2 = 70,
	IMX93_IOMUXC_SD1_DATA3 = 71,
	IMX93_IOMUXC_SD1_DATA4 = 72,
	IMX93_IOMUXC_SD1_DATA5 = 73,
	IMX93_IOMUXC_SD1_DATA6 = 74,
	IMX93_IOMUXC_SD1_DATA7 = 75,
	IMX93_IOMUXC_SD1_STROBE = 76,
	IMX93_IOMUXC_SD2_VSELECT = 77,
	IMX93_IOMUXC_SD3_CLK = 78,
	IMX93_IOMUXC_SD3_CMD = 79,
	IMX93_IOMUXC_SD3_DATA0 = 80,
	IMX93_IOMUXC_SD3_DATA1 = 81,
	IMX93_IOMUXC_SD3_DATA2 = 82,
	IMX93_IOMUXC_SD3_DATA3 = 83,
	IMX93_IOMUXC_SD2_CD_B = 84,
	IMX93_IOMUXC_SD2_CLK = 85,
	IMX93_IOMUXC_SD2_CMD = 86,
	IMX93_IOMUXC_SD2_DATA0 = 87,
	IMX93_IOMUXC_SD2_DATA1 = 88,
	IMX93_IOMUXC_SD2_DATA2 = 89,
	IMX93_IOMUXC_SD2_DATA3 = 90,
	IMX93_IOMUXC_SD2_RESET_B = 91,
	IMX93_IOMUXC_I2C1_SCL = 92,
	IMX93_IOMUXC_I2C1_SDA = 93,
	IMX93_IOMUXC_I2C2_SCL = 94,
	IMX93_IOMUXC_I2C2_SDA = 95,
	IMX93_IOMUXC_UART1_RXD = 96,
	IMX93_IOMUXC_UART1_TXD = 97,
	IMX93_IOMUXC_UART2_RXD = 98,
	IMX93_IOMUXC_UART2_TXD = 99,
	IMX93_IOMUXC_PDM_CLK = 100,
	IMX93_IOMUXC_PDM_BIT_STREAM0 = 101,
	IMX93_IOMUXC_PDM_BIT_STREAM1 = 102,
	IMX93_IOMUXC_SAI1_TXFS = 103,
	IMX93_IOMUXC_SAI1_TXC = 104,
	IMX93_IOMUXC_SAI1_TXD0 = 105,
	IMX93_IOMUXC_SAI1_RXD0 = 106,
	IMX93_IOMUXC_WDOG_ANY  = 107,
};

/* Pad names for the pinmux subsystem */
static const struct pinctrl_pin_desc imx93_pinctrl_pads[] = {
	IMX_PINCTRL_PIN(IMX93_IOMUXC_DAP_TDI),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_DAP_TMS_SWDIO),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_DAP_TCLK_SWCLK),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_DAP_TDO_TRACESWO),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO00),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO01),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO02),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO03),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO04),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO05),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO06),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO07),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO08),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO09),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO10),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO11),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO12),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO13),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO14),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO15),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO16),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO17),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO18),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO19),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO20),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO21),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO22),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO23),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO24),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO25),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO26),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO27),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO28),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_GPIO_IO29),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_CCM_CLKO1),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_CCM_CLKO2),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_CCM_CLKO3),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_CCM_CLKO4),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET1_MDC),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET1_MDIO),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET1_TD3),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET1_TD2),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET1_TD1),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET1_TD0),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET1_TX_CTL),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET1_TXC),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET1_RX_CTL),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET1_RXC),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET1_RD0),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET1_RD1),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET1_RD2),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET1_RD3),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET2_MDC),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET2_MDIO),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET2_TD3),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET2_TD2),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET2_TD1),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET2_TD0),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET2_TX_CTL),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET2_TXC),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET2_RX_CTL),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET2_RXC),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET2_RD0),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET2_RD1),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET2_RD2),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_ENET2_RD3),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD1_CLK),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD1_CMD),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD1_DATA0),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD1_DATA1),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD1_DATA2),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD1_DATA3),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD1_DATA4),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD1_DATA5),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD1_DATA6),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD1_DATA7),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD1_STROBE),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD2_VSELECT),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD3_CLK),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD3_CMD),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD3_DATA0),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD3_DATA1),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD3_DATA2),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD3_DATA3),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD2_CD_B),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD2_CLK),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD2_CMD),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD2_DATA0),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD2_DATA1),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD2_DATA2),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD2_DATA3),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SD2_RESET_B),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_I2C1_SCL),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_I2C1_SDA),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_I2C2_SCL),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_I2C2_SDA),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_UART1_RXD),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_UART1_TXD),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_UART2_RXD),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_UART2_TXD),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_PDM_CLK),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_PDM_BIT_STREAM0),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_PDM_BIT_STREAM1),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SAI1_TXFS),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SAI1_TXC),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SAI1_TXD0),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_SAI1_RXD0),
	IMX_PINCTRL_PIN(IMX93_IOMUXC_WDOG_ANY),
};

static const struct imx_pinctrl_soc_info imx93_pinctrl_info = {
	.pins = imx93_pinctrl_pads,
	.npins = ARRAY_SIZE(imx93_pinctrl_pads),
	.flags = ZERO_OFFSET_VALID,
	.gpr_compatible = "fsl,imx93-iomuxc-gpr",
};

static const struct of_device_id imx93_pinctrl_of_match[] = {
	{ .compatible = "fsl,imx93-iomuxc", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, imx93_pinctrl_of_match);

static int imx93_pinctrl_probe(struct platform_device *pdev)
{
	return imx_pinctrl_probe(pdev, &imx93_pinctrl_info);
}

static struct platform_driver imx93_pinctrl_driver = {
	.driver = {
		.name = "imx93-pinctrl",
		.of_match_table = imx93_pinctrl_of_match,
		.suppress_bind_attrs = true,
	},
	.probe = imx93_pinctrl_probe,
};

static int __init imx93_pinctrl_init(void)
{
	return platform_driver_register(&imx93_pinctrl_driver);
}
arch_initcall(imx93_pinctrl_init);

MODULE_AUTHOR("Bai Ping <ping.bai@nxp.com>");
MODULE_DESCRIPTION("NXP i.MX93 pinctrl driver");
MODULE_LICENSE("GPL v2");
