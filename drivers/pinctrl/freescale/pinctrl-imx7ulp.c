// SPDX-License-Identifier: GPL-2.0
//
// Copyright (C) 2016 Freescale Semiconductor, Inc.
// Copyright (C) 2017 NXP
//
// Author: Dong Aisheng <aisheng.dong@nxp.com>

#include <linux/err.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/mod_devicetable.h>
#include <linux/platform_device.h>
#include <linux/pinctrl/pinctrl.h>

#include "pinctrl-imx.h"

enum imx7ulp_pads {
	IMX7ULP_PAD_PTC0 = 0,
	IMX7ULP_PAD_PTC1,
	IMX7ULP_PAD_PTC2,
	IMX7ULP_PAD_PTC3,
	IMX7ULP_PAD_PTC4,
	IMX7ULP_PAD_PTC5,
	IMX7ULP_PAD_PTC6,
	IMX7ULP_PAD_PTC7,
	IMX7ULP_PAD_PTC8,
	IMX7ULP_PAD_PTC9,
	IMX7ULP_PAD_PTC10,
	IMX7ULP_PAD_PTC11,
	IMX7ULP_PAD_PTC12,
	IMX7ULP_PAD_PTC13,
	IMX7ULP_PAD_PTC14,
	IMX7ULP_PAD_PTC15,
	IMX7ULP_PAD_PTC16,
	IMX7ULP_PAD_PTC17,
	IMX7ULP_PAD_PTC18,
	IMX7ULP_PAD_PTC19,
	IMX7ULP_PAD_RESERVE0,
	IMX7ULP_PAD_RESERVE1,
	IMX7ULP_PAD_RESERVE2,
	IMX7ULP_PAD_RESERVE3,
	IMX7ULP_PAD_RESERVE4,
	IMX7ULP_PAD_RESERVE5,
	IMX7ULP_PAD_RESERVE6,
	IMX7ULP_PAD_RESERVE7,
	IMX7ULP_PAD_RESERVE8,
	IMX7ULP_PAD_RESERVE9,
	IMX7ULP_PAD_RESERVE10,
	IMX7ULP_PAD_RESERVE11,
	IMX7ULP_PAD_PTD0,
	IMX7ULP_PAD_PTD1,
	IMX7ULP_PAD_PTD2,
	IMX7ULP_PAD_PTD3,
	IMX7ULP_PAD_PTD4,
	IMX7ULP_PAD_PTD5,
	IMX7ULP_PAD_PTD6,
	IMX7ULP_PAD_PTD7,
	IMX7ULP_PAD_PTD8,
	IMX7ULP_PAD_PTD9,
	IMX7ULP_PAD_PTD10,
	IMX7ULP_PAD_PTD11,
	IMX7ULP_PAD_RESERVE12,
	IMX7ULP_PAD_RESERVE13,
	IMX7ULP_PAD_RESERVE14,
	IMX7ULP_PAD_RESERVE15,
	IMX7ULP_PAD_RESERVE16,
	IMX7ULP_PAD_RESERVE17,
	IMX7ULP_PAD_RESERVE18,
	IMX7ULP_PAD_RESERVE19,
	IMX7ULP_PAD_RESERVE20,
	IMX7ULP_PAD_RESERVE21,
	IMX7ULP_PAD_RESERVE22,
	IMX7ULP_PAD_RESERVE23,
	IMX7ULP_PAD_RESERVE24,
	IMX7ULP_PAD_RESERVE25,
	IMX7ULP_PAD_RESERVE26,
	IMX7ULP_PAD_RESERVE27,
	IMX7ULP_PAD_RESERVE28,
	IMX7ULP_PAD_RESERVE29,
	IMX7ULP_PAD_RESERVE30,
	IMX7ULP_PAD_RESERVE31,
	IMX7ULP_PAD_PTE0,
	IMX7ULP_PAD_PTE1,
	IMX7ULP_PAD_PTE2,
	IMX7ULP_PAD_PTE3,
	IMX7ULP_PAD_PTE4,
	IMX7ULP_PAD_PTE5,
	IMX7ULP_PAD_PTE6,
	IMX7ULP_PAD_PTE7,
	IMX7ULP_PAD_PTE8,
	IMX7ULP_PAD_PTE9,
	IMX7ULP_PAD_PTE10,
	IMX7ULP_PAD_PTE11,
	IMX7ULP_PAD_PTE12,
	IMX7ULP_PAD_PTE13,
	IMX7ULP_PAD_PTE14,
	IMX7ULP_PAD_PTE15,
	IMX7ULP_PAD_RESERVE32,
	IMX7ULP_PAD_RESERVE33,
	IMX7ULP_PAD_RESERVE34,
	IMX7ULP_PAD_RESERVE35,
	IMX7ULP_PAD_RESERVE36,
	IMX7ULP_PAD_RESERVE37,
	IMX7ULP_PAD_RESERVE38,
	IMX7ULP_PAD_RESERVE39,
	IMX7ULP_PAD_RESERVE40,
	IMX7ULP_PAD_RESERVE41,
	IMX7ULP_PAD_RESERVE42,
	IMX7ULP_PAD_RESERVE43,
	IMX7ULP_PAD_RESERVE44,
	IMX7ULP_PAD_RESERVE45,
	IMX7ULP_PAD_RESERVE46,
	IMX7ULP_PAD_RESERVE47,
	IMX7ULP_PAD_PTF0,
	IMX7ULP_PAD_PTF1,
	IMX7ULP_PAD_PTF2,
	IMX7ULP_PAD_PTF3,
	IMX7ULP_PAD_PTF4,
	IMX7ULP_PAD_PTF5,
	IMX7ULP_PAD_PTF6,
	IMX7ULP_PAD_PTF7,
	IMX7ULP_PAD_PTF8,
	IMX7ULP_PAD_PTF9,
	IMX7ULP_PAD_PTF10,
	IMX7ULP_PAD_PTF11,
	IMX7ULP_PAD_PTF12,
	IMX7ULP_PAD_PTF13,
	IMX7ULP_PAD_PTF14,
	IMX7ULP_PAD_PTF15,
	IMX7ULP_PAD_PTF16,
	IMX7ULP_PAD_PTF17,
	IMX7ULP_PAD_PTF18,
	IMX7ULP_PAD_PTF19,
};

/* Pad names for the pinmux subsystem */
static const struct pinctrl_pin_desc imx7ulp_pinctrl_pads[] = {
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTC0),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTC1),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTC2),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTC3),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTC4),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTC5),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTC6),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTC7),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTC8),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTC9),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTC10),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTC11),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTC12),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTC13),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTC14),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTC15),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTC16),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTC17),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTC18),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTC19),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE0),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE1),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE2),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE3),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE4),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE5),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE6),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE7),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE8),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE9),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE10),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE11),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTD0),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTD1),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTD2),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTD3),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTD4),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTD5),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTD6),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTD7),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTD8),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTD9),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTD10),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTD11),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE12),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE13),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE14),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE15),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE16),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE17),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE18),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE19),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE20),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE21),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE22),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE23),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE24),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE25),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE26),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE27),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE28),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE29),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE30),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE31),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTE0),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTE1),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTE2),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTE3),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTE4),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTE5),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTE6),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTE7),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTE8),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTE9),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTE10),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTE11),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTE12),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTE13),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTE14),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTE15),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE32),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE33),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE34),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE35),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE36),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE37),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE38),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE39),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE40),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE41),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE42),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE43),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE44),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE45),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE46),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_RESERVE47),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTF0),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTF1),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTF2),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTF3),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTF4),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTF5),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTF6),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTF7),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTF8),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTF9),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTF10),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTF11),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTF12),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTF13),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTF14),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTF15),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTF16),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTF17),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTF18),
	IMX_PINCTRL_PIN(IMX7ULP_PAD_PTF19),
};

#define BM_OBE_ENABLED		BIT(17)
#define BM_IBE_ENABLED		BIT(16)
#define BM_MUX_MODE		0xf00
#define BP_MUX_MODE		8

static int imx7ulp_pmx_gpio_set_direction(struct pinctrl_dev *pctldev,
					  struct pinctrl_gpio_range *range,
					  unsigned offset, bool input)
{
	struct imx_pinctrl *ipctl = pinctrl_dev_get_drvdata(pctldev);
	const struct imx_pin_reg *pin_reg;
	u32 reg;

	pin_reg = &ipctl->pin_regs[offset];
	if (pin_reg->mux_reg == -1)
		return -EINVAL;

	reg = readl(ipctl->base + pin_reg->mux_reg);
	if (input)
		reg = (reg & ~BM_OBE_ENABLED) | BM_IBE_ENABLED;
	else
		reg = (reg & ~BM_IBE_ENABLED) | BM_OBE_ENABLED;
	writel(reg, ipctl->base + pin_reg->mux_reg);

	return 0;
}

static const struct imx_pinctrl_soc_info imx7ulp_pinctrl_info = {
	.pins = imx7ulp_pinctrl_pads,
	.npins = ARRAY_SIZE(imx7ulp_pinctrl_pads),
	.flags = ZERO_OFFSET_VALID | SHARE_MUX_CONF_REG,
	.gpio_set_direction = imx7ulp_pmx_gpio_set_direction,
	.mux_mask = BM_MUX_MODE,
	.mux_shift = BP_MUX_MODE,
};

static const struct of_device_id imx7ulp_pinctrl_of_match[] = {
	{ .compatible = "fsl,imx7ulp-iomuxc1", },
	{ /* sentinel */ }
};

static int imx7ulp_pinctrl_probe(struct platform_device *pdev)
{
	return imx_pinctrl_probe(pdev, &imx7ulp_pinctrl_info);
}

static struct platform_driver imx7ulp_pinctrl_driver = {
	.driver = {
		.name = "imx7ulp-pinctrl",
		.of_match_table = imx7ulp_pinctrl_of_match,
		.suppress_bind_attrs = true,
	},
	.probe = imx7ulp_pinctrl_probe,
};

static int __init imx7ulp_pinctrl_init(void)
{
	return platform_driver_register(&imx7ulp_pinctrl_driver);
}
arch_initcall(imx7ulp_pinctrl_init);
