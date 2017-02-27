/*
 * VF610 pinctrl driver based on imx pinmux and pinconf core
 *
 * Copyright 2013 Freescale Semiconductor, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/err.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/pinctrl/pinctrl.h>

#include "pinctrl-imx.h"

enum vf610_pads {
	VF610_PAD_PTA6 = 0,
	VF610_PAD_PTA8 = 1,
	VF610_PAD_PTA9 = 2,
	VF610_PAD_PTA10 = 3,
	VF610_PAD_PTA11 = 4,
	VF610_PAD_PTA12 = 5,
	VF610_PAD_PTA16 = 6,
	VF610_PAD_PTA17 = 7,
	VF610_PAD_PTA18 = 8,
	VF610_PAD_PTA19 = 9,
	VF610_PAD_PTA20 = 10,
	VF610_PAD_PTA21 = 11,
	VF610_PAD_PTA22 = 12,
	VF610_PAD_PTA23 = 13,
	VF610_PAD_PTA24 = 14,
	VF610_PAD_PTA25 = 15,
	VF610_PAD_PTA26 = 16,
	VF610_PAD_PTA27 = 17,
	VF610_PAD_PTA28 = 18,
	VF610_PAD_PTA29 = 19,
	VF610_PAD_PTA30 = 20,
	VF610_PAD_PTA31 = 21,
	VF610_PAD_PTB0 = 22,
	VF610_PAD_PTB1 = 23,
	VF610_PAD_PTB2 = 24,
	VF610_PAD_PTB3 = 25,
	VF610_PAD_PTB4 = 26,
	VF610_PAD_PTB5 = 27,
	VF610_PAD_PTB6 = 28,
	VF610_PAD_PTB7 = 29,
	VF610_PAD_PTB8 = 30,
	VF610_PAD_PTB9 = 31,
	VF610_PAD_PTB10 = 32,
	VF610_PAD_PTB11 = 33,
	VF610_PAD_PTB12 = 34,
	VF610_PAD_PTB13 = 35,
	VF610_PAD_PTB14 = 36,
	VF610_PAD_PTB15 = 37,
	VF610_PAD_PTB16 = 38,
	VF610_PAD_PTB17 = 39,
	VF610_PAD_PTB18 = 40,
	VF610_PAD_PTB19 = 41,
	VF610_PAD_PTB20 = 42,
	VF610_PAD_PTB21 = 43,
	VF610_PAD_PTB22 = 44,
	VF610_PAD_PTC0 = 45,
	VF610_PAD_PTC1 = 46,
	VF610_PAD_PTC2 = 47,
	VF610_PAD_PTC3 = 48,
	VF610_PAD_PTC4 = 49,
	VF610_PAD_PTC5 = 50,
	VF610_PAD_PTC6 = 51,
	VF610_PAD_PTC7 = 52,
	VF610_PAD_PTC8 = 53,
	VF610_PAD_PTC9 = 54,
	VF610_PAD_PTC10 = 55,
	VF610_PAD_PTC11 = 56,
	VF610_PAD_PTC12 = 57,
	VF610_PAD_PTC13 = 58,
	VF610_PAD_PTC14 = 59,
	VF610_PAD_PTC15 = 60,
	VF610_PAD_PTC16 = 61,
	VF610_PAD_PTC17 = 62,
	VF610_PAD_PTD31 = 63,
	VF610_PAD_PTD30 = 64,
	VF610_PAD_PTD29 = 65,
	VF610_PAD_PTD28 = 66,
	VF610_PAD_PTD27 = 67,
	VF610_PAD_PTD26 = 68,
	VF610_PAD_PTD25 = 69,
	VF610_PAD_PTD24 = 70,
	VF610_PAD_PTD23 = 71,
	VF610_PAD_PTD22 = 72,
	VF610_PAD_PTD21 = 73,
	VF610_PAD_PTD20 = 74,
	VF610_PAD_PTD19 = 75,
	VF610_PAD_PTD18 = 76,
	VF610_PAD_PTD17 = 77,
	VF610_PAD_PTD16 = 78,
	VF610_PAD_PTD0 = 79,
	VF610_PAD_PTD1 = 80,
	VF610_PAD_PTD2 = 81,
	VF610_PAD_PTD3 = 82,
	VF610_PAD_PTD4 = 83,
	VF610_PAD_PTD5 = 84,
	VF610_PAD_PTD6 = 85,
	VF610_PAD_PTD7 = 86,
	VF610_PAD_PTD8 = 87,
	VF610_PAD_PTD9 = 88,
	VF610_PAD_PTD10 = 89,
	VF610_PAD_PTD11 = 90,
	VF610_PAD_PTD12 = 91,
	VF610_PAD_PTD13 = 92,
	VF610_PAD_PTB23 = 93,
	VF610_PAD_PTB24 = 94,
	VF610_PAD_PTB25 = 95,
	VF610_PAD_PTB26 = 96,
	VF610_PAD_PTB27 = 97,
	VF610_PAD_PTB28 = 98,
	VF610_PAD_PTC26 = 99,
	VF610_PAD_PTC27 = 100,
	VF610_PAD_PTC28 = 101,
	VF610_PAD_PTC29 = 102,
	VF610_PAD_PTC30 = 103,
	VF610_PAD_PTC31 = 104,
	VF610_PAD_PTE0 = 105,
	VF610_PAD_PTE1 = 106,
	VF610_PAD_PTE2 = 107,
	VF610_PAD_PTE3 = 108,
	VF610_PAD_PTE4 = 109,
	VF610_PAD_PTE5 = 110,
	VF610_PAD_PTE6 = 111,
	VF610_PAD_PTE7 = 112,
	VF610_PAD_PTE8 = 113,
	VF610_PAD_PTE9 = 114,
	VF610_PAD_PTE10 = 115,
	VF610_PAD_PTE11 = 116,
	VF610_PAD_PTE12 = 117,
	VF610_PAD_PTE13 = 118,
	VF610_PAD_PTE14 = 119,
	VF610_PAD_PTE15 = 120,
	VF610_PAD_PTE16 = 121,
	VF610_PAD_PTE17 = 122,
	VF610_PAD_PTE18 = 123,
	VF610_PAD_PTE19 = 124,
	VF610_PAD_PTE20 = 125,
	VF610_PAD_PTE21 = 126,
	VF610_PAD_PTE22 = 127,
	VF610_PAD_PTE23 = 128,
	VF610_PAD_PTE24 = 129,
	VF610_PAD_PTE25 = 130,
	VF610_PAD_PTE26 = 131,
	VF610_PAD_PTE27 = 132,
	VF610_PAD_PTE28 = 133,
	VF610_PAD_PTA7 = 134,
};

/* Pad names for the pinmux subsystem */
static const struct pinctrl_pin_desc vf610_pinctrl_pads[] = {
	IMX_PINCTRL_PIN(VF610_PAD_PTA6),
	IMX_PINCTRL_PIN(VF610_PAD_PTA8),
	IMX_PINCTRL_PIN(VF610_PAD_PTA9),
	IMX_PINCTRL_PIN(VF610_PAD_PTA10),
	IMX_PINCTRL_PIN(VF610_PAD_PTA11),
	IMX_PINCTRL_PIN(VF610_PAD_PTA12),
	IMX_PINCTRL_PIN(VF610_PAD_PTA16),
	IMX_PINCTRL_PIN(VF610_PAD_PTA17),
	IMX_PINCTRL_PIN(VF610_PAD_PTA18),
	IMX_PINCTRL_PIN(VF610_PAD_PTA19),
	IMX_PINCTRL_PIN(VF610_PAD_PTA20),
	IMX_PINCTRL_PIN(VF610_PAD_PTA21),
	IMX_PINCTRL_PIN(VF610_PAD_PTA22),
	IMX_PINCTRL_PIN(VF610_PAD_PTA23),
	IMX_PINCTRL_PIN(VF610_PAD_PTA24),
	IMX_PINCTRL_PIN(VF610_PAD_PTA25),
	IMX_PINCTRL_PIN(VF610_PAD_PTA26),
	IMX_PINCTRL_PIN(VF610_PAD_PTA27),
	IMX_PINCTRL_PIN(VF610_PAD_PTA28),
	IMX_PINCTRL_PIN(VF610_PAD_PTA29),
	IMX_PINCTRL_PIN(VF610_PAD_PTA30),
	IMX_PINCTRL_PIN(VF610_PAD_PTA31),
	IMX_PINCTRL_PIN(VF610_PAD_PTB0),
	IMX_PINCTRL_PIN(VF610_PAD_PTB1),
	IMX_PINCTRL_PIN(VF610_PAD_PTB2),
	IMX_PINCTRL_PIN(VF610_PAD_PTB3),
	IMX_PINCTRL_PIN(VF610_PAD_PTB4),
	IMX_PINCTRL_PIN(VF610_PAD_PTB5),
	IMX_PINCTRL_PIN(VF610_PAD_PTB6),
	IMX_PINCTRL_PIN(VF610_PAD_PTB7),
	IMX_PINCTRL_PIN(VF610_PAD_PTB8),
	IMX_PINCTRL_PIN(VF610_PAD_PTB9),
	IMX_PINCTRL_PIN(VF610_PAD_PTB10),
	IMX_PINCTRL_PIN(VF610_PAD_PTB11),
	IMX_PINCTRL_PIN(VF610_PAD_PTB12),
	IMX_PINCTRL_PIN(VF610_PAD_PTB13),
	IMX_PINCTRL_PIN(VF610_PAD_PTB14),
	IMX_PINCTRL_PIN(VF610_PAD_PTB15),
	IMX_PINCTRL_PIN(VF610_PAD_PTB16),
	IMX_PINCTRL_PIN(VF610_PAD_PTB17),
	IMX_PINCTRL_PIN(VF610_PAD_PTB18),
	IMX_PINCTRL_PIN(VF610_PAD_PTB19),
	IMX_PINCTRL_PIN(VF610_PAD_PTB20),
	IMX_PINCTRL_PIN(VF610_PAD_PTB21),
	IMX_PINCTRL_PIN(VF610_PAD_PTB22),
	IMX_PINCTRL_PIN(VF610_PAD_PTC0),
	IMX_PINCTRL_PIN(VF610_PAD_PTC1),
	IMX_PINCTRL_PIN(VF610_PAD_PTC2),
	IMX_PINCTRL_PIN(VF610_PAD_PTC3),
	IMX_PINCTRL_PIN(VF610_PAD_PTC4),
	IMX_PINCTRL_PIN(VF610_PAD_PTC5),
	IMX_PINCTRL_PIN(VF610_PAD_PTC6),
	IMX_PINCTRL_PIN(VF610_PAD_PTC7),
	IMX_PINCTRL_PIN(VF610_PAD_PTC8),
	IMX_PINCTRL_PIN(VF610_PAD_PTC9),
	IMX_PINCTRL_PIN(VF610_PAD_PTC10),
	IMX_PINCTRL_PIN(VF610_PAD_PTC11),
	IMX_PINCTRL_PIN(VF610_PAD_PTC12),
	IMX_PINCTRL_PIN(VF610_PAD_PTC13),
	IMX_PINCTRL_PIN(VF610_PAD_PTC14),
	IMX_PINCTRL_PIN(VF610_PAD_PTC15),
	IMX_PINCTRL_PIN(VF610_PAD_PTC16),
	IMX_PINCTRL_PIN(VF610_PAD_PTC17),
	IMX_PINCTRL_PIN(VF610_PAD_PTD31),
	IMX_PINCTRL_PIN(VF610_PAD_PTD30),
	IMX_PINCTRL_PIN(VF610_PAD_PTD29),
	IMX_PINCTRL_PIN(VF610_PAD_PTD28),
	IMX_PINCTRL_PIN(VF610_PAD_PTD27),
	IMX_PINCTRL_PIN(VF610_PAD_PTD26),
	IMX_PINCTRL_PIN(VF610_PAD_PTD25),
	IMX_PINCTRL_PIN(VF610_PAD_PTD24),
	IMX_PINCTRL_PIN(VF610_PAD_PTD23),
	IMX_PINCTRL_PIN(VF610_PAD_PTD22),
	IMX_PINCTRL_PIN(VF610_PAD_PTD21),
	IMX_PINCTRL_PIN(VF610_PAD_PTD20),
	IMX_PINCTRL_PIN(VF610_PAD_PTD19),
	IMX_PINCTRL_PIN(VF610_PAD_PTD18),
	IMX_PINCTRL_PIN(VF610_PAD_PTD17),
	IMX_PINCTRL_PIN(VF610_PAD_PTD16),
	IMX_PINCTRL_PIN(VF610_PAD_PTD0),
	IMX_PINCTRL_PIN(VF610_PAD_PTD1),
	IMX_PINCTRL_PIN(VF610_PAD_PTD2),
	IMX_PINCTRL_PIN(VF610_PAD_PTD3),
	IMX_PINCTRL_PIN(VF610_PAD_PTD4),
	IMX_PINCTRL_PIN(VF610_PAD_PTD5),
	IMX_PINCTRL_PIN(VF610_PAD_PTD6),
	IMX_PINCTRL_PIN(VF610_PAD_PTD7),
	IMX_PINCTRL_PIN(VF610_PAD_PTD8),
	IMX_PINCTRL_PIN(VF610_PAD_PTD9),
	IMX_PINCTRL_PIN(VF610_PAD_PTD10),
	IMX_PINCTRL_PIN(VF610_PAD_PTD11),
	IMX_PINCTRL_PIN(VF610_PAD_PTD12),
	IMX_PINCTRL_PIN(VF610_PAD_PTD13),
	IMX_PINCTRL_PIN(VF610_PAD_PTB23),
	IMX_PINCTRL_PIN(VF610_PAD_PTB24),
	IMX_PINCTRL_PIN(VF610_PAD_PTB25),
	IMX_PINCTRL_PIN(VF610_PAD_PTB26),
	IMX_PINCTRL_PIN(VF610_PAD_PTB27),
	IMX_PINCTRL_PIN(VF610_PAD_PTB28),
	IMX_PINCTRL_PIN(VF610_PAD_PTC26),
	IMX_PINCTRL_PIN(VF610_PAD_PTC27),
	IMX_PINCTRL_PIN(VF610_PAD_PTC28),
	IMX_PINCTRL_PIN(VF610_PAD_PTC29),
	IMX_PINCTRL_PIN(VF610_PAD_PTC30),
	IMX_PINCTRL_PIN(VF610_PAD_PTC31),
	IMX_PINCTRL_PIN(VF610_PAD_PTE0),
	IMX_PINCTRL_PIN(VF610_PAD_PTE1),
	IMX_PINCTRL_PIN(VF610_PAD_PTE2),
	IMX_PINCTRL_PIN(VF610_PAD_PTE3),
	IMX_PINCTRL_PIN(VF610_PAD_PTE4),
	IMX_PINCTRL_PIN(VF610_PAD_PTE5),
	IMX_PINCTRL_PIN(VF610_PAD_PTE6),
	IMX_PINCTRL_PIN(VF610_PAD_PTE7),
	IMX_PINCTRL_PIN(VF610_PAD_PTE8),
	IMX_PINCTRL_PIN(VF610_PAD_PTE9),
	IMX_PINCTRL_PIN(VF610_PAD_PTE10),
	IMX_PINCTRL_PIN(VF610_PAD_PTE11),
	IMX_PINCTRL_PIN(VF610_PAD_PTE12),
	IMX_PINCTRL_PIN(VF610_PAD_PTE13),
	IMX_PINCTRL_PIN(VF610_PAD_PTE14),
	IMX_PINCTRL_PIN(VF610_PAD_PTE15),
	IMX_PINCTRL_PIN(VF610_PAD_PTE16),
	IMX_PINCTRL_PIN(VF610_PAD_PTE17),
	IMX_PINCTRL_PIN(VF610_PAD_PTE18),
	IMX_PINCTRL_PIN(VF610_PAD_PTE19),
	IMX_PINCTRL_PIN(VF610_PAD_PTE20),
	IMX_PINCTRL_PIN(VF610_PAD_PTE21),
	IMX_PINCTRL_PIN(VF610_PAD_PTE22),
	IMX_PINCTRL_PIN(VF610_PAD_PTE23),
	IMX_PINCTRL_PIN(VF610_PAD_PTE24),
	IMX_PINCTRL_PIN(VF610_PAD_PTE25),
	IMX_PINCTRL_PIN(VF610_PAD_PTE26),
	IMX_PINCTRL_PIN(VF610_PAD_PTE27),
	IMX_PINCTRL_PIN(VF610_PAD_PTE28),
	IMX_PINCTRL_PIN(VF610_PAD_PTA7),
};

static struct imx_pinctrl_soc_info vf610_pinctrl_info = {
	.pins = vf610_pinctrl_pads,
	.npins = ARRAY_SIZE(vf610_pinctrl_pads),
	.flags = SHARE_MUX_CONF_REG | ZERO_OFFSET_VALID,
};

static const struct of_device_id vf610_pinctrl_of_match[] = {
	{ .compatible = "fsl,vf610-iomuxc", },
	{ /* sentinel */ }
};

static int vf610_pinctrl_probe(struct platform_device *pdev)
{
	return imx_pinctrl_probe(pdev, &vf610_pinctrl_info);
}

static struct platform_driver vf610_pinctrl_driver = {
	.driver = {
		.name = "vf610-pinctrl",
		.of_match_table = vf610_pinctrl_of_match,
	},
	.probe = vf610_pinctrl_probe,
};

static int __init vf610_pinctrl_init(void)
{
	return platform_driver_register(&vf610_pinctrl_driver);
}
arch_initcall(vf610_pinctrl_init);
