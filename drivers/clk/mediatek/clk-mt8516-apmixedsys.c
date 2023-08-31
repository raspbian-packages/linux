// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2019 MediaTek Inc.
 *               James Liao <jamesjj.liao@mediatek.com>
 *               Fabien Parent <fparent@baylibre.com>
 *
 * Copyright (c) 2023 Collabora, Ltd.
 *               AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>
 */

#include <dt-bindings/clock/mt8516-clk.h>
#include <linux/clk.h>
#include <linux/of.h>
#include <linux/platform_device.h>

#include "clk-mtk.h"
#include "clk-pll.h"

#define MT8516_PLL_FMAX		(1502UL * MHZ)

#define CON0_MT8516_RST_BAR	BIT(27)

#define PLL_B(_id, _name, _reg, _pwr_reg, _en_mask, _flags, _pcwbits,	\
			_pd_reg, _pd_shift, _tuner_reg, _pcw_reg,	\
			_pcw_shift, _div_table) {			\
		.id = _id,						\
		.name = _name,						\
		.reg = _reg,						\
		.pwr_reg = _pwr_reg,					\
		.en_mask = _en_mask,					\
		.flags = _flags,					\
		.rst_bar_mask = CON0_MT8516_RST_BAR,			\
		.fmax = MT8516_PLL_FMAX,				\
		.pcwbits = _pcwbits,					\
		.pd_reg = _pd_reg,					\
		.pd_shift = _pd_shift,					\
		.tuner_reg = _tuner_reg,				\
		.pcw_reg = _pcw_reg,					\
		.pcw_shift = _pcw_shift,				\
		.div_table = _div_table,				\
	}

#define PLL(_id, _name, _reg, _pwr_reg, _en_mask, _flags, _pcwbits,	\
			_pd_reg, _pd_shift, _tuner_reg, _pcw_reg,	\
			_pcw_shift)					\
		PLL_B(_id, _name, _reg, _pwr_reg, _en_mask, _flags, _pcwbits, \
			_pd_reg, _pd_shift, _tuner_reg, _pcw_reg, _pcw_shift, \
			NULL)

static const struct mtk_pll_div_table mmpll_div_table[] = {
	{ .div = 0, .freq = MT8516_PLL_FMAX },
	{ .div = 1, .freq = 1000000000 },
	{ .div = 2, .freq = 604500000 },
	{ .div = 3, .freq = 253500000 },
	{ .div = 4, .freq = 126750000 },
	{ } /* sentinel */
};

static const struct mtk_pll_data plls[] = {
	PLL(CLK_APMIXED_ARMPLL, "armpll", 0x0100, 0x0110, 0, 0,
	    21, 0x0104, 24, 0, 0x0104, 0),
	PLL(CLK_APMIXED_MAINPLL, "mainpll", 0x0120, 0x0130, 0,
	    HAVE_RST_BAR, 21, 0x0124, 24, 0, 0x0124, 0),
	PLL(CLK_APMIXED_UNIVPLL, "univpll", 0x0140, 0x0150, 0x30000000,
	    HAVE_RST_BAR, 7, 0x0144, 24, 0, 0x0144, 0),
	PLL_B(CLK_APMIXED_MMPLL, "mmpll", 0x0160, 0x0170, 0, 0,
	      21, 0x0164, 24, 0, 0x0164, 0, mmpll_div_table),
	PLL(CLK_APMIXED_APLL1, "apll1", 0x0180, 0x0190, 0, 0,
	    31, 0x0180, 1, 0x0194, 0x0184, 0),
	PLL(CLK_APMIXED_APLL2, "apll2", 0x01A0, 0x01B0, 0, 0,
	    31, 0x01A0, 1, 0x01B4, 0x01A4, 0),
};

static int clk_mt8516_apmixed_probe(struct platform_device *pdev)
{
	void __iomem *base;
	struct clk_hw_onecell_data *clk_data;
	struct device_node *node = pdev->dev.of_node;
	struct device *dev = &pdev->dev;
	int ret;

	base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(base))
		return PTR_ERR(base);

	clk_data = mtk_devm_alloc_clk_data(dev, CLK_APMIXED_NR_CLK);
	if (!clk_data)
		return -ENOMEM;

	ret = mtk_clk_register_plls(node, plls, ARRAY_SIZE(plls), clk_data);
	if (ret)
		return ret;

	ret = of_clk_add_hw_provider(node, of_clk_hw_onecell_get, clk_data);
	if (ret)
		goto unregister_plls;

	return 0;

unregister_plls:
	mtk_clk_unregister_plls(plls, ARRAY_SIZE(plls), clk_data);

	return ret;
}

static const struct of_device_id of_match_clk_mt8516_apmixed[] = {
	{ .compatible = "mediatek,mt8516-apmixedsys" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, of_match_clk_mt8516_apmixed);

static struct platform_driver clk_mt8516_apmixed_drv = {
	.probe = clk_mt8516_apmixed_probe,
	.driver = {
		.name = "clk-mt8516-apmixed",
		.of_match_table = of_match_clk_mt8516_apmixed,
	},
};
builtin_platform_driver(clk_mt8516_apmixed_drv)

MODULE_DESCRIPTION("MediaTek MT8516 apmixedsys clocks driver");
MODULE_LICENSE("GPL");
