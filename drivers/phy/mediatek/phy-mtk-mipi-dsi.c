// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015 MediaTek Inc.
 */

#include "phy-mtk-mipi-dsi.h"

inline struct mtk_mipi_tx *mtk_mipi_tx_from_clk_hw(struct clk_hw *hw)
{
	return container_of(hw, struct mtk_mipi_tx, pll_hw);
}

int mtk_mipi_tx_pll_set_rate(struct clk_hw *hw, unsigned long rate,
			     unsigned long parent_rate)
{
	struct mtk_mipi_tx *mipi_tx = mtk_mipi_tx_from_clk_hw(hw);

	dev_dbg(mipi_tx->dev, "set rate: %lu Hz\n", rate);

	mipi_tx->data_rate = rate;

	return 0;
}

unsigned long mtk_mipi_tx_pll_recalc_rate(struct clk_hw *hw,
					  unsigned long parent_rate)
{
	struct mtk_mipi_tx *mipi_tx = mtk_mipi_tx_from_clk_hw(hw);

	return mipi_tx->data_rate;
}

static int mtk_mipi_tx_power_on(struct phy *phy)
{
	struct mtk_mipi_tx *mipi_tx = phy_get_drvdata(phy);
	int ret;

	/* Power up core and enable PLL */
	ret = clk_prepare_enable(mipi_tx->pll_hw.clk);
	if (ret < 0)
		return ret;

	/* Enable DSI Lane LDO outputs, disable pad tie low */
	mipi_tx->driver_data->mipi_tx_enable_signal(phy);
	return 0;
}

static int mtk_mipi_tx_power_off(struct phy *phy)
{
	struct mtk_mipi_tx *mipi_tx = phy_get_drvdata(phy);

	/* Enable pad tie low, disable DSI Lane LDO outputs */
	mipi_tx->driver_data->mipi_tx_disable_signal(phy);

	/* Disable PLL and power down core */
	clk_disable_unprepare(mipi_tx->pll_hw.clk);

	return 0;
}

static const struct phy_ops mtk_mipi_tx_ops = {
	.power_on = mtk_mipi_tx_power_on,
	.power_off = mtk_mipi_tx_power_off,
	.owner = THIS_MODULE,
};

static void mtk_mipi_tx_get_calibration_datal(struct mtk_mipi_tx *mipi_tx)
{
	struct nvmem_cell *cell;
	size_t len;
	u32 *buf;

	cell = nvmem_cell_get(mipi_tx->dev, "calibration-data");
	if (IS_ERR(cell)) {
		dev_info(mipi_tx->dev, "can't get nvmem_cell_get, ignore it\n");
		return;
	}
	buf = (u32 *)nvmem_cell_read(cell, &len);
	nvmem_cell_put(cell);

	if (IS_ERR(buf)) {
		dev_info(mipi_tx->dev, "can't get data, ignore it\n");
		return;
	}

	if (len < 3 * sizeof(u32)) {
		dev_info(mipi_tx->dev, "invalid calibration data\n");
		kfree(buf);
		return;
	}

	mipi_tx->rt_code[0] = ((buf[0] >> 6 & 0x1f) << 5) |
			       (buf[0] >> 11 & 0x1f);
	mipi_tx->rt_code[1] = ((buf[1] >> 27 & 0x1f) << 5) |
			       (buf[0] >> 1 & 0x1f);
	mipi_tx->rt_code[2] = ((buf[1] >> 17 & 0x1f) << 5) |
			       (buf[1] >> 22 & 0x1f);
	mipi_tx->rt_code[3] = ((buf[1] >> 7 & 0x1f) << 5) |
			       (buf[1] >> 12 & 0x1f);
	mipi_tx->rt_code[4] = ((buf[2] >> 27 & 0x1f) << 5) |
			       (buf[1] >> 2 & 0x1f);
	kfree(buf);
}

static int mtk_mipi_tx_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct mtk_mipi_tx *mipi_tx;
	const char *ref_clk_name;
	struct clk *ref_clk;
	struct clk_init_data clk_init = {
		.num_parents = 1,
		.parent_names = (const char * const *)&ref_clk_name,
		.flags = CLK_SET_RATE_GATE,
	};
	struct phy *phy;
	struct phy_provider *phy_provider;
	int ret;

	mipi_tx = devm_kzalloc(dev, sizeof(*mipi_tx), GFP_KERNEL);
	if (!mipi_tx)
		return -ENOMEM;

	mipi_tx->driver_data = of_device_get_match_data(dev);
	if (!mipi_tx->driver_data)
		return -ENODEV;

	mipi_tx->regs = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(mipi_tx->regs))
		return PTR_ERR(mipi_tx->regs);

	ref_clk = devm_clk_get(dev, NULL);
	if (IS_ERR(ref_clk))
		return dev_err_probe(dev, PTR_ERR(ref_clk),
				     "Failed to get reference clock\n");

	ret = of_property_read_u32(dev->of_node, "drive-strength-microamp",
				   &mipi_tx->mipitx_drive);
	/* If can't get the "mipi_tx->mipitx_drive", set it default 0x8 */
	if (ret < 0)
		mipi_tx->mipitx_drive = 4600;

	/* check the mipitx_drive valid */
	if (mipi_tx->mipitx_drive > 6000 || mipi_tx->mipitx_drive < 3000) {
		dev_warn(dev, "drive-strength-microamp is invalid %d, not in 3000 ~ 6000\n",
			 mipi_tx->mipitx_drive);
		mipi_tx->mipitx_drive = clamp_val(mipi_tx->mipitx_drive, 3000,
						  6000);
	}

	ref_clk_name = __clk_get_name(ref_clk);

	ret = of_property_read_string(dev->of_node, "clock-output-names",
				      &clk_init.name);
	if (ret < 0)
		return dev_err_probe(dev, ret, "Failed to read clock-output-names\n");

	clk_init.ops = mipi_tx->driver_data->mipi_tx_clk_ops;

	mipi_tx->pll_hw.init = &clk_init;
	ret = devm_clk_hw_register(dev, &mipi_tx->pll_hw);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to register PLL\n");

	phy = devm_phy_create(dev, NULL, &mtk_mipi_tx_ops);
	if (IS_ERR(phy))
		return dev_err_probe(dev, PTR_ERR(phy), "Failed to create MIPI D-PHY\n");

	phy_set_drvdata(phy, mipi_tx);

	phy_provider = devm_of_phy_provider_register(dev, of_phy_simple_xlate);
	if (IS_ERR(phy_provider))
		return PTR_ERR(phy_provider);

	mipi_tx->dev = dev;

	mtk_mipi_tx_get_calibration_datal(mipi_tx);

	return devm_of_clk_add_hw_provider(dev, of_clk_hw_simple_get, &mipi_tx->pll_hw);
}

static const struct of_device_id mtk_mipi_tx_match[] = {
	{ .compatible = "mediatek,mt2701-mipi-tx", .data = &mt2701_mipitx_data },
	{ .compatible = "mediatek,mt8173-mipi-tx", .data = &mt8173_mipitx_data },
	{ .compatible = "mediatek,mt8183-mipi-tx", .data = &mt8183_mipitx_data },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, mtk_mipi_tx_match);

static struct platform_driver mtk_mipi_tx_driver = {
	.probe = mtk_mipi_tx_probe,
	.driver = {
		.name = "mediatek-mipi-tx",
		.of_match_table = mtk_mipi_tx_match,
	},
};
module_platform_driver(mtk_mipi_tx_driver);

MODULE_DESCRIPTION("MediaTek MIPI TX Driver");
MODULE_LICENSE("GPL v2");
