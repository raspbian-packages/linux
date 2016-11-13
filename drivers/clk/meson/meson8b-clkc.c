/*
 * AmLogic S805 / Meson8b Clock Controller Driver
 *
 * Copyright (c) 2015 Endless Mobile, Inc.
 * Author: Carlo Caione <carlo@endlessm.com>
 *
 * Copyright (c) 2016 BayLibre, Inc.
 * Michael Turquette <mturquette@baylibre.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/of_address.h>
#include <dt-bindings/clock/meson8b-clkc.h>
#include <linux/platform_device.h>
#include <linux/init.h>

#include "clkc.h"

/*
 * Clock controller register offsets
 *
 * Register offsets from the HardKernel[0] data sheet are listed in comment
 * blocks below. Those offsets must be multiplied by 4 before adding them to
 * the base address to get the right value
 *
 * [0] http://dn.odroid.com/S805/Datasheet/S805_Datasheet%20V0.8%2020150126.pdf
 */
#define MESON8B_REG_SYS_CPU_CNTL1	0x015c /* 0x57 offset in data sheet */
#define MESON8B_REG_HHI_MPEG		0x0174 /* 0x5d offset in data sheet */
#define MESON8B_REG_MALI		0x01b0 /* 0x6c offset in data sheet */
#define MESON8B_REG_PLL_FIXED		0x0280
#define MESON8B_REG_PLL_SYS		0x0300
#define MESON8B_REG_PLL_VID		0x0320

static DEFINE_SPINLOCK(clk_lock);

static const struct pll_rate_table sys_pll_rate_table[] = {
	PLL_RATE(312000000, 52, 1, 2),
	PLL_RATE(336000000, 56, 1, 2),
	PLL_RATE(360000000, 60, 1, 2),
	PLL_RATE(384000000, 64, 1, 2),
	PLL_RATE(408000000, 68, 1, 2),
	PLL_RATE(432000000, 72, 1, 2),
	PLL_RATE(456000000, 76, 1, 2),
	PLL_RATE(480000000, 80, 1, 2),
	PLL_RATE(504000000, 84, 1, 2),
	PLL_RATE(528000000, 88, 1, 2),
	PLL_RATE(552000000, 92, 1, 2),
	PLL_RATE(576000000, 96, 1, 2),
	PLL_RATE(600000000, 50, 1, 1),
	PLL_RATE(624000000, 52, 1, 1),
	PLL_RATE(648000000, 54, 1, 1),
	PLL_RATE(672000000, 56, 1, 1),
	PLL_RATE(696000000, 58, 1, 1),
	PLL_RATE(720000000, 60, 1, 1),
	PLL_RATE(744000000, 62, 1, 1),
	PLL_RATE(768000000, 64, 1, 1),
	PLL_RATE(792000000, 66, 1, 1),
	PLL_RATE(816000000, 68, 1, 1),
	PLL_RATE(840000000, 70, 1, 1),
	PLL_RATE(864000000, 72, 1, 1),
	PLL_RATE(888000000, 74, 1, 1),
	PLL_RATE(912000000, 76, 1, 1),
	PLL_RATE(936000000, 78, 1, 1),
	PLL_RATE(960000000, 80, 1, 1),
	PLL_RATE(984000000, 82, 1, 1),
	PLL_RATE(1008000000, 84, 1, 1),
	PLL_RATE(1032000000, 86, 1, 1),
	PLL_RATE(1056000000, 88, 1, 1),
	PLL_RATE(1080000000, 90, 1, 1),
	PLL_RATE(1104000000, 92, 1, 1),
	PLL_RATE(1128000000, 94, 1, 1),
	PLL_RATE(1152000000, 96, 1, 1),
	PLL_RATE(1176000000, 98, 1, 1),
	PLL_RATE(1200000000, 50, 1, 0),
	PLL_RATE(1224000000, 51, 1, 0),
	PLL_RATE(1248000000, 52, 1, 0),
	PLL_RATE(1272000000, 53, 1, 0),
	PLL_RATE(1296000000, 54, 1, 0),
	PLL_RATE(1320000000, 55, 1, 0),
	PLL_RATE(1344000000, 56, 1, 0),
	PLL_RATE(1368000000, 57, 1, 0),
	PLL_RATE(1392000000, 58, 1, 0),
	PLL_RATE(1416000000, 59, 1, 0),
	PLL_RATE(1440000000, 60, 1, 0),
	PLL_RATE(1464000000, 61, 1, 0),
	PLL_RATE(1488000000, 62, 1, 0),
	PLL_RATE(1512000000, 63, 1, 0),
	PLL_RATE(1536000000, 64, 1, 0),
	{ /* sentinel */ },
};

static const struct clk_div_table cpu_div_table[] = {
	{ .val = 1, .div = 1 },
	{ .val = 2, .div = 2 },
	{ .val = 3, .div = 3 },
	{ .val = 2, .div = 4 },
	{ .val = 3, .div = 6 },
	{ .val = 4, .div = 8 },
	{ .val = 5, .div = 10 },
	{ .val = 6, .div = 12 },
	{ .val = 7, .div = 14 },
	{ .val = 8, .div = 16 },
	{ /* sentinel */ },
};

static struct clk_fixed_rate meson8b_xtal = {
	.fixed_rate = 24000000,
	.hw.init = &(struct clk_init_data){
		.name = "xtal",
		.num_parents = 0,
		.ops = &clk_fixed_rate_ops,
	},
};

static struct meson_clk_pll meson8b_fixed_pll = {
	.m = {
		.reg_off = MESON8B_REG_PLL_FIXED,
		.shift   = 0,
		.width   = 9,
	},
	.n = {
		.reg_off = MESON8B_REG_PLL_FIXED,
		.shift   = 9,
		.width   = 5,
	},
	.od = {
		.reg_off = MESON8B_REG_PLL_FIXED,
		.shift   = 16,
		.width   = 2,
	},
	.lock = &clk_lock,
	.hw.init = &(struct clk_init_data){
		.name = "fixed_pll",
		.ops = &meson_clk_pll_ro_ops,
		.parent_names = (const char *[]){ "xtal" },
		.num_parents = 1,
		.flags = CLK_GET_RATE_NOCACHE,
	},
};

static struct meson_clk_pll meson8b_vid_pll = {
	.m = {
		.reg_off = MESON8B_REG_PLL_VID,
		.shift   = 0,
		.width   = 9,
	},
	.n = {
		.reg_off = MESON8B_REG_PLL_VID,
		.shift   = 9,
		.width   = 5,
	},
	.od = {
		.reg_off = MESON8B_REG_PLL_VID,
		.shift   = 16,
		.width   = 2,
	},
	.lock = &clk_lock,
	.hw.init = &(struct clk_init_data){
		.name = "vid_pll",
		.ops = &meson_clk_pll_ro_ops,
		.parent_names = (const char *[]){ "xtal" },
		.num_parents = 1,
		.flags = CLK_GET_RATE_NOCACHE,
	},
};

static struct meson_clk_pll meson8b_sys_pll = {
	.m = {
		.reg_off = MESON8B_REG_PLL_SYS,
		.shift   = 0,
		.width   = 9,
	},
	.n = {
		.reg_off = MESON8B_REG_PLL_SYS,
		.shift   = 9,
		.width   = 5,
	},
	.od = {
		.reg_off = MESON8B_REG_PLL_SYS,
		.shift   = 16,
		.width   = 2,
	},
	.rate_table = sys_pll_rate_table,
	.rate_count = ARRAY_SIZE(sys_pll_rate_table),
	.lock = &clk_lock,
	.hw.init = &(struct clk_init_data){
		.name = "sys_pll",
		.ops = &meson_clk_pll_ops,
		.parent_names = (const char *[]){ "xtal" },
		.num_parents = 1,
		.flags = CLK_GET_RATE_NOCACHE,
	},
};

static struct clk_fixed_factor meson8b_fclk_div2 = {
	.mult = 1,
	.div = 2,
	.hw.init = &(struct clk_init_data){
		.name = "fclk_div2",
		.ops = &clk_fixed_factor_ops,
		.parent_names = (const char *[]){ "fixed_pll" },
		.num_parents = 1,
	},
};

static struct clk_fixed_factor meson8b_fclk_div3 = {
	.mult = 1,
	.div = 3,
	.hw.init = &(struct clk_init_data){
		.name = "fclk_div3",
		.ops = &clk_fixed_factor_ops,
		.parent_names = (const char *[]){ "fixed_pll" },
		.num_parents = 1,
	},
};

static struct clk_fixed_factor meson8b_fclk_div4 = {
	.mult = 1,
	.div = 4,
	.hw.init = &(struct clk_init_data){
		.name = "fclk_div4",
		.ops = &clk_fixed_factor_ops,
		.parent_names = (const char *[]){ "fixed_pll" },
		.num_parents = 1,
	},
};

static struct clk_fixed_factor meson8b_fclk_div5 = {
	.mult = 1,
	.div = 5,
	.hw.init = &(struct clk_init_data){
		.name = "fclk_div5",
		.ops = &clk_fixed_factor_ops,
		.parent_names = (const char *[]){ "fixed_pll" },
		.num_parents = 1,
	},
};

static struct clk_fixed_factor meson8b_fclk_div7 = {
	.mult = 1,
	.div = 7,
	.hw.init = &(struct clk_init_data){
		.name = "fclk_div7",
		.ops = &clk_fixed_factor_ops,
		.parent_names = (const char *[]){ "fixed_pll" },
		.num_parents = 1,
	},
};

/*
 * FIXME cpu clocks and the legacy composite clocks (e.g. clk81) are both PLL
 * post-dividers and should be modeled with their respective PLLs via the
 * forthcoming coordinated clock rates feature
 */
static struct meson_clk_cpu meson8b_cpu_clk = {
	.reg_off = MESON8B_REG_SYS_CPU_CNTL1,
	.div_table = cpu_div_table,
	.clk_nb.notifier_call = meson_clk_cpu_notifier_cb,
	.hw.init = &(struct clk_init_data){
		.name = "cpu_clk",
		.ops = &meson_clk_cpu_ops,
		.parent_names = (const char *[]){ "sys_pll" },
		.num_parents = 1,
	},
};

static u32 mux_table_clk81[]	= { 6, 5, 7 };

struct clk_mux meson8b_mpeg_clk_sel = {
	.reg = (void *)MESON8B_REG_HHI_MPEG,
	.mask = 0x7,
	.shift = 12,
	.flags = CLK_MUX_READ_ONLY,
	.table = mux_table_clk81,
	.lock = &clk_lock,
	.hw.init = &(struct clk_init_data){
		.name = "mpeg_clk_sel",
		.ops = &clk_mux_ro_ops,
		/*
		 * FIXME bits 14:12 selects from 8 possible parents:
		 * xtal, 1'b0 (wtf), fclk_div7, mpll_clkout1, mpll_clkout2,
		 * fclk_div4, fclk_div3, fclk_div5
		 */
		.parent_names = (const char *[]){ "fclk_div3", "fclk_div4",
			"fclk_div5" },
		.num_parents = 3,
		.flags = (CLK_SET_RATE_NO_REPARENT | CLK_IGNORE_UNUSED),
	},
};

struct clk_divider meson8b_mpeg_clk_div = {
	.reg = (void *)MESON8B_REG_HHI_MPEG,
	.shift = 0,
	.width = 7,
	.lock = &clk_lock,
	.hw.init = &(struct clk_init_data){
		.name = "mpeg_clk_div",
		.ops = &clk_divider_ops,
		.parent_names = (const char *[]){ "mpeg_clk_sel" },
		.num_parents = 1,
		.flags = (CLK_SET_RATE_PARENT | CLK_IGNORE_UNUSED),
	},
};

struct clk_gate meson8b_clk81 = {
	.reg = (void *)MESON8B_REG_HHI_MPEG,
	.bit_idx = 7,
	.lock = &clk_lock,
	.hw.init = &(struct clk_init_data){
		.name = "clk81",
		.ops = &clk_gate_ops,
		.parent_names = (const char *[]){ "mpeg_clk_div" },
		.num_parents = 1,
		.flags = (CLK_SET_RATE_PARENT | CLK_IGNORE_UNUSED),
	},
};

static struct clk_hw_onecell_data meson8b_hw_onecell_data = {
	.hws = {
		[CLKID_XTAL] = &meson8b_xtal.hw,
		[CLKID_PLL_FIXED] = &meson8b_fixed_pll.hw,
		[CLKID_PLL_VID] = &meson8b_vid_pll.hw,
		[CLKID_PLL_SYS] = &meson8b_sys_pll.hw,
		[CLKID_FCLK_DIV2] = &meson8b_fclk_div2.hw,
		[CLKID_FCLK_DIV3] = &meson8b_fclk_div3.hw,
		[CLKID_FCLK_DIV4] = &meson8b_fclk_div4.hw,
		[CLKID_FCLK_DIV5] = &meson8b_fclk_div5.hw,
		[CLKID_FCLK_DIV7] = &meson8b_fclk_div7.hw,
		[CLKID_CPUCLK] = &meson8b_cpu_clk.hw,
		[CLKID_MPEG_SEL] = &meson8b_mpeg_clk_sel.hw,
		[CLKID_MPEG_DIV] = &meson8b_mpeg_clk_div.hw,
		[CLKID_CLK81] = &meson8b_clk81.hw,
	},
	.num = CLK_NR_CLKS,
};

static struct meson_clk_pll *const meson8b_clk_plls[] = {
	&meson8b_fixed_pll,
	&meson8b_vid_pll,
	&meson8b_sys_pll,
};

static int meson8b_clkc_probe(struct platform_device *pdev)
{
	void __iomem *clk_base;
	int ret, clkid, i;
	struct clk_hw *parent_hw;
	struct clk *parent_clk;
	struct device *dev = &pdev->dev;

	/*  Generic clocks and PLLs */
	clk_base = of_iomap(dev->of_node, 1);
	if (!clk_base) {
		pr_err("%s: Unable to map clk base\n", __func__);
		return -ENXIO;
	}

	/* Populate base address for PLLs */
	for (i = 0; i < ARRAY_SIZE(meson8b_clk_plls); i++)
		meson8b_clk_plls[i]->base = clk_base;

	/* Populate the base address for CPU clk */
	meson8b_cpu_clk.base = clk_base;

	/* Populate the base address for the MPEG clks */
	meson8b_mpeg_clk_sel.reg = clk_base + (u32)meson8b_mpeg_clk_sel.reg;
	meson8b_mpeg_clk_div.reg = clk_base + (u32)meson8b_mpeg_clk_div.reg;
	meson8b_clk81.reg = clk_base + (u32)meson8b_clk81.reg;

	/*
	 * register all clks
	 * CLKID_UNUSED = 0, so skip it and start with CLKID_XTAL = 1
	 */
	for (clkid = CLKID_XTAL; clkid < CLK_NR_CLKS; clkid++) {
		/* array might be sparse */
		if (!meson8b_hw_onecell_data.hws[clkid])
			continue;

		/* FIXME convert to devm_clk_register */
		ret = devm_clk_hw_register(dev, meson8b_hw_onecell_data.hws[clkid]);
		if (ret)
			goto iounmap;
	}

	/*
	 * Register CPU clk notifier
	 *
	 * FIXME this is wrong for a lot of reasons. First, the muxes should be
	 * struct clk_hw objects. Second, we shouldn't program the muxes in
	 * notifier handlers. The tricky programming sequence will be handled
	 * by the forthcoming coordinated clock rates mechanism once that
	 * feature is released.
	 *
	 * Furthermore, looking up the parent this way is terrible. At some
	 * point we will stop allocating a default struct clk when registering
	 * a new clk_hw, and this hack will no longer work. Releasing the ccr
	 * feature before that time solves the problem :-)
	 */
	parent_hw = clk_hw_get_parent(&meson8b_cpu_clk.hw);
	parent_clk = parent_hw->clk;
	ret = clk_notifier_register(parent_clk, &meson8b_cpu_clk.clk_nb);
	if (ret) {
		pr_err("%s: failed to register clock notifier for cpu_clk\n",
				__func__);
		goto iounmap;
	}

	return of_clk_add_hw_provider(dev->of_node, of_clk_hw_onecell_get,
			&meson8b_hw_onecell_data);

iounmap:
	iounmap(clk_base);
	return ret;
}

static const struct of_device_id meson8b_clkc_match_table[] = {
	{ .compatible = "amlogic,meson8b-clkc" },
	{ }
};

static struct platform_driver meson8b_driver = {
	.probe		= meson8b_clkc_probe,
	.driver		= {
		.name	= "meson8b-clkc",
		.of_match_table = meson8b_clkc_match_table,
	},
};

static int __init meson8b_clkc_init(void)
{
	return platform_driver_register(&meson8b_driver);
}
device_initcall(meson8b_clkc_init);
