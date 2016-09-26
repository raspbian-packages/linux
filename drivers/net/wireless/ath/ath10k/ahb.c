/*
 * Copyright (c) 2016 Qualcomm Atheros, Inc. All rights reserved.
 * Copyright (c) 2015 The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/clk.h>
#include <linux/reset.h>
#include "core.h"
#include "debug.h"
#include "pci.h"
#include "ahb.h"

static const struct of_device_id ath10k_ahb_of_match[] = {
	/* TODO: enable this entry once everything in place.
	 * { .compatible = "qcom,ipq4019-wifi",
	 *   .data = (void *)ATH10K_HW_QCA4019 },
	 */
	{ }
};

MODULE_DEVICE_TABLE(of, ath10k_ahb_of_match);

static inline struct ath10k_ahb *ath10k_ahb_priv(struct ath10k *ar)
{
	return &((struct ath10k_pci *)ar->drv_priv)->ahb[0];
}

static void ath10k_ahb_write32(struct ath10k *ar, u32 offset, u32 value)
{
	struct ath10k_ahb *ar_ahb = ath10k_ahb_priv(ar);

	iowrite32(value, ar_ahb->mem + offset);
}

static u32 ath10k_ahb_read32(struct ath10k *ar, u32 offset)
{
	struct ath10k_ahb *ar_ahb = ath10k_ahb_priv(ar);

	return ioread32(ar_ahb->mem + offset);
}

static u32 ath10k_ahb_gcc_read32(struct ath10k *ar, u32 offset)
{
	struct ath10k_ahb *ar_ahb = ath10k_ahb_priv(ar);

	return ioread32(ar_ahb->gcc_mem + offset);
}

static void ath10k_ahb_tcsr_write32(struct ath10k *ar, u32 offset, u32 value)
{
	struct ath10k_ahb *ar_ahb = ath10k_ahb_priv(ar);

	iowrite32(value, ar_ahb->tcsr_mem + offset);
}

static u32 ath10k_ahb_tcsr_read32(struct ath10k *ar, u32 offset)
{
	struct ath10k_ahb *ar_ahb = ath10k_ahb_priv(ar);

	return ioread32(ar_ahb->tcsr_mem + offset);
}

static u32 ath10k_ahb_soc_read32(struct ath10k *ar, u32 addr)
{
	return ath10k_ahb_read32(ar, RTC_SOC_BASE_ADDRESS + addr);
}

static int ath10k_ahb_get_num_banks(struct ath10k *ar)
{
	if (ar->hw_rev == ATH10K_HW_QCA4019)
		return 1;

	ath10k_warn(ar, "unknown number of banks, assuming 1\n");
	return 1;
}

static int ath10k_ahb_clock_init(struct ath10k *ar)
{
	struct ath10k_ahb *ar_ahb = ath10k_ahb_priv(ar);
	struct device *dev;
	int ret;

	dev = &ar_ahb->pdev->dev;

	ar_ahb->cmd_clk = clk_get(dev, "wifi_wcss_cmd");
	if (IS_ERR_OR_NULL(ar_ahb->cmd_clk)) {
		ath10k_err(ar, "failed to get cmd clk: %ld\n",
			   PTR_ERR(ar_ahb->cmd_clk));
		ret = ar_ahb->cmd_clk ? PTR_ERR(ar_ahb->cmd_clk) : -ENODEV;
		goto out;
	}

	ar_ahb->ref_clk = clk_get(dev, "wifi_wcss_ref");
	if (IS_ERR_OR_NULL(ar_ahb->ref_clk)) {
		ath10k_err(ar, "failed to get ref clk: %ld\n",
			   PTR_ERR(ar_ahb->ref_clk));
		ret = ar_ahb->ref_clk ? PTR_ERR(ar_ahb->ref_clk) : -ENODEV;
		goto err_cmd_clk_put;
	}

	ar_ahb->rtc_clk = clk_get(dev, "wifi_wcss_rtc");
	if (IS_ERR_OR_NULL(ar_ahb->rtc_clk)) {
		ath10k_err(ar, "failed to get rtc clk: %ld\n",
			   PTR_ERR(ar_ahb->rtc_clk));
		ret = ar_ahb->rtc_clk ? PTR_ERR(ar_ahb->rtc_clk) : -ENODEV;
		goto err_ref_clk_put;
	}

	return 0;

err_ref_clk_put:
	clk_put(ar_ahb->ref_clk);

err_cmd_clk_put:
	clk_put(ar_ahb->cmd_clk);

out:
	return ret;
}

static void ath10k_ahb_clock_deinit(struct ath10k *ar)
{
	struct ath10k_ahb *ar_ahb = ath10k_ahb_priv(ar);

	if (!IS_ERR_OR_NULL(ar_ahb->cmd_clk))
		clk_put(ar_ahb->cmd_clk);

	if (!IS_ERR_OR_NULL(ar_ahb->ref_clk))
		clk_put(ar_ahb->ref_clk);

	if (!IS_ERR_OR_NULL(ar_ahb->rtc_clk))
		clk_put(ar_ahb->rtc_clk);

	ar_ahb->cmd_clk = NULL;
	ar_ahb->ref_clk = NULL;
	ar_ahb->rtc_clk = NULL;
}

static int ath10k_ahb_clock_enable(struct ath10k *ar)
{
	struct ath10k_ahb *ar_ahb = ath10k_ahb_priv(ar);
	struct device *dev;
	int ret;

	dev = &ar_ahb->pdev->dev;

	if (IS_ERR_OR_NULL(ar_ahb->cmd_clk) ||
	    IS_ERR_OR_NULL(ar_ahb->ref_clk) ||
	    IS_ERR_OR_NULL(ar_ahb->rtc_clk)) {
		ath10k_err(ar, "clock(s) is/are not initialized\n");
		ret = -EIO;
		goto out;
	}

	ret = clk_prepare_enable(ar_ahb->cmd_clk);
	if (ret) {
		ath10k_err(ar, "failed to enable cmd clk: %d\n", ret);
		goto out;
	}

	ret = clk_prepare_enable(ar_ahb->ref_clk);
	if (ret) {
		ath10k_err(ar, "failed to enable ref clk: %d\n", ret);
		goto err_cmd_clk_disable;
	}

	ret = clk_prepare_enable(ar_ahb->rtc_clk);
	if (ret) {
		ath10k_err(ar, "failed to enable rtc clk: %d\n", ret);
		goto err_ref_clk_disable;
	}

	return 0;

err_ref_clk_disable:
	clk_disable_unprepare(ar_ahb->ref_clk);

err_cmd_clk_disable:
	clk_disable_unprepare(ar_ahb->cmd_clk);

out:
	return ret;
}

static void ath10k_ahb_clock_disable(struct ath10k *ar)
{
	struct ath10k_ahb *ar_ahb = ath10k_ahb_priv(ar);

	if (!IS_ERR_OR_NULL(ar_ahb->cmd_clk))
		clk_disable_unprepare(ar_ahb->cmd_clk);

	if (!IS_ERR_OR_NULL(ar_ahb->ref_clk))
		clk_disable_unprepare(ar_ahb->ref_clk);

	if (!IS_ERR_OR_NULL(ar_ahb->rtc_clk))
		clk_disable_unprepare(ar_ahb->rtc_clk);
}

static int ath10k_ahb_rst_ctrl_init(struct ath10k *ar)
{
	struct ath10k_ahb *ar_ahb = ath10k_ahb_priv(ar);
	struct device *dev;
	int ret;

	dev = &ar_ahb->pdev->dev;

	ar_ahb->core_cold_rst = reset_control_get(dev, "wifi_core_cold");
	if (IS_ERR_OR_NULL(ar_ahb->core_cold_rst)) {
		ath10k_err(ar, "failed to get core cold rst ctrl: %ld\n",
			   PTR_ERR(ar_ahb->core_cold_rst));
		ret = ar_ahb->core_cold_rst ?
			PTR_ERR(ar_ahb->core_cold_rst) : -ENODEV;
		goto out;
	}

	ar_ahb->radio_cold_rst = reset_control_get(dev, "wifi_radio_cold");
	if (IS_ERR_OR_NULL(ar_ahb->radio_cold_rst)) {
		ath10k_err(ar, "failed to get radio cold rst ctrl: %ld\n",
			   PTR_ERR(ar_ahb->radio_cold_rst));
		ret = ar_ahb->radio_cold_rst ?
			PTR_ERR(ar_ahb->radio_cold_rst) : -ENODEV;
		goto err_core_cold_rst_put;
	}

	ar_ahb->radio_warm_rst = reset_control_get(dev, "wifi_radio_warm");
	if (IS_ERR_OR_NULL(ar_ahb->radio_warm_rst)) {
		ath10k_err(ar, "failed to get radio warm rst ctrl: %ld\n",
			   PTR_ERR(ar_ahb->radio_warm_rst));
		ret = ar_ahb->radio_warm_rst ?
			PTR_ERR(ar_ahb->radio_warm_rst) : -ENODEV;
		goto err_radio_cold_rst_put;
	}

	ar_ahb->radio_srif_rst = reset_control_get(dev, "wifi_radio_srif");
	if (IS_ERR_OR_NULL(ar_ahb->radio_srif_rst)) {
		ath10k_err(ar, "failed to get radio srif rst ctrl: %ld\n",
			   PTR_ERR(ar_ahb->radio_srif_rst));
		ret = ar_ahb->radio_srif_rst ?
			PTR_ERR(ar_ahb->radio_srif_rst) : -ENODEV;
		goto err_radio_warm_rst_put;
	}

	ar_ahb->cpu_init_rst = reset_control_get(dev, "wifi_cpu_init");
	if (IS_ERR_OR_NULL(ar_ahb->cpu_init_rst)) {
		ath10k_err(ar, "failed to get cpu init rst ctrl: %ld\n",
			   PTR_ERR(ar_ahb->cpu_init_rst));
		ret = ar_ahb->cpu_init_rst ?
			PTR_ERR(ar_ahb->cpu_init_rst) : -ENODEV;
		goto err_radio_srif_rst_put;
	}

	return 0;

err_radio_srif_rst_put:
	reset_control_put(ar_ahb->radio_srif_rst);

err_radio_warm_rst_put:
	reset_control_put(ar_ahb->radio_warm_rst);

err_radio_cold_rst_put:
	reset_control_put(ar_ahb->radio_cold_rst);

err_core_cold_rst_put:
	reset_control_put(ar_ahb->core_cold_rst);

out:
	return ret;
}

static void ath10k_ahb_rst_ctrl_deinit(struct ath10k *ar)
{
	struct ath10k_ahb *ar_ahb = ath10k_ahb_priv(ar);

	if (!IS_ERR_OR_NULL(ar_ahb->core_cold_rst))
		reset_control_put(ar_ahb->core_cold_rst);

	if (!IS_ERR_OR_NULL(ar_ahb->radio_cold_rst))
		reset_control_put(ar_ahb->radio_cold_rst);

	if (!IS_ERR_OR_NULL(ar_ahb->radio_warm_rst))
		reset_control_put(ar_ahb->radio_warm_rst);

	if (!IS_ERR_OR_NULL(ar_ahb->radio_srif_rst))
		reset_control_put(ar_ahb->radio_srif_rst);

	if (!IS_ERR_OR_NULL(ar_ahb->cpu_init_rst))
		reset_control_put(ar_ahb->cpu_init_rst);

	ar_ahb->core_cold_rst = NULL;
	ar_ahb->radio_cold_rst = NULL;
	ar_ahb->radio_warm_rst = NULL;
	ar_ahb->radio_srif_rst = NULL;
	ar_ahb->cpu_init_rst = NULL;
}

static int ath10k_ahb_release_reset(struct ath10k *ar)
{
	struct ath10k_ahb *ar_ahb = ath10k_ahb_priv(ar);
	int ret;

	if (IS_ERR_OR_NULL(ar_ahb->radio_cold_rst) ||
	    IS_ERR_OR_NULL(ar_ahb->radio_warm_rst) ||
	    IS_ERR_OR_NULL(ar_ahb->radio_srif_rst) ||
	    IS_ERR_OR_NULL(ar_ahb->cpu_init_rst)) {
		ath10k_err(ar, "rst ctrl(s) is/are not initialized\n");
		return -EINVAL;
	}

	ret = reset_control_deassert(ar_ahb->radio_cold_rst);
	if (ret) {
		ath10k_err(ar, "failed to deassert radio cold rst: %d\n", ret);
		return ret;
	}

	ret = reset_control_deassert(ar_ahb->radio_warm_rst);
	if (ret) {
		ath10k_err(ar, "failed to deassert radio warm rst: %d\n", ret);
		return ret;
	}

	ret = reset_control_deassert(ar_ahb->radio_srif_rst);
	if (ret) {
		ath10k_err(ar, "failed to deassert radio srif rst: %d\n", ret);
		return ret;
	}

	ret = reset_control_deassert(ar_ahb->cpu_init_rst);
	if (ret) {
		ath10k_err(ar, "failed to deassert cpu init rst: %d\n", ret);
		return ret;
	}

	return 0;
}

static void ath10k_ahb_halt_axi_bus(struct ath10k *ar, u32 haltreq_reg,
				    u32 haltack_reg)
{
	unsigned long timeout;
	u32 val;

	/* Issue halt axi bus request */
	val = ath10k_ahb_tcsr_read32(ar, haltreq_reg);
	val |= AHB_AXI_BUS_HALT_REQ;
	ath10k_ahb_tcsr_write32(ar, haltreq_reg, val);

	/* Wait for axi bus halted ack */
	timeout = jiffies + msecs_to_jiffies(ATH10K_AHB_AXI_BUS_HALT_TIMEOUT);
	do {
		val = ath10k_ahb_tcsr_read32(ar, haltack_reg);
		if (val & AHB_AXI_BUS_HALT_ACK)
			break;

		mdelay(1);
	} while (time_before(jiffies, timeout));

	if (!(val & AHB_AXI_BUS_HALT_ACK)) {
		ath10k_err(ar, "failed to halt axi bus: %d\n", val);
		return;
	}

	ath10k_dbg(ar, ATH10K_DBG_AHB, "axi bus halted\n");
}

static void ath10k_ahb_halt_chip(struct ath10k *ar)
{
	struct ath10k_ahb *ar_ahb = ath10k_ahb_priv(ar);
	u32 core_id, glb_cfg_reg, haltreq_reg, haltack_reg;
	u32 val;
	int ret;

	if (IS_ERR_OR_NULL(ar_ahb->core_cold_rst) ||
	    IS_ERR_OR_NULL(ar_ahb->radio_cold_rst) ||
	    IS_ERR_OR_NULL(ar_ahb->radio_warm_rst) ||
	    IS_ERR_OR_NULL(ar_ahb->radio_srif_rst) ||
	    IS_ERR_OR_NULL(ar_ahb->cpu_init_rst)) {
		ath10k_err(ar, "rst ctrl(s) is/are not initialized\n");
		return;
	}

	core_id = ath10k_ahb_read32(ar, ATH10K_AHB_WLAN_CORE_ID_REG);

	switch (core_id) {
	case 0:
		glb_cfg_reg = ATH10K_AHB_TCSR_WIFI0_GLB_CFG;
		haltreq_reg = ATH10K_AHB_TCSR_WCSS0_HALTREQ;
		haltack_reg = ATH10K_AHB_TCSR_WCSS0_HALTACK;
		break;
	case 1:
		glb_cfg_reg = ATH10K_AHB_TCSR_WIFI1_GLB_CFG;
		haltreq_reg = ATH10K_AHB_TCSR_WCSS1_HALTREQ;
		haltack_reg = ATH10K_AHB_TCSR_WCSS1_HALTACK;
		break;
	default:
		ath10k_err(ar, "invalid core id %d found, skipping reset sequence\n",
			   core_id);
		return;
	}

	ath10k_ahb_halt_axi_bus(ar, haltreq_reg, haltack_reg);

	val = ath10k_ahb_tcsr_read32(ar, glb_cfg_reg);
	val |= TCSR_WIFIX_GLB_CFG_DISABLE_CORE_CLK;
	ath10k_ahb_tcsr_write32(ar, glb_cfg_reg, val);

	ret = reset_control_assert(ar_ahb->core_cold_rst);
	if (ret)
		ath10k_err(ar, "failed to assert core cold rst: %d\n", ret);
	msleep(1);

	ret = reset_control_assert(ar_ahb->radio_cold_rst);
	if (ret)
		ath10k_err(ar, "failed to assert radio cold rst: %d\n", ret);
	msleep(1);

	ret = reset_control_assert(ar_ahb->radio_warm_rst);
	if (ret)
		ath10k_err(ar, "failed to assert radio warm rst: %d\n", ret);
	msleep(1);

	ret = reset_control_assert(ar_ahb->radio_srif_rst);
	if (ret)
		ath10k_err(ar, "failed to assert radio srif rst: %d\n", ret);
	msleep(1);

	ret = reset_control_assert(ar_ahb->cpu_init_rst);
	if (ret)
		ath10k_err(ar, "failed to assert cpu init rst: %d\n", ret);
	msleep(10);

	/* Clear halt req and core clock disable req before
	 * deasserting wifi core reset.
	 */
	val = ath10k_ahb_tcsr_read32(ar, haltreq_reg);
	val &= ~AHB_AXI_BUS_HALT_REQ;
	ath10k_ahb_tcsr_write32(ar, haltreq_reg, val);

	val = ath10k_ahb_tcsr_read32(ar, glb_cfg_reg);
	val &= ~TCSR_WIFIX_GLB_CFG_DISABLE_CORE_CLK;
	ath10k_ahb_tcsr_write32(ar, glb_cfg_reg, val);

	ret = reset_control_deassert(ar_ahb->core_cold_rst);
	if (ret)
		ath10k_err(ar, "failed to deassert core cold rst: %d\n", ret);

	ath10k_dbg(ar, ATH10K_DBG_AHB, "core %d reset done\n", core_id);
}

static irqreturn_t ath10k_ahb_interrupt_handler(int irq, void *arg)
{
	struct ath10k *ar = arg;
	struct ath10k_pci *ar_pci = ath10k_pci_priv(ar);

	if (!ath10k_pci_irq_pending(ar))
		return IRQ_NONE;

	ath10k_pci_disable_and_clear_legacy_irq(ar);
	tasklet_schedule(&ar_pci->intr_tq);

	return IRQ_HANDLED;
}

static int ath10k_ahb_request_irq_legacy(struct ath10k *ar)
{
	struct ath10k_ahb *ar_ahb = ath10k_ahb_priv(ar);
	int ret;

	ret = request_irq(ar_ahb->irq,
			  ath10k_ahb_interrupt_handler,
			  IRQF_SHARED, "ath10k_ahb", ar);
	if (ret) {
		ath10k_warn(ar, "failed to request legacy irq %d: %d\n",
			    ar_ahb->irq, ret);
		return ret;
	}

	return 0;
}

static void ath10k_ahb_release_irq_legacy(struct ath10k *ar)
{
	struct ath10k_ahb *ar_ahb = ath10k_ahb_priv(ar);

	free_irq(ar_ahb->irq, ar);
}

static void ath10k_ahb_irq_disable(struct ath10k *ar)
{
	ath10k_ce_disable_interrupts(ar);
	ath10k_pci_disable_and_clear_legacy_irq(ar);
}

static int ath10k_ahb_resource_init(struct ath10k *ar)
{
	struct ath10k_ahb *ar_ahb = ath10k_ahb_priv(ar);
	struct platform_device *pdev;
	struct device *dev;
	struct resource *res;
	int ret;

	pdev = ar_ahb->pdev;
	dev = &pdev->dev;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		ath10k_err(ar, "failed to get memory resource\n");
		ret = -ENXIO;
		goto out;
	}

	ar_ahb->mem = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(ar_ahb->mem)) {
		ath10k_err(ar, "mem ioremap error\n");
		ret = PTR_ERR(ar_ahb->mem);
		goto out;
	}

	ar_ahb->mem_len = resource_size(res);

	ar_ahb->gcc_mem = ioremap_nocache(ATH10K_GCC_REG_BASE,
					  ATH10K_GCC_REG_SIZE);
	if (!ar_ahb->gcc_mem) {
		ath10k_err(ar, "gcc mem ioremap error\n");
		ret = -ENOMEM;
		goto err_mem_unmap;
	}

	ar_ahb->tcsr_mem = ioremap_nocache(ATH10K_TCSR_REG_BASE,
					   ATH10K_TCSR_REG_SIZE);
	if (!ar_ahb->tcsr_mem) {
		ath10k_err(ar, "tcsr mem ioremap error\n");
		ret = -ENOMEM;
		goto err_gcc_mem_unmap;
	}

	ret = dma_set_mask(&pdev->dev, DMA_BIT_MASK(32));
	if (ret) {
		ath10k_err(ar, "failed to set 32-bit dma mask: %d\n", ret);
		goto err_tcsr_mem_unmap;
	}

	ret = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(32));
	if (ret) {
		ath10k_err(ar, "failed to set 32-bit consistent dma: %d\n",
			   ret);
		goto err_tcsr_mem_unmap;
	}

	ret = ath10k_ahb_clock_init(ar);
	if (ret)
		goto err_tcsr_mem_unmap;

	ret = ath10k_ahb_rst_ctrl_init(ar);
	if (ret)
		goto err_clock_deinit;

	ar_ahb->irq = platform_get_irq_byname(pdev, "legacy");
	if (ar_ahb->irq < 0) {
		ath10k_err(ar, "failed to get irq number: %d\n", ar_ahb->irq);
		goto err_clock_deinit;
	}

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "irq: %d\n", ar_ahb->irq);

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "mem: 0x%p mem_len: %lu gcc mem: 0x%p tcsr_mem: 0x%p\n",
		   ar_ahb->mem, ar_ahb->mem_len,
		   ar_ahb->gcc_mem, ar_ahb->tcsr_mem);
	return 0;

err_clock_deinit:
	ath10k_ahb_clock_deinit(ar);

err_tcsr_mem_unmap:
	iounmap(ar_ahb->tcsr_mem);

err_gcc_mem_unmap:
	ar_ahb->tcsr_mem = NULL;
	iounmap(ar_ahb->gcc_mem);

err_mem_unmap:
	ar_ahb->gcc_mem = NULL;
	devm_iounmap(&pdev->dev, ar_ahb->mem);

out:
	ar_ahb->mem = NULL;
	return ret;
}

static void ath10k_ahb_resource_deinit(struct ath10k *ar)
{
	struct ath10k_ahb *ar_ahb = ath10k_ahb_priv(ar);
	struct device *dev;

	dev = &ar_ahb->pdev->dev;

	if (ar_ahb->mem)
		devm_iounmap(dev, ar_ahb->mem);

	if (ar_ahb->gcc_mem)
		iounmap(ar_ahb->gcc_mem);

	if (ar_ahb->tcsr_mem)
		iounmap(ar_ahb->tcsr_mem);

	ar_ahb->mem = NULL;
	ar_ahb->gcc_mem = NULL;
	ar_ahb->tcsr_mem = NULL;

	ath10k_ahb_clock_deinit(ar);
	ath10k_ahb_rst_ctrl_deinit(ar);
}

static int ath10k_ahb_prepare_device(struct ath10k *ar)
{
	u32 val;
	int ret;

	ret = ath10k_ahb_clock_enable(ar);
	if (ret) {
		ath10k_err(ar, "failed to enable clocks\n");
		return ret;
	}

	/* Clock for the target is supplied from outside of target (ie,
	 * external clock module controlled by the host). Target needs
	 * to know what frequency target cpu is configured which is needed
	 * for target internal use. Read target cpu frequency info from
	 * gcc register and write into target's scratch register where
	 * target expects this information.
	 */
	val = ath10k_ahb_gcc_read32(ar, ATH10K_AHB_GCC_FEPLL_PLL_DIV);
	ath10k_ahb_write32(ar, ATH10K_AHB_WIFI_SCRATCH_5_REG, val);

	ret = ath10k_ahb_release_reset(ar);
	if (ret)
		goto err_clk_disable;

	ath10k_ahb_irq_disable(ar);

	ath10k_ahb_write32(ar, FW_INDICATOR_ADDRESS, FW_IND_HOST_READY);

	ret = ath10k_pci_wait_for_target_init(ar);
	if (ret)
		goto err_halt_chip;

	return 0;

err_halt_chip:
	ath10k_ahb_halt_chip(ar);

err_clk_disable:
	ath10k_ahb_clock_disable(ar);

	return ret;
}

static int ath10k_ahb_chip_reset(struct ath10k *ar)
{
	int ret;

	ath10k_ahb_halt_chip(ar);
	ath10k_ahb_clock_disable(ar);

	ret = ath10k_ahb_prepare_device(ar);
	if (ret)
		return ret;

	return 0;
}

static int ath10k_ahb_wake_target_cpu(struct ath10k *ar)
{
	u32 addr, val;

	addr = SOC_CORE_BASE_ADDRESS | CORE_CTRL_ADDRESS;
	val = ath10k_ahb_read32(ar, addr);
	val |= ATH10K_AHB_CORE_CTRL_CPU_INTR_MASK;
	ath10k_ahb_write32(ar, addr, val);

	return 0;
}

static int ath10k_ahb_hif_start(struct ath10k *ar)
{
	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot ahb hif start\n");

	ath10k_ce_enable_interrupts(ar);
	ath10k_pci_enable_legacy_irq(ar);

	ath10k_pci_rx_post(ar);

	return 0;
}

static void ath10k_ahb_hif_stop(struct ath10k *ar)
{
	struct ath10k_ahb *ar_ahb = ath10k_ahb_priv(ar);

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot ahb hif stop\n");

	ath10k_ahb_irq_disable(ar);
	synchronize_irq(ar_ahb->irq);

	ath10k_pci_flush(ar);
}

static int ath10k_ahb_hif_power_up(struct ath10k *ar)
{
	int ret;

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "boot ahb hif power up\n");

	ret = ath10k_ahb_chip_reset(ar);
	if (ret) {
		ath10k_err(ar, "failed to reset chip: %d\n", ret);
		goto out;
	}

	ret = ath10k_pci_init_pipes(ar);
	if (ret) {
		ath10k_err(ar, "failed to initialize CE: %d\n", ret);
		goto out;
	}

	ret = ath10k_pci_init_config(ar);
	if (ret) {
		ath10k_err(ar, "failed to setup init config: %d\n", ret);
		goto err_ce_deinit;
	}

	ret = ath10k_ahb_wake_target_cpu(ar);
	if (ret) {
		ath10k_err(ar, "could not wake up target CPU: %d\n", ret);
		goto err_ce_deinit;
	}

	return 0;

err_ce_deinit:
	ath10k_pci_ce_deinit(ar);
out:
	return ret;
}

static const struct ath10k_hif_ops ath10k_ahb_hif_ops = {
	.tx_sg                  = ath10k_pci_hif_tx_sg,
	.diag_read              = ath10k_pci_hif_diag_read,
	.diag_write             = ath10k_pci_diag_write_mem,
	.exchange_bmi_msg       = ath10k_pci_hif_exchange_bmi_msg,
	.start                  = ath10k_ahb_hif_start,
	.stop                   = ath10k_ahb_hif_stop,
	.map_service_to_pipe    = ath10k_pci_hif_map_service_to_pipe,
	.get_default_pipe       = ath10k_pci_hif_get_default_pipe,
	.send_complete_check    = ath10k_pci_hif_send_complete_check,
	.get_free_queue_number  = ath10k_pci_hif_get_free_queue_number,
	.power_up               = ath10k_ahb_hif_power_up,
	.power_down             = ath10k_pci_hif_power_down,
	.read32                 = ath10k_ahb_read32,
	.write32                = ath10k_ahb_write32,
};

static const struct ath10k_bus_ops ath10k_ahb_bus_ops = {
	.read32		= ath10k_ahb_read32,
	.write32	= ath10k_ahb_write32,
	.get_num_banks	= ath10k_ahb_get_num_banks,
};

static int ath10k_ahb_probe(struct platform_device *pdev)
{
	struct ath10k *ar;
	struct ath10k_ahb *ar_ahb;
	struct ath10k_pci *ar_pci;
	const struct of_device_id *of_id;
	enum ath10k_hw_rev hw_rev;
	size_t size;
	int ret;
	u32 chip_id;

	of_id = of_match_device(ath10k_ahb_of_match, &pdev->dev);
	if (!of_id) {
		dev_err(&pdev->dev, "failed to find matching device tree id\n");
		return -EINVAL;
	}

	hw_rev = (enum ath10k_hw_rev)of_id->data;

	size = sizeof(*ar_pci) + sizeof(*ar_ahb);
	ar = ath10k_core_create(size, &pdev->dev, ATH10K_BUS_AHB,
				hw_rev, &ath10k_ahb_hif_ops);
	if (!ar) {
		dev_err(&pdev->dev, "failed to allocate core\n");
		return -ENOMEM;
	}

	ath10k_dbg(ar, ATH10K_DBG_BOOT, "ahb probe\n");

	ar_pci = ath10k_pci_priv(ar);
	ar_ahb = ath10k_ahb_priv(ar);

	ar_ahb->pdev = pdev;
	platform_set_drvdata(pdev, ar);

	ret = ath10k_ahb_resource_init(ar);
	if (ret)
		goto err_core_destroy;

	ar->dev_id = 0;
	ar_pci->mem = ar_ahb->mem;
	ar_pci->mem_len = ar_ahb->mem_len;
	ar_pci->ar = ar;
	ar_pci->bus_ops = &ath10k_ahb_bus_ops;

	ret = ath10k_pci_setup_resource(ar);
	if (ret) {
		ath10k_err(ar, "failed to setup resource: %d\n", ret);
		goto err_resource_deinit;
	}

	ath10k_pci_init_irq_tasklets(ar);

	ret = ath10k_ahb_request_irq_legacy(ar);
	if (ret)
		goto err_free_pipes;

	ret = ath10k_ahb_prepare_device(ar);
	if (ret)
		goto err_free_irq;

	ath10k_pci_ce_deinit(ar);

	chip_id = ath10k_ahb_soc_read32(ar, SOC_CHIP_ID_ADDRESS);
	if (chip_id == 0xffffffff) {
		ath10k_err(ar, "failed to get chip id\n");
		goto err_halt_device;
	}

	ret = ath10k_core_register(ar, chip_id);
	if (ret) {
		ath10k_err(ar, "failed to register driver core: %d\n", ret);
		goto err_halt_device;
	}

	return 0;

err_halt_device:
	ath10k_ahb_halt_chip(ar);
	ath10k_ahb_clock_disable(ar);

err_free_irq:
	ath10k_ahb_release_irq_legacy(ar);

err_free_pipes:
	ath10k_pci_free_pipes(ar);

err_resource_deinit:
	ath10k_ahb_resource_deinit(ar);

err_core_destroy:
	ath10k_core_destroy(ar);
	platform_set_drvdata(pdev, NULL);

	return ret;
}

static int ath10k_ahb_remove(struct platform_device *pdev)
{
	struct ath10k *ar = platform_get_drvdata(pdev);
	struct ath10k_ahb *ar_ahb;

	if (!ar)
		return -EINVAL;

	ar_ahb = ath10k_ahb_priv(ar);

	if (!ar_ahb)
		return -EINVAL;

	ath10k_dbg(ar, ATH10K_DBG_AHB, "ahb remove\n");

	ath10k_core_unregister(ar);
	ath10k_ahb_irq_disable(ar);
	ath10k_ahb_release_irq_legacy(ar);
	ath10k_pci_release_resource(ar);
	ath10k_ahb_halt_chip(ar);
	ath10k_ahb_clock_disable(ar);
	ath10k_ahb_resource_deinit(ar);
	ath10k_core_destroy(ar);

	platform_set_drvdata(pdev, NULL);

	return 0;
}

static struct platform_driver ath10k_ahb_driver = {
	.driver         = {
		.name   = "ath10k_ahb",
		.of_match_table = ath10k_ahb_of_match,
	},
	.probe  = ath10k_ahb_probe,
	.remove = ath10k_ahb_remove,
};

int ath10k_ahb_init(void)
{
	int ret;

	printk(KERN_ERR "AHB support is still work in progress\n");

	ret = platform_driver_register(&ath10k_ahb_driver);
	if (ret)
		printk(KERN_ERR "failed to register ath10k ahb driver: %d\n",
		       ret);
	return ret;
}

void ath10k_ahb_exit(void)
{
	platform_driver_unregister(&ath10k_ahb_driver);
}
