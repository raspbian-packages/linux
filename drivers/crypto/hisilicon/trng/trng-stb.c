// SPDX-License-Identifier: GPL-2.0-or-later OR MIT
/*
 * Device driver for True RNG in HiSTB SoCs
 *
 * Copyright (c) 2023 David Yang
 */

#include <crypto/internal/rng.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/hw_random.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of_device.h>

#define HISTB_TRNG_CTRL		0x0
#define  RNG_SOURCE			GENMASK(1, 0)
#define  DROP_ENABLE			BIT(5)
#define  POST_PROCESS_ENABLE		BIT(7)
#define  POST_PROCESS_DEPTH		GENMASK(15, 8)
#define HISTB_TRNG_NUMBER	0x4
#define HISTB_TRNG_STAT		0x8
#define  DATA_COUNT			GENMASK(2, 0)	/* max 4 */

struct histb_trng_priv {
	struct hwrng rng;
	void __iomem *base;
};

/*
 * Observed:
 * depth = 1 -> ~1ms
 * depth = 255 -> ~16ms
 */
static int histb_trng_wait(void __iomem *base)
{
	u32 val;

	return readl_relaxed_poll_timeout(base + HISTB_TRNG_STAT, val,
					  val & DATA_COUNT, 1000, 30 * 1000);
}

static void histb_trng_init(void __iomem *base, unsigned int depth)
{
	u32 val;

	val = readl_relaxed(base + HISTB_TRNG_CTRL);

	val &= ~RNG_SOURCE;
	val |= 2;

	val &= ~POST_PROCESS_DEPTH;
	val |= min(depth, 0xffu) << 8;

	val |= POST_PROCESS_ENABLE;
	val |= DROP_ENABLE;

	writel_relaxed(val, base + HISTB_TRNG_CTRL);
}

static int histb_trng_read(struct hwrng *rng, void *data, size_t max, bool wait)
{
	struct histb_trng_priv *priv = container_of(rng, typeof(*priv), rng);
	void __iomem *base = priv->base;

	for (int i = 0; i < max; i += sizeof(u32)) {
		if (!(readl_relaxed(base + HISTB_TRNG_STAT) & DATA_COUNT)) {
			if (!wait)
				return i;
			if (histb_trng_wait(base)) {
				pr_err("failed to generate random number, generated %d\n",
				       i);
				return i ? i : -ETIMEDOUT;
			}
		}
		*(u32 *) (data + i) = readl_relaxed(base + HISTB_TRNG_NUMBER);
	}

	return max;
}

static unsigned int histb_trng_get_depth(void __iomem *base)
{
	return (readl_relaxed(base + HISTB_TRNG_CTRL) & POST_PROCESS_DEPTH) >> 8;
}

static ssize_t
depth_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct histb_trng_priv *priv = dev_get_drvdata(dev);
	void __iomem *base = priv->base;

	return sprintf(buf, "%d\n", histb_trng_get_depth(base));
}

static ssize_t
depth_store(struct device *dev, struct device_attribute *attr,
	    const char *buf, size_t count)
{
	struct histb_trng_priv *priv = dev_get_drvdata(dev);
	void __iomem *base = priv->base;
	unsigned int depth;

	if (kstrtouint(buf, 0, &depth))
		return -ERANGE;

	histb_trng_init(base, depth);
	return count;
}

static DEVICE_ATTR_RW(depth);

static struct attribute *histb_trng_attrs[] = {
	&dev_attr_depth.attr,
	NULL,
};

ATTRIBUTE_GROUPS(histb_trng);

static int histb_trng_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct histb_trng_priv *priv;
	void __iomem *base;
	int ret;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(base))
		return -ENOMEM;

	histb_trng_init(base, 144);
	if (histb_trng_wait(base)) {
		dev_err(dev, "cannot bring up device\n");
		return -ENODEV;
	}

	priv->base = base;
	priv->rng.name = pdev->name;
	priv->rng.read = histb_trng_read;
	ret = devm_hwrng_register(dev, &priv->rng);
	if (ret) {
		dev_err(dev, "failed to register hwrng: %d\n", ret);
		return ret;
	}

	platform_set_drvdata(pdev, priv);
	dev_set_drvdata(dev, priv);
	return 0;
}

static const struct of_device_id histb_trng_of_match[] = {
	{ .compatible = "hisilicon,histb-trng", },
	{ }
};

static struct platform_driver histb_trng_driver = {
	.probe = histb_trng_probe,
	.driver = {
		.name = "histb-trng",
		.of_match_table = histb_trng_of_match,
		.dev_groups = histb_trng_groups,
	},
};

module_platform_driver(histb_trng_driver);

MODULE_DESCRIPTION("HiSTB True RNG");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("David Yang <mmyangfl@gmail.com>");
