/*
 * Driver for Socionext External Interrupt Unit (EXIU)
 *
 * Copyright (c) 2017 Linaro, Ltd. <ard.biesheuvel@linaro.org>
 *
 * Based on irq-tegra.c:
 *   Copyright (C) 2011 Google, Inc.
 *   Copyright (C) 2010,2013, NVIDIA Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>

#include <dt-bindings/interrupt-controller/arm-gic.h>

#define NUM_IRQS	32

#define EIMASK		0x00
#define EISRCSEL	0x04
#define EIREQSTA	0x08
#define EIRAWREQSTA	0x0C
#define EIREQCLR	0x10
#define EILVL		0x14
#define EIEDG		0x18
#define EISIR		0x1C

struct exiu_irq_data {
	void __iomem	*base;
	u32		spi_base;
};

static void exiu_irq_eoi(struct irq_data *d)
{
	struct exiu_irq_data *data = irq_data_get_irq_chip_data(d);

	writel(BIT(d->hwirq), data->base + EIREQCLR);
	irq_chip_eoi_parent(d);
}

static void exiu_irq_mask(struct irq_data *d)
{
	struct exiu_irq_data *data = irq_data_get_irq_chip_data(d);
	u32 val;

	val = readl_relaxed(data->base + EIMASK) | BIT(d->hwirq);
	writel_relaxed(val, data->base + EIMASK);
	irq_chip_mask_parent(d);
}

static void exiu_irq_unmask(struct irq_data *d)
{
	struct exiu_irq_data *data = irq_data_get_irq_chip_data(d);
	u32 val;

	val = readl_relaxed(data->base + EIMASK) & ~BIT(d->hwirq);
	writel_relaxed(val, data->base + EIMASK);
	irq_chip_unmask_parent(d);
}

static void exiu_irq_enable(struct irq_data *d)
{
	struct exiu_irq_data *data = irq_data_get_irq_chip_data(d);
	u32 val;

	/* clear interrupts that were latched while disabled */
	writel_relaxed(BIT(d->hwirq), data->base + EIREQCLR);

	val = readl_relaxed(data->base + EIMASK) & ~BIT(d->hwirq);
	writel_relaxed(val, data->base + EIMASK);
	irq_chip_enable_parent(d);
}

static int exiu_irq_set_type(struct irq_data *d, unsigned int type)
{
	struct exiu_irq_data *data = irq_data_get_irq_chip_data(d);
	u32 val;

	val = readl_relaxed(data->base + EILVL);
	if (type == IRQ_TYPE_EDGE_RISING || type == IRQ_TYPE_LEVEL_HIGH)
		val |= BIT(d->hwirq);
	else
		val &= ~BIT(d->hwirq);
	writel_relaxed(val, data->base + EILVL);

	val = readl_relaxed(data->base + EIEDG);
	if (type == IRQ_TYPE_LEVEL_LOW || type == IRQ_TYPE_LEVEL_HIGH)
		val &= ~BIT(d->hwirq);
	else
		val |= BIT(d->hwirq);
	writel_relaxed(val, data->base + EIEDG);

	writel_relaxed(BIT(d->hwirq), data->base + EIREQCLR);

	return irq_chip_set_type_parent(d, IRQ_TYPE_LEVEL_HIGH);
}

static struct irq_chip exiu_irq_chip = {
	.name			= "EXIU",
	.irq_eoi		= exiu_irq_eoi,
	.irq_enable		= exiu_irq_enable,
	.irq_mask		= exiu_irq_mask,
	.irq_unmask		= exiu_irq_unmask,
	.irq_set_type		= exiu_irq_set_type,
	.irq_set_affinity	= irq_chip_set_affinity_parent,
	.flags			= IRQCHIP_SET_TYPE_MASKED |
				  IRQCHIP_SKIP_SET_WAKE |
				  IRQCHIP_EOI_THREADED |
				  IRQCHIP_MASK_ON_SUSPEND,
};

static int exiu_domain_translate(struct irq_domain *domain,
				 struct irq_fwspec *fwspec,
				 unsigned long *hwirq,
				 unsigned int *type)
{
	struct exiu_irq_data *info = domain->host_data;

	if (is_of_node(fwspec->fwnode)) {
		if (fwspec->param_count != 3)
			return -EINVAL;

		if (fwspec->param[0] != GIC_SPI)
			return -EINVAL; /* No PPI should point to this domain */

		*hwirq = fwspec->param[1] - info->spi_base;
		*type = fwspec->param[2] & IRQ_TYPE_SENSE_MASK;
		return 0;
	}
	return -EINVAL;
}

static int exiu_domain_alloc(struct irq_domain *dom, unsigned int virq,
			     unsigned int nr_irqs, void *data)
{
	struct irq_fwspec *fwspec = data;
	struct irq_fwspec parent_fwspec;
	struct exiu_irq_data *info = dom->host_data;
	irq_hw_number_t hwirq;

	if (fwspec->param_count != 3)
		return -EINVAL;	/* Not GIC compliant */
	if (fwspec->param[0] != GIC_SPI)
		return -EINVAL;	/* No PPI should point to this domain */

	WARN_ON(nr_irqs != 1);
	hwirq = fwspec->param[1] - info->spi_base;
	irq_domain_set_hwirq_and_chip(dom, virq, hwirq, &exiu_irq_chip, info);

	parent_fwspec = *fwspec;
	parent_fwspec.fwnode = dom->parent->fwnode;
	return irq_domain_alloc_irqs_parent(dom, virq, nr_irqs, &parent_fwspec);
}

static const struct irq_domain_ops exiu_domain_ops = {
	.translate	= exiu_domain_translate,
	.alloc		= exiu_domain_alloc,
	.free		= irq_domain_free_irqs_common,
};

static int __init exiu_init(struct device_node *node,
			    struct device_node *parent)
{
	struct irq_domain *parent_domain, *domain;
	struct exiu_irq_data *data;
	int err;

	if (!parent) {
		pr_err("%pOF: no parent, giving up\n", node);
		return -ENODEV;
	}

	parent_domain = irq_find_host(parent);
	if (!parent_domain) {
		pr_err("%pOF: unable to obtain parent domain\n", node);
		return -ENXIO;
	}

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	if (of_property_read_u32(node, "socionext,spi-base", &data->spi_base)) {
		pr_err("%pOF: failed to parse 'spi-base' property\n", node);
		err = -ENODEV;
		goto out_free;
	}

	data->base = of_iomap(node, 0);
	if (!data->base) {
		err = -ENODEV;
		goto out_free;
	}

	/* clear and mask all interrupts */
	writel_relaxed(0xFFFFFFFF, data->base + EIREQCLR);
	writel_relaxed(0xFFFFFFFF, data->base + EIMASK);

	domain = irq_domain_add_hierarchy(parent_domain, 0, NUM_IRQS, node,
					  &exiu_domain_ops, data);
	if (!domain) {
		pr_err("%pOF: failed to allocate domain\n", node);
		err = -ENOMEM;
		goto out_unmap;
	}

	pr_info("%pOF: %d interrupts forwarded to %pOF\n", node, NUM_IRQS,
		parent);

	return 0;

out_unmap:
	iounmap(data->base);
out_free:
	kfree(data);
	return err;
}
IRQCHIP_DECLARE(exiu, "socionext,synquacer-exiu", exiu_init);
