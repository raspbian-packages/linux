/*
 * Copyright (C) 2015 Atmel
 *
 * Alexandre Belloni <alexandre.belloni@free-electrons.com
 * Boris Brezillon <boris.brezillon@free-electrons.com
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 *
 */

#define pr_fmt(fmt)	"AT91: " fmt

#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/slab.h>
#include <linux/sys_soc.h>

#include "soc.h"

#define AT91_DBGU_CIDR			0x40
#define AT91_DBGU_EXID			0x44
#define AT91_CHIPID_CIDR		0x00
#define AT91_CHIPID_EXID		0x04
#define AT91_CIDR_VERSION(x)		((x) & 0x1f)
#define AT91_CIDR_EXT			BIT(31)
#define AT91_CIDR_MATCH_MASK		0x7fffffe0

static int __init at91_get_cidr_exid_from_dbgu(u32 *cidr, u32 *exid)
{
	struct device_node *np;
	void __iomem *regs;

	np = of_find_compatible_node(NULL, NULL, "atmel,at91rm9200-dbgu");
	if (!np)
		np = of_find_compatible_node(NULL, NULL,
					     "atmel,at91sam9260-dbgu");
	if (!np)
		return -ENODEV;

	regs = of_iomap(np, 0);
	of_node_put(np);

	if (!regs) {
		pr_warn("Could not map DBGU iomem range");
		return -ENXIO;
	}

	*cidr = readl(regs + AT91_DBGU_CIDR);
	*exid = readl(regs + AT91_DBGU_EXID);

	iounmap(regs);

	return 0;
}

static int __init at91_get_cidr_exid_from_chipid(u32 *cidr, u32 *exid)
{
	struct device_node *np;
	void __iomem *regs;

	np = of_find_compatible_node(NULL, NULL, "atmel,sama5d2-chipid");
	if (!np)
		return -ENODEV;

	regs = of_iomap(np, 0);
	of_node_put(np);

	if (!regs) {
		pr_warn("Could not map DBGU iomem range");
		return -ENXIO;
	}

	*cidr = readl(regs + AT91_CHIPID_CIDR);
	*exid = readl(regs + AT91_CHIPID_EXID);

	iounmap(regs);

	return 0;
}

struct soc_device * __init at91_soc_init(const struct at91_soc *socs)
{
	struct soc_device_attribute *soc_dev_attr;
	const struct at91_soc *soc;
	struct soc_device *soc_dev;
	u32 cidr, exid;
	int ret;

	/*
	 * With SAMA5D2 and later SoCs, CIDR and EXID registers are no more
	 * in the dbgu device but in the chipid device whose purpose is only
	 * to expose these two registers.
	 */
	ret = at91_get_cidr_exid_from_dbgu(&cidr, &exid);
	if (ret)
		ret = at91_get_cidr_exid_from_chipid(&cidr, &exid);
	if (ret) {
		if (ret == -ENODEV)
			pr_warn("Could not find identification node");
		return NULL;
	}

	for (soc = socs; soc->name; soc++) {
		if (soc->cidr_match != (cidr & AT91_CIDR_MATCH_MASK))
			continue;

		if (!(cidr & AT91_CIDR_EXT) || soc->exid_match == exid)
			break;
	}

	if (!soc->name) {
		pr_warn("Could not find matching SoC description\n");
		return NULL;
	}

	soc_dev_attr = kzalloc(sizeof(*soc_dev_attr), GFP_KERNEL);
	if (!soc_dev_attr)
		return NULL;

	soc_dev_attr->family = soc->family;
	soc_dev_attr->soc_id = soc->name;
	soc_dev_attr->revision = kasprintf(GFP_KERNEL, "%X",
					   AT91_CIDR_VERSION(cidr));
	soc_dev = soc_device_register(soc_dev_attr);
	if (IS_ERR(soc_dev)) {
		kfree(soc_dev_attr->revision);
		kfree(soc_dev_attr);
		pr_warn("Could not register SoC device\n");
		return NULL;
	}

	if (soc->family)
		pr_info("Detected SoC family: %s\n", soc->family);
	pr_info("Detected SoC: %s, revision %X\n", soc->name,
		AT91_CIDR_VERSION(cidr));

	return soc_dev;
}
