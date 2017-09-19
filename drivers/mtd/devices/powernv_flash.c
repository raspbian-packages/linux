/*
 * OPAL PNOR flash MTD abstraction
 *
 * Copyright IBM 2015
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>

#include <linux/debugfs.h>
#include <linux/seq_file.h>

#include <asm/opal.h>


/*
 * This driver creates the a Linux MTD abstraction for platform PNOR flash
 * backed by OPAL calls
 */

struct powernv_flash {
	struct mtd_info	mtd;
	u32 id;
};

enum flash_op {
	FLASH_OP_READ,
	FLASH_OP_WRITE,
	FLASH_OP_ERASE,
};

static int powernv_flash_async_op(struct mtd_info *mtd, enum flash_op op,
		loff_t offset, size_t len, size_t *retlen, u_char *buf)
{
	struct powernv_flash *info = (struct powernv_flash *)mtd->priv;
	struct device *dev = &mtd->dev;
	int token;
	struct opal_msg msg;
	int rc;

	dev_dbg(dev, "%s(op=%d, offset=0x%llx, len=%zu)\n",
			__func__, op, offset, len);

	token = opal_async_get_token_interruptible();
	if (token < 0) {
		if (token != -ERESTARTSYS)
			dev_err(dev, "Failed to get an async token\n");

		return token;
	}

	switch (op) {
	case FLASH_OP_READ:
		rc = opal_flash_read(info->id, offset, __pa(buf), len, token);
		break;
	case FLASH_OP_WRITE:
		rc = opal_flash_write(info->id, offset, __pa(buf), len, token);
		break;
	case FLASH_OP_ERASE:
		rc = opal_flash_erase(info->id, offset, len, token);
		break;
	default:
		BUG_ON(1);
	}

	if (rc != OPAL_ASYNC_COMPLETION) {
		dev_err(dev, "opal_flash_async_op(op=%d) failed (rc %d)\n",
				op, rc);
		opal_async_release_token(token);
		return -EIO;
	}

	rc = opal_async_wait_response(token, &msg);
	opal_async_release_token(token);
	if (rc) {
		dev_err(dev, "opal async wait failed (rc %d)\n", rc);
		return -EIO;
	}

	rc = opal_get_async_rc(msg);
	if (rc == OPAL_SUCCESS) {
		rc = 0;
		if (retlen)
			*retlen = len;
	} else {
		rc = -EIO;
	}

	return rc;
}

/**
 * @mtd: the device
 * @from: the offset to read from
 * @len: the number of bytes to read
 * @retlen: the number of bytes actually read
 * @buf: the filled in buffer
 *
 * Returns 0 if read successful, or -ERRNO if an error occurred
 */
static int powernv_flash_read(struct mtd_info *mtd, loff_t from, size_t len,
	     size_t *retlen, u_char *buf)
{
	return powernv_flash_async_op(mtd, FLASH_OP_READ, from,
			len, retlen, buf);
}

/**
 * @mtd: the device
 * @to: the offset to write to
 * @len: the number of bytes to write
 * @retlen: the number of bytes actually written
 * @buf: the buffer to get bytes from
 *
 * Returns 0 if write successful, -ERRNO if error occurred
 */
static int powernv_flash_write(struct mtd_info *mtd, loff_t to, size_t len,
		     size_t *retlen, const u_char *buf)
{
	return powernv_flash_async_op(mtd, FLASH_OP_WRITE, to,
			len, retlen, (u_char *)buf);
}

/**
 * @mtd: the device
 * @erase: the erase info
 * Returns 0 if erase successful or -ERRNO if an error occurred
 */
static int powernv_flash_erase(struct mtd_info *mtd, struct erase_info *erase)
{
	int rc;

	erase->state = MTD_ERASING;

	/* todo: register our own notifier to do a true async implementation */
	rc =  powernv_flash_async_op(mtd, FLASH_OP_ERASE, erase->addr,
			erase->len, NULL, NULL);

	if (rc) {
		erase->fail_addr = erase->addr;
		erase->state = MTD_ERASE_FAILED;
	} else {
		erase->state = MTD_ERASE_DONE;
	}
	mtd_erase_callback(erase);
	return rc;
}

/**
 * powernv_flash_set_driver_info - Fill the mtd_info structure and docg3
 * structure @pdev: The platform device
 * @mtd: The structure to fill
 */
static int powernv_flash_set_driver_info(struct device *dev,
		struct mtd_info *mtd)
{
	u64 size;
	u32 erase_size;
	int rc;

	rc = of_property_read_u32(dev->of_node, "ibm,flash-block-size",
			&erase_size);
	if (rc) {
		dev_err(dev, "couldn't get resource block size information\n");
		return rc;
	}

	rc = of_property_read_u64(dev->of_node, "reg", &size);
	if (rc) {
		dev_err(dev, "couldn't get resource size information\n");
		return rc;
	}

	/*
	 * Going to have to check what details I need to set and how to
	 * get them
	 */
	mtd->name = of_get_property(dev->of_node, "name", NULL);
	mtd->type = MTD_NORFLASH;
	mtd->flags = MTD_WRITEABLE;
	mtd->size = size;
	mtd->erasesize = erase_size;
	mtd->writebufsize = mtd->writesize = 1;
	mtd->owner = THIS_MODULE;
	mtd->_erase = powernv_flash_erase;
	mtd->_read = powernv_flash_read;
	mtd->_write = powernv_flash_write;
	mtd->dev.parent = dev;
	return 0;
}

/**
 * powernv_flash_probe
 * @pdev: platform device
 *
 * Returns 0 on success, -ENOMEM, -ENXIO on error
 */
static int powernv_flash_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct powernv_flash *data;
	int ret;

	data = devm_kzalloc(dev, sizeof(*data), GFP_KERNEL);
	if (!data) {
		ret = -ENOMEM;
		goto out;
	}
	data->mtd.priv = data;

	ret = of_property_read_u32(dev->of_node, "ibm,opal-id", &(data->id));
	if (ret) {
		dev_err(dev, "no device property 'ibm,opal-id'\n");
		goto out;
	}

	ret = powernv_flash_set_driver_info(dev, &data->mtd);
	if (ret)
		goto out;

	dev_set_drvdata(dev, data);

	/*
	 * The current flash that skiboot exposes is one contiguous flash chip
	 * with an ffs partition at the start, it should prove easier for users
	 * to deal with partitions or not as they see fit
	 */
	ret = mtd_device_register(&data->mtd, NULL, 0);

out:
	return ret;
}

/**
 * op_release - Release the driver
 * @pdev: the platform device
 *
 * Returns 0
 */
static int powernv_flash_release(struct platform_device *pdev)
{
	struct powernv_flash *data = dev_get_drvdata(&(pdev->dev));

	/* All resources should be freed automatically */
	return mtd_device_unregister(&(data->mtd));
}

static const struct of_device_id powernv_flash_match[] = {
	{ .compatible = "ibm,opal-flash" },
	{}
};

static struct platform_driver powernv_flash_driver = {
	.driver		= {
		.name		= "powernv_flash",
		.of_match_table	= powernv_flash_match,
	},
	.remove		= powernv_flash_release,
	.probe		= powernv_flash_probe,
};

module_platform_driver(powernv_flash_driver);

MODULE_DEVICE_TABLE(of, powernv_flash_match);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cyril Bur <cyril.bur@au1.ibm.com>");
MODULE_DESCRIPTION("MTD abstraction for OPAL flash");
