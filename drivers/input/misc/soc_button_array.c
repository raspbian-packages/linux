/*
 * Supports for the button array on SoC tablets originally running
 * Windows 8.
 *
 * (C) Copyright 2014 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#include <linux/module.h>
#include <linux/input.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/acpi.h>
#include <linux/gpio/consumer.h>
#include <linux/gpio_keys.h>
#include <linux/gpio.h>
#include <linux/platform_device.h>

struct soc_button_info {
	const char *name;
	int acpi_index;
	unsigned int event_type;
	unsigned int event_code;
	bool autorepeat;
	bool wakeup;
};

/*
 * Some of the buttons like volume up/down are auto repeat, while others
 * are not. To support both, we register two platform devices, and put
 * buttons into them based on whether the key should be auto repeat.
 */
#define BUTTON_TYPES	2

struct soc_button_data {
	struct platform_device *children[BUTTON_TYPES];
};

/*
 * Get the Nth GPIO number from the ACPI object.
 */
static int soc_button_lookup_gpio(struct device *dev, int acpi_index)
{
	struct gpio_desc *desc;
	int gpio;

	desc = gpiod_get_index(dev, NULL, acpi_index, GPIOD_ASIS);
	if (IS_ERR(desc))
		return PTR_ERR(desc);

	gpio = desc_to_gpio(desc);

	gpiod_put(desc);

	return gpio;
}

static struct platform_device *
soc_button_device_create(struct platform_device *pdev,
			 const struct soc_button_info *button_info,
			 bool autorepeat)
{
	const struct soc_button_info *info;
	struct platform_device *pd;
	struct gpio_keys_button *gpio_keys;
	struct gpio_keys_platform_data *gpio_keys_pdata;
	int n_buttons = 0;
	int gpio;
	int error;

	for (info = button_info; info->name; info++)
		if (info->autorepeat == autorepeat)
			n_buttons++;

	gpio_keys_pdata = devm_kzalloc(&pdev->dev,
				       sizeof(*gpio_keys_pdata) +
					sizeof(*gpio_keys) * n_buttons,
				       GFP_KERNEL);
	if (!gpio_keys_pdata)
		return ERR_PTR(-ENOMEM);

	gpio_keys = (void *)(gpio_keys_pdata + 1);
	n_buttons = 0;

	for (info = button_info; info->name; info++) {
		if (info->autorepeat != autorepeat)
			continue;

		gpio = soc_button_lookup_gpio(&pdev->dev, info->acpi_index);
		if (!gpio_is_valid(gpio))
			continue;

		gpio_keys[n_buttons].type = info->event_type;
		gpio_keys[n_buttons].code = info->event_code;
		gpio_keys[n_buttons].gpio = gpio;
		gpio_keys[n_buttons].active_low = 1;
		gpio_keys[n_buttons].desc = info->name;
		gpio_keys[n_buttons].wakeup = info->wakeup;
		/* These devices often use cheap buttons, use 50 ms debounce */
		gpio_keys[n_buttons].debounce_interval = 50;
		n_buttons++;
	}

	if (n_buttons == 0) {
		error = -ENODEV;
		goto err_free_mem;
	}

	gpio_keys_pdata->buttons = gpio_keys;
	gpio_keys_pdata->nbuttons = n_buttons;
	gpio_keys_pdata->rep = autorepeat;

	pd = platform_device_alloc("gpio-keys", PLATFORM_DEVID_AUTO);
	if (!pd) {
		error = -ENOMEM;
		goto err_free_mem;
	}

	error = platform_device_add_data(pd, gpio_keys_pdata,
					 sizeof(*gpio_keys_pdata));
	if (error)
		goto err_free_pdev;

	error = platform_device_add(pd);
	if (error)
		goto err_free_pdev;

	return pd;

err_free_pdev:
	platform_device_put(pd);
err_free_mem:
	devm_kfree(&pdev->dev, gpio_keys_pdata);
	return ERR_PTR(error);
}

static int soc_button_get_acpi_object_int(const union acpi_object *obj)
{
	if (obj->type != ACPI_TYPE_INTEGER)
		return -1;

	return obj->integer.value;
}

/* Parse a single ACPI0011 _DSD button descriptor */
static int soc_button_parse_btn_desc(struct device *dev,
				     const union acpi_object *desc,
				     int collection_uid,
				     struct soc_button_info *info)
{
	int upage, usage;

	if (desc->type != ACPI_TYPE_PACKAGE ||
	    desc->package.count != 5 ||
	    /* First byte should be 1 (control) */
	    soc_button_get_acpi_object_int(&desc->package.elements[0]) != 1 ||
	    /* Third byte should be collection uid */
	    soc_button_get_acpi_object_int(&desc->package.elements[2]) !=
							    collection_uid) {
		dev_err(dev, "Invalid ACPI Button Descriptor\n");
		return -ENODEV;
	}

	info->event_type = EV_KEY;
	info->acpi_index =
		soc_button_get_acpi_object_int(&desc->package.elements[1]);
	upage = soc_button_get_acpi_object_int(&desc->package.elements[3]);
	usage = soc_button_get_acpi_object_int(&desc->package.elements[4]);

	/*
	 * The UUID: fa6bd625-9ce8-470d-a2c7-b3ca36c4282e descriptors use HID
	 * usage page and usage codes, but otherwise the device is not HID
	 * compliant: it uses one irq per button instead of generating HID
	 * input reports and some buttons should generate wakeups where as
	 * others should not, so we cannot use the HID subsystem.
	 *
	 * Luckily all devices only use a few usage page + usage combinations,
	 * so we can simply check for the known combinations here.
	 */
	if (upage == 0x01 && usage == 0x81) {
		info->name = "power";
		info->event_code = KEY_POWER;
		info->wakeup = true;
	} else if (upage == 0x07 && usage == 0xe3) {
		info->name = "home";
		info->event_code = KEY_LEFTMETA;
		info->wakeup = true;
	} else if (upage == 0x0c && usage == 0xe9) {
		info->name = "volume_up";
		info->event_code = KEY_VOLUMEUP;
		info->autorepeat = true;
	} else if (upage == 0x0c && usage == 0xea) {
		info->name = "volume_down";
		info->event_code = KEY_VOLUMEDOWN;
		info->autorepeat = true;
	} else {
		dev_warn(dev, "Unknown button index %d upage %02x usage %02x, ignoring\n",
			 info->acpi_index, upage, usage);
		info->name = "unknown";
		info->event_code = KEY_RESERVED;
	}

	return 0;
}

/* ACPI0011 _DSD btns descriptors UUID: fa6bd625-9ce8-470d-a2c7-b3ca36c4282e */
static const u8 btns_desc_uuid[16] = {
	0x25, 0xd6, 0x6b, 0xfa, 0xe8, 0x9c, 0x0d, 0x47,
	0xa2, 0xc7, 0xb3, 0xca, 0x36, 0xc4, 0x28, 0x2e
};

/* Parse ACPI0011 _DSD button descriptors */
static struct soc_button_info *soc_button_get_button_info(struct device *dev)
{
	struct acpi_buffer buf = { ACPI_ALLOCATE_BUFFER };
	const union acpi_object *desc, *el0, *uuid, *btns_desc = NULL;
	struct soc_button_info *button_info;
	acpi_status status;
	int i, btn, collection_uid = -1;

	status = acpi_evaluate_object_typed(ACPI_HANDLE(dev), "_DSD", NULL,
					    &buf, ACPI_TYPE_PACKAGE);
	if (ACPI_FAILURE(status)) {
		dev_err(dev, "ACPI _DSD object not found\n");
		return ERR_PTR(-ENODEV);
	}

	/* Look for the Button Descriptors UUID */
	desc = buf.pointer;
	for (i = 0; (i + 1) < desc->package.count; i += 2) {
		uuid = &desc->package.elements[i];

		if (uuid->type != ACPI_TYPE_BUFFER ||
		    uuid->buffer.length != 16 ||
		    desc->package.elements[i + 1].type != ACPI_TYPE_PACKAGE) {
			break;
		}

		if (memcmp(uuid->buffer.pointer, btns_desc_uuid, 16) == 0) {
			btns_desc = &desc->package.elements[i + 1];
			break;
		}
	}

	if (!btns_desc) {
		dev_err(dev, "ACPI Button Descriptors not found\n");
		button_info = ERR_PTR(-ENODEV);
		goto out;
	}

	/* The first package describes the collection */
	el0 = &btns_desc->package.elements[0];
	if (el0->type == ACPI_TYPE_PACKAGE &&
	    el0->package.count == 5 &&
	    /* First byte should be 0 (collection) */
	    soc_button_get_acpi_object_int(&el0->package.elements[0]) == 0 &&
	    /* Third byte should be 0 (top level collection) */
	    soc_button_get_acpi_object_int(&el0->package.elements[2]) == 0) {
		collection_uid = soc_button_get_acpi_object_int(
						&el0->package.elements[1]);
	}
	if (collection_uid == -1) {
		dev_err(dev, "Invalid Button Collection Descriptor\n");
		button_info = ERR_PTR(-ENODEV);
		goto out;
	}

	/* There are package.count - 1 buttons + 1 terminating empty entry */
	button_info = devm_kcalloc(dev, btns_desc->package.count,
				   sizeof(*button_info), GFP_KERNEL);
	if (!button_info) {
		button_info = ERR_PTR(-ENOMEM);
		goto out;
	}

	/* Parse the button descriptors */
	for (i = 1, btn = 0; i < btns_desc->package.count; i++, btn++) {
		if (soc_button_parse_btn_desc(dev,
					      &btns_desc->package.elements[i],
					      collection_uid,
					      &button_info[btn])) {
			button_info = ERR_PTR(-ENODEV);
			goto out;
		}
	}

out:
	kfree(buf.pointer);
	return button_info;
}

static int soc_button_remove(struct platform_device *pdev)
{
	struct soc_button_data *priv = platform_get_drvdata(pdev);

	int i;

	for (i = 0; i < BUTTON_TYPES; i++)
		if (priv->children[i])
			platform_device_unregister(priv->children[i]);

	return 0;
}

static int soc_button_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	const struct acpi_device_id *id;
	struct soc_button_info *button_info;
	struct soc_button_data *priv;
	struct platform_device *pd;
	int i;
	int error;

	id = acpi_match_device(dev->driver->acpi_match_table, dev);
	if (!id)
		return -ENODEV;

	if (!id->driver_data) {
		button_info = soc_button_get_button_info(dev);
		if (IS_ERR(button_info))
			return PTR_ERR(button_info);
	} else {
		button_info = (struct soc_button_info *)id->driver_data;
	}

	error = gpiod_count(dev, NULL);
	if (error < 0) {
		dev_dbg(dev, "no GPIO attached, ignoring...\n");
		return error;
	}

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	platform_set_drvdata(pdev, priv);

	for (i = 0; i < BUTTON_TYPES; i++) {
		pd = soc_button_device_create(pdev, button_info, i == 0);
		if (IS_ERR(pd)) {
			error = PTR_ERR(pd);
			if (error != -ENODEV) {
				soc_button_remove(pdev);
				return error;
			}
			continue;
		}

		priv->children[i] = pd;
	}

	if (!priv->children[0] && !priv->children[1])
		return -ENODEV;

	if (!id->driver_data)
		devm_kfree(dev, button_info);

	return 0;
}

/*
 * Definition of buttons on the tablet. The ACPI index of each button
 * is defined in section 2.8.7.2 of "Windows ACPI Design Guide for SoC
 * Platforms"
 */
static struct soc_button_info soc_button_PNP0C40[] = {
	{ "power", 0, EV_KEY, KEY_POWER, false, true },
	{ "home", 1, EV_KEY, KEY_LEFTMETA, false, true },
	{ "volume_up", 2, EV_KEY, KEY_VOLUMEUP, true, false },
	{ "volume_down", 3, EV_KEY, KEY_VOLUMEDOWN, true, false },
	{ "rotation_lock", 4, EV_SW, SW_ROTATE_LOCK, false, false },
	{ }
};

static const struct acpi_device_id soc_button_acpi_match[] = {
	{ "PNP0C40", (unsigned long)soc_button_PNP0C40 },
	{ "ACPI0011", 0 },
	{ }
};

MODULE_DEVICE_TABLE(acpi, soc_button_acpi_match);

static struct platform_driver soc_button_driver = {
	.probe          = soc_button_probe,
	.remove		= soc_button_remove,
	.driver		= {
		.name = KBUILD_MODNAME,
		.acpi_match_table = ACPI_PTR(soc_button_acpi_match),
	},
};
module_platform_driver(soc_button_driver);

MODULE_LICENSE("GPL");
