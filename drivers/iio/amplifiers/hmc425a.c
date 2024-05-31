// SPDX-License-Identifier: GPL-2.0
/*
 * HMC425A and similar Gain Amplifiers
 *
 * Copyright 2020 Analog Devices Inc.
 */

#include <linux/bitops.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/gpio/consumer.h>
#include <linux/iio/iio.h>
#include <linux/iio/sysfs.h>
#include <linux/kernel.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/slab.h>
#include <linux/regulator/consumer.h>
#include <linux/sysfs.h>

enum hmc425a_type {
	ID_HMC425A,
	ID_HMC540S,
	ID_ADRF5740
};

struct hmc425a_chip_info {
	const char			*name;
	const struct iio_chan_spec	*channels;
	unsigned int			num_channels;
	unsigned int			num_gpios;
	int				gain_min;
	int				gain_max;
	int				default_gain;
};

struct hmc425a_state {
	struct	mutex lock; /* protect sensor state */
	struct	hmc425a_chip_info *chip_info;
	struct	gpio_descs *gpios;
	enum	hmc425a_type type;
	u32	gain;
};

static int hmc425a_write(struct iio_dev *indio_dev, u32 value)
{
	struct hmc425a_state *st = iio_priv(indio_dev);
	DECLARE_BITMAP(values, BITS_PER_TYPE(value));

	values[0] = value;

	gpiod_set_array_value_cansleep(st->gpios->ndescs, st->gpios->desc,
				       NULL, values);
	return 0;
}

static int hmc425a_read_raw(struct iio_dev *indio_dev,
			    struct iio_chan_spec const *chan, int *val,
			    int *val2, long m)
{
	struct hmc425a_state *st = iio_priv(indio_dev);
	int code, gain = 0;
	int ret;

	mutex_lock(&st->lock);
	switch (m) {
	case IIO_CHAN_INFO_HARDWAREGAIN:
		code = st->gain;

		switch (st->type) {
		case ID_HMC425A:
			gain = ~code * -500;
			break;
		case ID_HMC540S:
			gain = ~code * -1000;
			break;
		case ID_ADRF5740:
			code = code & BIT(3) ? code & ~BIT(2) : code;
			gain = code * -2000;
			break;
		}

		*val = gain / 1000;
		*val2 = (gain % 1000) * 1000;

		ret = IIO_VAL_INT_PLUS_MICRO_DB;
		break;
	default:
		ret = -EINVAL;
	}
	mutex_unlock(&st->lock);

	return ret;
};

static int hmc425a_write_raw(struct iio_dev *indio_dev,
			     struct iio_chan_spec const *chan, int val,
			     int val2, long mask)
{
	struct hmc425a_state *st = iio_priv(indio_dev);
	struct hmc425a_chip_info *inf = st->chip_info;
	int code = 0, gain;
	int ret;

	if (val < 0)
		gain = (val * 1000) - (val2 / 1000);
	else
		gain = (val * 1000) + (val2 / 1000);

	if (gain > inf->gain_max || gain < inf->gain_min)
		return -EINVAL;

	switch (st->type) {
	case ID_HMC425A:
		code = ~((abs(gain) / 500) & 0x3F);
		break;
	case ID_HMC540S:
		code = ~((abs(gain) / 1000) & 0xF);
		break;
	case ID_ADRF5740:
		code = (abs(gain) / 2000) & 0xF;
		code = code & BIT(3) ? code | BIT(2) : code;
		break;
	}

	mutex_lock(&st->lock);
	switch (mask) {
	case IIO_CHAN_INFO_HARDWAREGAIN:
		st->gain = code;

		ret = hmc425a_write(indio_dev, st->gain);
		break;
	default:
		ret = -EINVAL;
	}
	mutex_unlock(&st->lock);

	return ret;
}

static int hmc425a_write_raw_get_fmt(struct iio_dev *indio_dev,
				     struct iio_chan_spec const *chan,
				     long mask)
{
	switch (mask) {
	case IIO_CHAN_INFO_HARDWAREGAIN:
		return IIO_VAL_INT_PLUS_MICRO_DB;
	default:
		return -EINVAL;
	}
}

static const struct iio_info hmc425a_info = {
	.read_raw = &hmc425a_read_raw,
	.write_raw = &hmc425a_write_raw,
	.write_raw_get_fmt = &hmc425a_write_raw_get_fmt,
};

#define HMC425A_CHAN(_channel)						\
{									\
	.type = IIO_VOLTAGE,						\
	.output = 1,							\
	.indexed = 1,							\
	.channel = _channel,						\
	.info_mask_separate = BIT(IIO_CHAN_INFO_HARDWAREGAIN),		\
}

static const struct iio_chan_spec hmc425a_channels[] = {
	HMC425A_CHAN(0),
};

/* Match table for of_platform binding */
static const struct of_device_id hmc425a_of_match[] = {
	{ .compatible = "adi,hmc425a", .data = (void *)ID_HMC425A },
	{ .compatible = "adi,hmc540s", .data = (void *)ID_HMC540S },
	{ .compatible = "adi,adrf5740", .data = (void *)ID_ADRF5740 },
	{},
};
MODULE_DEVICE_TABLE(of, hmc425a_of_match);

static struct hmc425a_chip_info hmc425a_chip_info_tbl[] = {
	[ID_HMC425A] = {
		.name = "hmc425a",
		.channels = hmc425a_channels,
		.num_channels = ARRAY_SIZE(hmc425a_channels),
		.num_gpios = 6,
		.gain_min = -31500,
		.gain_max = 0,
		.default_gain = -0x40, /* set default gain -31.5db*/
	},
	[ID_HMC540S] = {
		.name = "hmc540s",
		.channels = hmc425a_channels,
		.num_channels = ARRAY_SIZE(hmc425a_channels),
		.num_gpios = 4,
		.gain_min = -15000,
		.gain_max = 0,
		.default_gain = -0x10, /* set default gain -15.0db*/
	},
	[ID_ADRF5740] = {
		.name = "adrf5740",
		.channels = hmc425a_channels,
		.num_channels = ARRAY_SIZE(hmc425a_channels),
		.num_gpios = 4,
		.gain_min = -22000,
		.gain_max = 0,
		.default_gain = 0xF, /* set default gain -22.0db*/
	},
};

static int hmc425a_probe(struct platform_device *pdev)
{
	struct iio_dev *indio_dev;
	struct hmc425a_state *st;
	int ret;

	indio_dev = devm_iio_device_alloc(&pdev->dev, sizeof(*st));
	if (!indio_dev)
		return -ENOMEM;

	st = iio_priv(indio_dev);
	st->type = (uintptr_t)device_get_match_data(&pdev->dev);

	st->chip_info = &hmc425a_chip_info_tbl[st->type];
	indio_dev->num_channels = st->chip_info->num_channels;
	indio_dev->channels = st->chip_info->channels;
	indio_dev->name = st->chip_info->name;
	st->gain = st->chip_info->default_gain;

	st->gpios = devm_gpiod_get_array(&pdev->dev, "ctrl", GPIOD_OUT_LOW);
	if (IS_ERR(st->gpios))
		return dev_err_probe(&pdev->dev, PTR_ERR(st->gpios),
				     "failed to get gpios\n");

	if (st->gpios->ndescs != st->chip_info->num_gpios) {
		dev_err(&pdev->dev, "%d GPIOs needed to operate\n",
			st->chip_info->num_gpios);
		return -ENODEV;
	}

	ret = devm_regulator_get_enable(&pdev->dev, "vcc-supply");
	if (ret)
		return ret;

	mutex_init(&st->lock);

	indio_dev->info = &hmc425a_info;
	indio_dev->modes = INDIO_DIRECT_MODE;

	/* Set default gain */
	hmc425a_write(indio_dev, st->gain);

	return devm_iio_device_register(&pdev->dev, indio_dev);
}

static struct platform_driver hmc425a_driver = {
	.driver = {
		.name = KBUILD_MODNAME,
		.of_match_table = hmc425a_of_match,
	},
	.probe = hmc425a_probe,
};
module_platform_driver(hmc425a_driver);

MODULE_AUTHOR("Michael Hennerich <michael.hennerich@analog.com>");
MODULE_DESCRIPTION("Analog Devices HMC425A and similar GPIO control Gain Amplifiers");
MODULE_LICENSE("GPL v2");
