// SPDX-License-Identifier: GPL-2.0-only
/*
 * ADXL345 3-Axis Digital Accelerometer IIO core driver
 *
 * Copyright (c) 2017 Eva Rachel Retuya <eraretuya@gmail.com>
 *
 * Datasheet: https://www.analog.com/media/en/technical-documentation/data-sheets/ADXL345.pdf
 */

#include <linux/module.h>
#include <linux/property.h>
#include <linux/regmap.h>
#include <linux/units.h>

#include <linux/iio/iio.h>
#include <linux/iio/sysfs.h>

#include "adxl345.h"

#define ADXL345_REG_DEVID		0x00
#define ADXL345_REG_OFSX		0x1e
#define ADXL345_REG_OFSY		0x1f
#define ADXL345_REG_OFSZ		0x20
#define ADXL345_REG_OFS_AXIS(index)	(ADXL345_REG_OFSX + (index))
#define ADXL345_REG_BW_RATE		0x2C
#define ADXL345_REG_POWER_CTL		0x2D
#define ADXL345_REG_DATA_FORMAT		0x31
#define ADXL345_REG_DATAX0		0x32
#define ADXL345_REG_DATAY0		0x34
#define ADXL345_REG_DATAZ0		0x36
#define ADXL345_REG_DATA_AXIS(index)	\
	(ADXL345_REG_DATAX0 + (index) * sizeof(__le16))

#define ADXL345_BW_RATE			GENMASK(3, 0)
#define ADXL345_BASE_RATE_NANO_HZ	97656250LL

#define ADXL345_POWER_CTL_MEASURE	BIT(3)
#define ADXL345_POWER_CTL_STANDBY	0x00

#define ADXL345_DATA_FORMAT_FULL_RES	BIT(3) /* Up to 13-bits resolution */
#define ADXL345_DATA_FORMAT_2G		0
#define ADXL345_DATA_FORMAT_4G		1
#define ADXL345_DATA_FORMAT_8G		2
#define ADXL345_DATA_FORMAT_16G		3

#define ADXL345_DEVID			0xE5

struct adxl345_data {
	const struct adxl345_chip_info *info;
	struct regmap *regmap;
	u8 data_range;
};

#define ADXL345_CHANNEL(index, axis) {					\
	.type = IIO_ACCEL,						\
	.modified = 1,							\
	.channel2 = IIO_MOD_##axis,					\
	.address = index,						\
	.info_mask_separate = BIT(IIO_CHAN_INFO_RAW) |			\
		BIT(IIO_CHAN_INFO_CALIBBIAS),				\
	.info_mask_shared_by_type = BIT(IIO_CHAN_INFO_SCALE) |		\
		BIT(IIO_CHAN_INFO_SAMP_FREQ),				\
}

static const struct iio_chan_spec adxl345_channels[] = {
	ADXL345_CHANNEL(0, X),
	ADXL345_CHANNEL(1, Y),
	ADXL345_CHANNEL(2, Z),
};

static int adxl345_read_raw(struct iio_dev *indio_dev,
			    struct iio_chan_spec const *chan,
			    int *val, int *val2, long mask)
{
	struct adxl345_data *data = iio_priv(indio_dev);
	__le16 accel;
	long long samp_freq_nhz;
	unsigned int regval;
	int ret;

	switch (mask) {
	case IIO_CHAN_INFO_RAW:
		/*
		 * Data is stored in adjacent registers:
		 * ADXL345_REG_DATA(X0/Y0/Z0) contain the least significant byte
		 * and ADXL345_REG_DATA(X0/Y0/Z0) + 1 the most significant byte
		 */
		ret = regmap_bulk_read(data->regmap,
				       ADXL345_REG_DATA_AXIS(chan->address),
				       &accel, sizeof(accel));
		if (ret < 0)
			return ret;

		*val = sign_extend32(le16_to_cpu(accel), 12);
		return IIO_VAL_INT;
	case IIO_CHAN_INFO_SCALE:
		*val = 0;
		*val2 = data->info->uscale;
		return IIO_VAL_INT_PLUS_MICRO;
	case IIO_CHAN_INFO_CALIBBIAS:
		ret = regmap_read(data->regmap,
				  ADXL345_REG_OFS_AXIS(chan->address), &regval);
		if (ret < 0)
			return ret;
		/*
		 * 8-bit resolution at +/- 2g, that is 4x accel data scale
		 * factor
		 */
		*val = sign_extend32(regval, 7) * 4;

		return IIO_VAL_INT;
	case IIO_CHAN_INFO_SAMP_FREQ:
		ret = regmap_read(data->regmap, ADXL345_REG_BW_RATE, &regval);
		if (ret < 0)
			return ret;

		samp_freq_nhz = ADXL345_BASE_RATE_NANO_HZ <<
				(regval & ADXL345_BW_RATE);
		*val = div_s64_rem(samp_freq_nhz, NANOHZ_PER_HZ, val2);

		return IIO_VAL_INT_PLUS_NANO;
	}

	return -EINVAL;
}

static int adxl345_write_raw(struct iio_dev *indio_dev,
			     struct iio_chan_spec const *chan,
			     int val, int val2, long mask)
{
	struct adxl345_data *data = iio_priv(indio_dev);
	s64 n;

	switch (mask) {
	case IIO_CHAN_INFO_CALIBBIAS:
		/*
		 * 8-bit resolution at +/- 2g, that is 4x accel data scale
		 * factor
		 */
		return regmap_write(data->regmap,
				    ADXL345_REG_OFS_AXIS(chan->address),
				    val / 4);
	case IIO_CHAN_INFO_SAMP_FREQ:
		n = div_s64(val * NANOHZ_PER_HZ + val2,
			    ADXL345_BASE_RATE_NANO_HZ);

		return regmap_update_bits(data->regmap, ADXL345_REG_BW_RATE,
					  ADXL345_BW_RATE,
					  clamp_val(ilog2(n), 0,
						    ADXL345_BW_RATE));
	}

	return -EINVAL;
}

static int adxl345_write_raw_get_fmt(struct iio_dev *indio_dev,
				     struct iio_chan_spec const *chan,
				     long mask)
{
	switch (mask) {
	case IIO_CHAN_INFO_CALIBBIAS:
		return IIO_VAL_INT;
	case IIO_CHAN_INFO_SAMP_FREQ:
		return IIO_VAL_INT_PLUS_NANO;
	default:
		return -EINVAL;
	}
}

static IIO_CONST_ATTR_SAMP_FREQ_AVAIL(
"0.09765625 0.1953125 0.390625 0.78125 1.5625 3.125 6.25 12.5 25 50 100 200 400 800 1600 3200"
);

static struct attribute *adxl345_attrs[] = {
	&iio_const_attr_sampling_frequency_available.dev_attr.attr,
	NULL
};

static const struct attribute_group adxl345_attrs_group = {
	.attrs = adxl345_attrs,
};

static const struct iio_info adxl345_info = {
	.attrs		= &adxl345_attrs_group,
	.read_raw	= adxl345_read_raw,
	.write_raw	= adxl345_write_raw,
	.write_raw_get_fmt	= adxl345_write_raw_get_fmt,
};

static int adxl345_powerup(void *regmap)
{
	return regmap_write(regmap, ADXL345_REG_POWER_CTL, ADXL345_POWER_CTL_MEASURE);
}

static void adxl345_powerdown(void *regmap)
{
	regmap_write(regmap, ADXL345_REG_POWER_CTL, ADXL345_POWER_CTL_STANDBY);
}

int adxl345_core_probe(struct device *dev, struct regmap *regmap)
{
	struct adxl345_data *data;
	struct iio_dev *indio_dev;
	u32 regval;
	int ret;

	ret = regmap_read(regmap, ADXL345_REG_DEVID, &regval);
	if (ret < 0)
		return dev_err_probe(dev, ret, "Error reading device ID\n");

	if (regval != ADXL345_DEVID)
		return dev_err_probe(dev, -ENODEV, "Invalid device ID: %x, expected %x\n",
				     regval, ADXL345_DEVID);

	indio_dev = devm_iio_device_alloc(dev, sizeof(*data));
	if (!indio_dev)
		return -ENOMEM;

	data = iio_priv(indio_dev);
	data->regmap = regmap;
	/* Enable full-resolution mode */
	data->data_range = ADXL345_DATA_FORMAT_FULL_RES;
	data->info = device_get_match_data(dev);
	if (!data->info)
		return -ENODEV;

	ret = regmap_write(data->regmap, ADXL345_REG_DATA_FORMAT,
			   data->data_range);
	if (ret < 0)
		return dev_err_probe(dev, ret, "Failed to set data range\n");

	indio_dev->name = data->info->name;
	indio_dev->info = &adxl345_info;
	indio_dev->modes = INDIO_DIRECT_MODE;
	indio_dev->channels = adxl345_channels;
	indio_dev->num_channels = ARRAY_SIZE(adxl345_channels);

	/* Enable measurement mode */
	ret = adxl345_powerup(data->regmap);
	if (ret < 0)
		return dev_err_probe(dev, ret, "Failed to enable measurement mode\n");

	ret = devm_add_action_or_reset(dev, adxl345_powerdown, data->regmap);
	if (ret < 0)
		return ret;

	return devm_iio_device_register(dev, indio_dev);
}
EXPORT_SYMBOL_NS_GPL(adxl345_core_probe, IIO_ADXL345);

MODULE_AUTHOR("Eva Rachel Retuya <eraretuya@gmail.com>");
MODULE_DESCRIPTION("ADXL345 3-Axis Digital Accelerometer core driver");
MODULE_LICENSE("GPL v2");
