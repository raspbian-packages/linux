/*
 * atlas-ph-sensor.c - Support for Atlas Scientific OEM pH-SM sensor
 *
 * Copyright (C) 2015 Matt Ranostay <mranostay@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/err.h>
#include <linux/irq.h>
#include <linux/irq_work.h>
#include <linux/gpio.h>
#include <linux/i2c.h>
#include <linux/regmap.h>
#include <linux/iio/iio.h>
#include <linux/iio/buffer.h>
#include <linux/iio/trigger.h>
#include <linux/iio/trigger_consumer.h>
#include <linux/iio/triggered_buffer.h>
#include <linux/pm_runtime.h>

#define ATLAS_REGMAP_NAME	"atlas_ph_regmap"
#define ATLAS_DRV_NAME		"atlas_ph"

#define ATLAS_REG_DEV_TYPE		0x00
#define ATLAS_REG_DEV_VERSION		0x01

#define ATLAS_REG_INT_CONTROL		0x04
#define ATLAS_REG_INT_CONTROL_EN	BIT(3)

#define ATLAS_REG_PWR_CONTROL		0x06

#define ATLAS_REG_CALIB_STATUS		0x0d
#define ATLAS_REG_CALIB_STATUS_MASK	0x07
#define ATLAS_REG_CALIB_STATUS_LOW	BIT(0)
#define ATLAS_REG_CALIB_STATUS_MID	BIT(1)
#define ATLAS_REG_CALIB_STATUS_HIGH	BIT(2)

#define ATLAS_REG_TEMP_DATA		0x0e
#define ATLAS_REG_PH_DATA		0x16

#define ATLAS_PH_INT_TIME_IN_US		450000

struct atlas_data {
	struct i2c_client *client;
	struct iio_trigger *trig;
	struct regmap *regmap;
	struct irq_work work;

	__be32 buffer[4]; /* 32-bit pH data + 32-bit pad + 64-bit timestamp */
};

static const struct regmap_range atlas_volatile_ranges[] = {
	regmap_reg_range(ATLAS_REG_INT_CONTROL, ATLAS_REG_INT_CONTROL),
	regmap_reg_range(ATLAS_REG_PH_DATA, ATLAS_REG_PH_DATA + 4),
};

static const struct regmap_access_table atlas_volatile_table = {
	.yes_ranges	= atlas_volatile_ranges,
	.n_yes_ranges	= ARRAY_SIZE(atlas_volatile_ranges),
};

static const struct regmap_config atlas_regmap_config = {
	.name = ATLAS_REGMAP_NAME,

	.reg_bits = 8,
	.val_bits = 8,

	.volatile_table = &atlas_volatile_table,
	.max_register = ATLAS_REG_PH_DATA + 4,
	.cache_type = REGCACHE_RBTREE,
};

static const struct iio_chan_spec atlas_channels[] = {
	{
		.type = IIO_PH,
		.info_mask_separate =
			BIT(IIO_CHAN_INFO_RAW) | BIT(IIO_CHAN_INFO_SCALE),
		.scan_index = 0,
		.scan_type = {
			.sign = 'u',
			.realbits = 32,
			.storagebits = 32,
			.endianness = IIO_BE,
		},
	},
	IIO_CHAN_SOFT_TIMESTAMP(1),
	{
		.type = IIO_TEMP,
		.address = ATLAS_REG_TEMP_DATA,
		.info_mask_separate =
			BIT(IIO_CHAN_INFO_RAW) | BIT(IIO_CHAN_INFO_SCALE),
		.output = 1,
		.scan_index = -1
	},
};

static int atlas_set_powermode(struct atlas_data *data, int on)
{
	return regmap_write(data->regmap, ATLAS_REG_PWR_CONTROL, on);
}

static int atlas_set_interrupt(struct atlas_data *data, bool state)
{
	return regmap_update_bits(data->regmap, ATLAS_REG_INT_CONTROL,
				  ATLAS_REG_INT_CONTROL_EN,
				  state ? ATLAS_REG_INT_CONTROL_EN : 0);
}

static int atlas_buffer_postenable(struct iio_dev *indio_dev)
{
	struct atlas_data *data = iio_priv(indio_dev);
	int ret;

	ret = iio_triggered_buffer_postenable(indio_dev);
	if (ret)
		return ret;

	ret = pm_runtime_get_sync(&data->client->dev);
	if (ret < 0) {
		pm_runtime_put_noidle(&data->client->dev);
		return ret;
	}

	return atlas_set_interrupt(data, true);
}

static int atlas_buffer_predisable(struct iio_dev *indio_dev)
{
	struct atlas_data *data = iio_priv(indio_dev);
	int ret;

	ret = iio_triggered_buffer_predisable(indio_dev);
	if (ret)
		return ret;

	ret = atlas_set_interrupt(data, false);
	if (ret)
		return ret;

	pm_runtime_mark_last_busy(&data->client->dev);
	return pm_runtime_put_autosuspend(&data->client->dev);
}

static const struct iio_trigger_ops atlas_interrupt_trigger_ops = {
	.owner = THIS_MODULE,
};

static const struct iio_buffer_setup_ops atlas_buffer_setup_ops = {
	.postenable = atlas_buffer_postenable,
	.predisable = atlas_buffer_predisable,
};

static void atlas_work_handler(struct irq_work *work)
{
	struct atlas_data *data = container_of(work, struct atlas_data, work);

	iio_trigger_poll(data->trig);
}

static irqreturn_t atlas_trigger_handler(int irq, void *private)
{
	struct iio_poll_func *pf = private;
	struct iio_dev *indio_dev = pf->indio_dev;
	struct atlas_data *data = iio_priv(indio_dev);
	int ret;

	ret = regmap_bulk_read(data->regmap, ATLAS_REG_PH_DATA,
			      (u8 *) &data->buffer, sizeof(data->buffer[0]));

	if (!ret)
		iio_push_to_buffers_with_timestamp(indio_dev, data->buffer,
				iio_get_time_ns());

	iio_trigger_notify_done(indio_dev->trig);

	return IRQ_HANDLED;
}

static irqreturn_t atlas_interrupt_handler(int irq, void *private)
{
	struct iio_dev *indio_dev = private;
	struct atlas_data *data = iio_priv(indio_dev);

	irq_work_queue(&data->work);

	return IRQ_HANDLED;
}

static int atlas_read_ph_measurement(struct atlas_data *data, __be32 *val)
{
	struct device *dev = &data->client->dev;
	int suspended = pm_runtime_suspended(dev);
	int ret;

	ret = pm_runtime_get_sync(dev);
	if (ret < 0) {
		pm_runtime_put_noidle(dev);
		return ret;
	}

	if (suspended)
		usleep_range(ATLAS_PH_INT_TIME_IN_US,
			     ATLAS_PH_INT_TIME_IN_US + 100000);

	ret = regmap_bulk_read(data->regmap, ATLAS_REG_PH_DATA,
			      (u8 *) val, sizeof(*val));

	pm_runtime_mark_last_busy(dev);
	pm_runtime_put_autosuspend(dev);

	return ret;
}

static int atlas_read_raw(struct iio_dev *indio_dev,
			  struct iio_chan_spec const *chan,
			  int *val, int *val2, long mask)
{
	struct atlas_data *data = iio_priv(indio_dev);

	switch (mask) {
	case IIO_CHAN_INFO_RAW: {
		int ret;
		__be32 reg;

		switch (chan->type) {
		case IIO_TEMP:
			ret = regmap_bulk_read(data->regmap, chan->address,
					      (u8 *) &reg, sizeof(reg));
			break;
		case IIO_PH:
			mutex_lock(&indio_dev->mlock);

			if (iio_buffer_enabled(indio_dev))
				ret = -EBUSY;
			else
				ret = atlas_read_ph_measurement(data, &reg);

			mutex_unlock(&indio_dev->mlock);
			break;
		default:
			ret = -EINVAL;
		}

		if (!ret) {
			*val = be32_to_cpu(reg);
			ret = IIO_VAL_INT;
		}
		return ret;
	}
	case IIO_CHAN_INFO_SCALE:
		switch (chan->type) {
		case IIO_TEMP:
			*val = 1; /* 0.01 */
			*val2 = 100;
			break;
		case IIO_PH:
			*val = 1; /* 0.001 */
			*val2 = 1000;
			break;
		default:
			return -EINVAL;
		}
		return IIO_VAL_FRACTIONAL;
	}

	return -EINVAL;
}

static int atlas_write_raw(struct iio_dev *indio_dev,
			   struct iio_chan_spec const *chan,
			   int val, int val2, long mask)
{
	struct atlas_data *data = iio_priv(indio_dev);
	__be32 reg = cpu_to_be32(val);

	if (val2 != 0 || val < 0 || val > 20000)
		return -EINVAL;

	if (mask != IIO_CHAN_INFO_RAW || chan->type != IIO_TEMP)
		return -EINVAL;

	return regmap_bulk_write(data->regmap, chan->address,
				 &reg, sizeof(reg));
}

static const struct iio_info atlas_info = {
	.driver_module = THIS_MODULE,
	.read_raw = atlas_read_raw,
	.write_raw = atlas_write_raw,
};

static int atlas_check_calibration(struct atlas_data *data)
{
	struct device *dev = &data->client->dev;
	int ret;
	unsigned int val;

	ret = regmap_read(data->regmap, ATLAS_REG_CALIB_STATUS, &val);
	if (ret)
		return ret;

	if (!(val & ATLAS_REG_CALIB_STATUS_MASK)) {
		dev_warn(dev, "device has not been calibrated\n");
		return 0;
	}

	if (!(val & ATLAS_REG_CALIB_STATUS_LOW))
		dev_warn(dev, "device missing low point calibration\n");

	if (!(val & ATLAS_REG_CALIB_STATUS_MID))
		dev_warn(dev, "device missing mid point calibration\n");

	if (!(val & ATLAS_REG_CALIB_STATUS_HIGH))
		dev_warn(dev, "device missing high point calibration\n");

	return 0;
};

static int atlas_probe(struct i2c_client *client,
		       const struct i2c_device_id *id)
{
	struct atlas_data *data;
	struct iio_trigger *trig;
	struct iio_dev *indio_dev;
	int ret;

	indio_dev = devm_iio_device_alloc(&client->dev, sizeof(*data));
	if (!indio_dev)
		return -ENOMEM;

	indio_dev->info = &atlas_info;
	indio_dev->name = ATLAS_DRV_NAME;
	indio_dev->channels = atlas_channels;
	indio_dev->num_channels = ARRAY_SIZE(atlas_channels);
	indio_dev->modes = INDIO_BUFFER_SOFTWARE | INDIO_DIRECT_MODE;
	indio_dev->dev.parent = &client->dev;

	trig = devm_iio_trigger_alloc(&client->dev, "%s-dev%d",
				      indio_dev->name, indio_dev->id);

	if (!trig)
		return -ENOMEM;

	data = iio_priv(indio_dev);
	data->client = client;
	data->trig = trig;
	trig->dev.parent = indio_dev->dev.parent;
	trig->ops = &atlas_interrupt_trigger_ops;
	iio_trigger_set_drvdata(trig, indio_dev);

	i2c_set_clientdata(client, indio_dev);

	data->regmap = devm_regmap_init_i2c(client, &atlas_regmap_config);
	if (IS_ERR(data->regmap)) {
		dev_err(&client->dev, "regmap initialization failed\n");
		return PTR_ERR(data->regmap);
	}

	ret = pm_runtime_set_active(&client->dev);
	if (ret)
		return ret;

	if (client->irq <= 0) {
		dev_err(&client->dev, "no valid irq defined\n");
		return -EINVAL;
	}

	ret = atlas_check_calibration(data);
	if (ret)
		return ret;

	ret = iio_trigger_register(trig);
	if (ret) {
		dev_err(&client->dev, "failed to register trigger\n");
		return ret;
	}

	ret = iio_triggered_buffer_setup(indio_dev, &iio_pollfunc_store_time,
		&atlas_trigger_handler, &atlas_buffer_setup_ops);
	if (ret) {
		dev_err(&client->dev, "cannot setup iio trigger\n");
		goto unregister_trigger;
	}

	init_irq_work(&data->work, atlas_work_handler);

	/* interrupt pin toggles on new conversion */
	ret = devm_request_threaded_irq(&client->dev, client->irq,
					NULL, atlas_interrupt_handler,
					IRQF_TRIGGER_RISING |
					IRQF_TRIGGER_FALLING | IRQF_ONESHOT,
					"atlas_irq",
					indio_dev);
	if (ret) {
		dev_err(&client->dev, "request irq (%d) failed\n", client->irq);
		goto unregister_buffer;
	}

	ret = atlas_set_powermode(data, 1);
	if (ret) {
		dev_err(&client->dev, "cannot power device on");
		goto unregister_buffer;
	}

	pm_runtime_enable(&client->dev);
	pm_runtime_set_autosuspend_delay(&client->dev, 2500);
	pm_runtime_use_autosuspend(&client->dev);

	ret = iio_device_register(indio_dev);
	if (ret) {
		dev_err(&client->dev, "unable to register device\n");
		goto unregister_pm;
	}

	return 0;

unregister_pm:
	pm_runtime_disable(&client->dev);
	atlas_set_powermode(data, 0);

unregister_buffer:
	iio_triggered_buffer_cleanup(indio_dev);

unregister_trigger:
	iio_trigger_unregister(data->trig);

	return ret;
}

static int atlas_remove(struct i2c_client *client)
{
	struct iio_dev *indio_dev = i2c_get_clientdata(client);
	struct atlas_data *data = iio_priv(indio_dev);

	iio_device_unregister(indio_dev);
	iio_triggered_buffer_cleanup(indio_dev);
	iio_trigger_unregister(data->trig);

	pm_runtime_disable(&client->dev);
	pm_runtime_set_suspended(&client->dev);
	pm_runtime_put_noidle(&client->dev);

	return atlas_set_powermode(data, 0);
}

#ifdef CONFIG_PM
static int atlas_runtime_suspend(struct device *dev)
{
	struct atlas_data *data =
		     iio_priv(i2c_get_clientdata(to_i2c_client(dev)));

	return atlas_set_powermode(data, 0);
}

static int atlas_runtime_resume(struct device *dev)
{
	struct atlas_data *data =
		     iio_priv(i2c_get_clientdata(to_i2c_client(dev)));

	return atlas_set_powermode(data, 1);
}
#endif

static const struct dev_pm_ops atlas_pm_ops = {
	SET_RUNTIME_PM_OPS(atlas_runtime_suspend,
			   atlas_runtime_resume, NULL)
};

static const struct i2c_device_id atlas_id[] = {
	{ "atlas-ph-sm", 0 },
	{}
};
MODULE_DEVICE_TABLE(i2c, atlas_id);

static const struct of_device_id atlas_dt_ids[] = {
	{ .compatible = "atlas,ph-sm" },
	{ }
};
MODULE_DEVICE_TABLE(of, atlas_dt_ids);

static struct i2c_driver atlas_driver = {
	.driver = {
		.name	= ATLAS_DRV_NAME,
		.of_match_table	= of_match_ptr(atlas_dt_ids),
		.pm	= &atlas_pm_ops,
	},
	.probe		= atlas_probe,
	.remove		= atlas_remove,
	.id_table	= atlas_id,
};
module_i2c_driver(atlas_driver);

MODULE_AUTHOR("Matt Ranostay <mranostay@gmail.com>");
MODULE_DESCRIPTION("Atlas Scientific pH-SM sensor");
MODULE_LICENSE("GPL");
