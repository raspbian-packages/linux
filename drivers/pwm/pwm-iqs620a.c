// SPDX-License-Identifier: GPL-2.0+
/*
 * Azoteq IQS620A PWM Generator
 *
 * Copyright (C) 2019 Jeff LaBundy <jeff@labundy.com>
 *
 * Limitations:
 * - The period is fixed to 1 ms and is generated continuously despite changes
 *   to the duty cycle or enable/disable state.
 * - Changes to the duty cycle or enable/disable state take effect immediately
 *   and may result in a glitch during the period in which the change is made.
 * - The device cannot generate a 0% duty cycle. For duty cycles below 1 / 256
 *   ms, the output is disabled and relies upon an external pull-down resistor
 *   to hold the GPIO3/LTX pin low.
 */

#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/mfd/iqs62x.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/platform_device.h>
#include <linux/pwm.h>
#include <linux/regmap.h>
#include <linux/slab.h>

#define IQS620_PWR_SETTINGS			0xd2
#define IQS620_PWR_SETTINGS_PWM_OUT		BIT(7)

#define IQS620_PWM_DUTY_CYCLE			0xd8

#define IQS620_PWM_PERIOD_NS			1000000

struct iqs620_pwm_private {
	struct iqs62x_core *iqs62x;
	struct pwm_chip chip;
	struct notifier_block notifier;
	struct mutex lock;
	bool out_en;
	u8 duty_val;
};

static int iqs620_pwm_apply(struct pwm_chip *chip, struct pwm_device *pwm,
			    const struct pwm_state *state)
{
	struct iqs620_pwm_private *iqs620_pwm;
	struct iqs62x_core *iqs62x;
	unsigned int duty_cycle;
	unsigned int duty_scale;
	int ret;

	if (state->polarity != PWM_POLARITY_NORMAL)
		return -ENOTSUPP;

	if (state->period < IQS620_PWM_PERIOD_NS)
		return -EINVAL;

	iqs620_pwm = container_of(chip, struct iqs620_pwm_private, chip);
	iqs62x = iqs620_pwm->iqs62x;

	/*
	 * The duty cycle generated by the device is calculated as follows:
	 *
	 * duty_cycle = (IQS620_PWM_DUTY_CYCLE + 1) / 256 * 1 ms
	 *
	 * ...where IQS620_PWM_DUTY_CYCLE is a register value between 0 and 255
	 * (inclusive). Therefore the lowest duty cycle the device can generate
	 * while the output is enabled is 1 / 256 ms.
	 *
	 * For lower duty cycles (e.g. 0), the PWM output is simply disabled to
	 * allow an external pull-down resistor to hold the GPIO3/LTX pin low.
	 */
	duty_cycle = min_t(u64, state->duty_cycle, IQS620_PWM_PERIOD_NS);
	duty_scale = duty_cycle * 256 / IQS620_PWM_PERIOD_NS;

	mutex_lock(&iqs620_pwm->lock);

	if (!state->enabled || !duty_scale) {
		ret = regmap_update_bits(iqs62x->regmap, IQS620_PWR_SETTINGS,
					 IQS620_PWR_SETTINGS_PWM_OUT, 0);
		if (ret)
			goto err_mutex;
	}

	if (duty_scale) {
		u8 duty_val = duty_scale - 1;

		ret = regmap_write(iqs62x->regmap, IQS620_PWM_DUTY_CYCLE,
				   duty_val);
		if (ret)
			goto err_mutex;

		iqs620_pwm->duty_val = duty_val;
	}

	if (state->enabled && duty_scale) {
		ret = regmap_update_bits(iqs62x->regmap, IQS620_PWR_SETTINGS,
					 IQS620_PWR_SETTINGS_PWM_OUT, 0xff);
		if (ret)
			goto err_mutex;
	}

	iqs620_pwm->out_en = state->enabled;

err_mutex:
	mutex_unlock(&iqs620_pwm->lock);

	return ret;
}

static void iqs620_pwm_get_state(struct pwm_chip *chip, struct pwm_device *pwm,
				 struct pwm_state *state)
{
	struct iqs620_pwm_private *iqs620_pwm;

	iqs620_pwm = container_of(chip, struct iqs620_pwm_private, chip);

	mutex_lock(&iqs620_pwm->lock);

	/*
	 * Since the device cannot generate a 0% duty cycle, requests to do so
	 * cause subsequent calls to iqs620_pwm_get_state to report the output
	 * as disabled with duty cycle equal to that which was in use prior to
	 * the request. This is not ideal, but is the best compromise based on
	 * the capabilities of the device.
	 */
	state->enabled = iqs620_pwm->out_en;
	state->duty_cycle = DIV_ROUND_UP((iqs620_pwm->duty_val + 1) *
					 IQS620_PWM_PERIOD_NS, 256);

	mutex_unlock(&iqs620_pwm->lock);

	state->period = IQS620_PWM_PERIOD_NS;
}

static int iqs620_pwm_notifier(struct notifier_block *notifier,
			       unsigned long event_flags, void *context)
{
	struct iqs620_pwm_private *iqs620_pwm;
	struct iqs62x_core *iqs62x;
	int ret;

	if (!(event_flags & BIT(IQS62X_EVENT_SYS_RESET)))
		return NOTIFY_DONE;

	iqs620_pwm = container_of(notifier, struct iqs620_pwm_private,
				  notifier);
	iqs62x = iqs620_pwm->iqs62x;

	mutex_lock(&iqs620_pwm->lock);

	/*
	 * The parent MFD driver already prints an error message in the event
	 * of a device reset, so nothing else is printed here unless there is
	 * an additional failure.
	 */
	ret = regmap_write(iqs62x->regmap, IQS620_PWM_DUTY_CYCLE,
			   iqs620_pwm->duty_val);
	if (ret)
		goto err_mutex;

	ret = regmap_update_bits(iqs62x->regmap, IQS620_PWR_SETTINGS,
				 IQS620_PWR_SETTINGS_PWM_OUT,
				 iqs620_pwm->out_en ? 0xff : 0);

err_mutex:
	mutex_unlock(&iqs620_pwm->lock);

	if (ret) {
		dev_err(iqs620_pwm->chip.dev,
			"Failed to re-initialize device: %d\n", ret);
		return NOTIFY_BAD;
	}

	return NOTIFY_OK;
}

static const struct pwm_ops iqs620_pwm_ops = {
	.apply = iqs620_pwm_apply,
	.get_state = iqs620_pwm_get_state,
	.owner = THIS_MODULE,
};

static void iqs620_pwm_notifier_unregister(void *context)
{
	struct iqs620_pwm_private *iqs620_pwm = context;
	int ret;

	ret = blocking_notifier_chain_unregister(&iqs620_pwm->iqs62x->nh,
						 &iqs620_pwm->notifier);
	if (ret)
		dev_err(iqs620_pwm->chip.dev,
			"Failed to unregister notifier: %d\n", ret);
}

static int iqs620_pwm_probe(struct platform_device *pdev)
{
	struct iqs62x_core *iqs62x = dev_get_drvdata(pdev->dev.parent);
	struct iqs620_pwm_private *iqs620_pwm;
	unsigned int val;
	int ret;

	iqs620_pwm = devm_kzalloc(&pdev->dev, sizeof(*iqs620_pwm), GFP_KERNEL);
	if (!iqs620_pwm)
		return -ENOMEM;

	platform_set_drvdata(pdev, iqs620_pwm);
	iqs620_pwm->iqs62x = iqs62x;

	ret = regmap_read(iqs62x->regmap, IQS620_PWR_SETTINGS, &val);
	if (ret)
		return ret;
	iqs620_pwm->out_en = val & IQS620_PWR_SETTINGS_PWM_OUT;

	ret = regmap_read(iqs62x->regmap, IQS620_PWM_DUTY_CYCLE, &val);
	if (ret)
		return ret;
	iqs620_pwm->duty_val = val;

	iqs620_pwm->chip.dev = &pdev->dev;
	iqs620_pwm->chip.ops = &iqs620_pwm_ops;
	iqs620_pwm->chip.base = -1;
	iqs620_pwm->chip.npwm = 1;

	mutex_init(&iqs620_pwm->lock);

	iqs620_pwm->notifier.notifier_call = iqs620_pwm_notifier;
	ret = blocking_notifier_chain_register(&iqs620_pwm->iqs62x->nh,
					       &iqs620_pwm->notifier);
	if (ret) {
		dev_err(&pdev->dev, "Failed to register notifier: %d\n", ret);
		return ret;
	}

	ret = devm_add_action_or_reset(&pdev->dev,
				       iqs620_pwm_notifier_unregister,
				       iqs620_pwm);
	if (ret)
		return ret;

	ret = pwmchip_add(&iqs620_pwm->chip);
	if (ret)
		dev_err(&pdev->dev, "Failed to add device: %d\n", ret);

	return ret;
}

static int iqs620_pwm_remove(struct platform_device *pdev)
{
	struct iqs620_pwm_private *iqs620_pwm = platform_get_drvdata(pdev);
	int ret;

	ret = pwmchip_remove(&iqs620_pwm->chip);
	if (ret)
		dev_err(&pdev->dev, "Failed to remove device: %d\n", ret);

	return ret;
}

static struct platform_driver iqs620_pwm_platform_driver = {
	.driver = {
		.name = "iqs620a-pwm",
	},
	.probe = iqs620_pwm_probe,
	.remove = iqs620_pwm_remove,
};
module_platform_driver(iqs620_pwm_platform_driver);

MODULE_AUTHOR("Jeff LaBundy <jeff@labundy.com>");
MODULE_DESCRIPTION("Azoteq IQS620A PWM Generator");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:iqs620a-pwm");
