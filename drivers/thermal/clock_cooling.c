// SPDX-License-Identifier: GPL-2.0-only
/*
 *  drivers/thermal/clock_cooling.c
 *
 *  Copyright (C) 2014 Eduardo Valentin <edubezval@gmail.com>
 *
 *  Copyright (C) 2013	Texas Instruments Inc.
 *  Contact:  Eduardo Valentin <eduardo.valentin@ti.com>
 *
 *  Highly based on cpufreq_cooling.c.
 *  Copyright (C) 2012	Samsung Electronics Co., Ltd(http://www.samsung.com)
 *  Copyright (C) 2012  Amit Daniel <amit.kachhap@linaro.org>
 */
#include <linux/clk.h>
#include <linux/cpufreq.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/idr.h>
#include <linux/mutex.h>
#include <linux/pm_opp.h>
#include <linux/slab.h>
#include <linux/thermal.h>
#include <linux/clock_cooling.h>

/**
 * struct clock_cooling_device - data for cooling device with clock
 * @id: unique integer value corresponding to each clock_cooling_device
 *	registered.
 * @dev: struct device pointer to the device being used to cool off using
 *       clock frequencies.
 * @cdev: thermal_cooling_device pointer to keep track of the
 *	registered cooling device.
 * @clk_rate_change_nb: reference to notifier block used to receive clock
 *                      rate changes.
 * @freq_table: frequency table used to keep track of available frequencies.
 * @clock_state: integer value representing the current state of clock
 *	cooling	devices.
 * @clock_val: integer value representing the absolute value of the clipped
 *	frequency.
 * @clk: struct clk reference used to enforce clock limits.
 * @lock: mutex lock to protect this struct.
 *
 * This structure is required for keeping information of each
 * clock_cooling_device registered. In order to prevent corruption of this a
 * mutex @lock is used.
 */
struct clock_cooling_device {
	int id;
	struct device *dev;
	struct thermal_cooling_device *cdev;
	struct notifier_block clk_rate_change_nb;
	struct cpufreq_frequency_table *freq_table;
	unsigned long clock_state;
	unsigned long clock_val;
	struct clk *clk;
	struct mutex lock; /* lock to protect the content of this struct */
};
#define to_clock_cooling_device(x) \
		container_of(x, struct clock_cooling_device, clk_rate_change_nb)
static DEFINE_IDA(clock_ida);

/* Below code defines functions to be used for clock as cooling device */

enum clock_cooling_property {
	GET_LEVEL,
	GET_FREQ,
	GET_MAXL,
};

/**
 * clock_cooling_get_property - fetch a property of interest for a give cpu.
 * @ccdev: clock cooling device reference
 * @input: query parameter
 * @output: query return
 * @property: type of query (frequency, level, max level)
 *
 * This is the common function to
 * 1. get maximum clock cooling states
 * 2. translate frequency to cooling state
 * 3. translate cooling state to frequency
 * Note that the code may be not in good shape
 * but it is written in this way in order to:
 * a) reduce duplicate code as most of the code can be shared.
 * b) make sure the logic is consistent when translating between
 *    cooling states and frequencies.
 *
 * Return: 0 on success, -EINVAL when invalid parameters are passed.
 */
static int clock_cooling_get_property(struct clock_cooling_device *ccdev,
				      unsigned long input,
				      unsigned long *output,
				      enum clock_cooling_property property)
{
	int i;
	unsigned long max_level = 0, level = 0;
	unsigned int freq = CPUFREQ_ENTRY_INVALID;
	int descend = -1;
	struct cpufreq_frequency_table *pos, *table = ccdev->freq_table;

	if (!output)
		return -EINVAL;

	if (!table)
		return -EINVAL;

	cpufreq_for_each_valid_entry(pos, table) {
		/* ignore duplicate entry */
		if (freq == pos->frequency)
			continue;

		/* get the frequency order */
		if (freq != CPUFREQ_ENTRY_INVALID && descend == -1)
			descend = freq > pos->frequency;

		freq = pos->frequency;
		max_level++;
	}

	/* No valid cpu frequency entry */
	if (max_level == 0)
		return -EINVAL;

	/* max_level is an index, not a counter */
	max_level--;

	/* get max level */
	if (property == GET_MAXL) {
		*output = max_level;
		return 0;
	}

	if (property == GET_FREQ)
		level = descend ? input : (max_level - input);

	i = 0;
	cpufreq_for_each_valid_entry(pos, table) {
		/* ignore duplicate entry */
		if (freq == pos->frequency)
			continue;

		/* now we have a valid frequency entry */
		freq = pos->frequency;

		if (property == GET_LEVEL && (unsigned int)input == freq) {
			/* get level by frequency */
			*output = descend ? i : (max_level - i);
			return 0;
		}
		if (property == GET_FREQ && level == i) {
			/* get frequency by level */
			*output = freq;
			return 0;
		}
		i++;
	}

	return -EINVAL;
}

/**
 * clock_cooling_get_level - return the cooling level of given clock cooling.
 * @cdev: reference of a thermal cooling device of used as clock cooling device
 * @freq: the frequency of interest
 *
 * This function will match the cooling level corresponding to the
 * requested @freq and return it.
 *
 * Return: The matched cooling level on success or THERMAL_CSTATE_INVALID
 * otherwise.
 */
unsigned long clock_cooling_get_level(struct thermal_cooling_device *cdev,
				      unsigned long freq)
{
	struct clock_cooling_device *ccdev = cdev->devdata;
	unsigned long val;

	if (clock_cooling_get_property(ccdev, (unsigned long)freq, &val,
				       GET_LEVEL))
		return THERMAL_CSTATE_INVALID;

	return val;
}
EXPORT_SYMBOL_GPL(clock_cooling_get_level);

/**
 * clock_cooling_get_frequency - get the absolute value of frequency from level.
 * @ccdev: clock cooling device reference
 * @level: cooling level
 *
 * This function matches cooling level with frequency. Based on a cooling level
 * of frequency, equals cooling state of cpu cooling device, it will return
 * the corresponding frequency.
 *	e.g level=0 --> 1st MAX FREQ, level=1 ---> 2nd MAX FREQ, .... etc
 *
 * Return: 0 on error, the corresponding frequency otherwise.
 */
static unsigned long
clock_cooling_get_frequency(struct clock_cooling_device *ccdev,
			    unsigned long level)
{
	int ret = 0;
	unsigned long freq;

	ret = clock_cooling_get_property(ccdev, level, &freq, GET_FREQ);
	if (ret)
		return 0;

	return freq;
}

/**
 * clock_cooling_apply - function to apply frequency clipping.
 * @ccdev: clock_cooling_device pointer containing frequency clipping data.
 * @cooling_state: value of the cooling state.
 *
 * Function used to make sure the clock layer is aware of current thermal
 * limits. The limits are applied by updating the clock rate in case it is
 * higher than the corresponding frequency based on the requested cooling_state.
 *
 * Return: 0 on success, an error code otherwise (-EINVAL in case wrong
 * cooling state).
 */
static int clock_cooling_apply(struct clock_cooling_device *ccdev,
			       unsigned long cooling_state)
{
	unsigned long clip_freq, cur_freq;
	int ret = 0;

	/* Here we write the clipping */
	/* Check if the old cooling action is same as new cooling action */
	if (ccdev->clock_state == cooling_state)
		return 0;

	clip_freq = clock_cooling_get_frequency(ccdev, cooling_state);
	if (!clip_freq)
		return -EINVAL;

	cur_freq = clk_get_rate(ccdev->clk);

	mutex_lock(&ccdev->lock);
	ccdev->clock_state = cooling_state;
	ccdev->clock_val = clip_freq;
	/* enforce clock level */
	if (cur_freq > clip_freq)
		ret = clk_set_rate(ccdev->clk, clip_freq);
	mutex_unlock(&ccdev->lock);

	return ret;
}

/**
 * clock_cooling_clock_notifier - notifier callback on clock rate changes.
 * @nb:	struct notifier_block * with callback info.
 * @event: value showing clock event for which this function invoked.
 * @data: callback-specific data
 *
 * Callback to hijack the notification on clock transition.
 * Every time there is a clock change, we intercept all pre change events
 * and block the transition in case the new rate infringes thermal limits.
 *
 * Return: NOTIFY_DONE (success) or NOTIFY_BAD (new_rate > thermal limit).
 */
static int clock_cooling_clock_notifier(struct notifier_block *nb,
					unsigned long event, void *data)
{
	struct clk_notifier_data *ndata = data;
	struct clock_cooling_device *ccdev = to_clock_cooling_device(nb);

	switch (event) {
	case PRE_RATE_CHANGE:
		/*
		 * checks on current state
		 * TODO: current method is not best we can find as it
		 * allows possibly voltage transitions, in case DVFS
		 * layer is also hijacking clock pre notifications.
		 */
		if (ndata->new_rate > ccdev->clock_val)
			return NOTIFY_BAD;
		/* fall through */
	case POST_RATE_CHANGE:
	case ABORT_RATE_CHANGE:
	default:
		return NOTIFY_DONE;
	}
}

/* clock cooling device thermal callback functions are defined below */

/**
 * clock_cooling_get_max_state - callback function to get the max cooling state.
 * @cdev: thermal cooling device pointer.
 * @state: fill this variable with the max cooling state.
 *
 * Callback for the thermal cooling device to return the clock
 * max cooling state.
 *
 * Return: 0 on success, an error code otherwise.
 */
static int clock_cooling_get_max_state(struct thermal_cooling_device *cdev,
				       unsigned long *state)
{
	struct clock_cooling_device *ccdev = cdev->devdata;
	unsigned long count = 0;
	int ret;

	ret = clock_cooling_get_property(ccdev, 0, &count, GET_MAXL);
	if (!ret)
		*state = count;

	return ret;
}

/**
 * clock_cooling_get_cur_state - function to get the current cooling state.
 * @cdev: thermal cooling device pointer.
 * @state: fill this variable with the current cooling state.
 *
 * Callback for the thermal cooling device to return the clock
 * current cooling state.
 *
 * Return: 0 (success)
 */
static int clock_cooling_get_cur_state(struct thermal_cooling_device *cdev,
				       unsigned long *state)
{
	struct clock_cooling_device *ccdev = cdev->devdata;

	*state = ccdev->clock_state;

	return 0;
}

/**
 * clock_cooling_set_cur_state - function to set the current cooling state.
 * @cdev: thermal cooling device pointer.
 * @state: set this variable to the current cooling state.
 *
 * Callback for the thermal cooling device to change the clock cooling
 * current cooling state.
 *
 * Return: 0 on success, an error code otherwise.
 */
static int clock_cooling_set_cur_state(struct thermal_cooling_device *cdev,
				       unsigned long state)
{
	struct clock_cooling_device *clock_device = cdev->devdata;

	return clock_cooling_apply(clock_device, state);
}

/* Bind clock callbacks to thermal cooling device ops */
static struct thermal_cooling_device_ops const clock_cooling_ops = {
	.get_max_state = clock_cooling_get_max_state,
	.get_cur_state = clock_cooling_get_cur_state,
	.set_cur_state = clock_cooling_set_cur_state,
};

/**
 * clock_cooling_register - function to create clock cooling device.
 * @dev: struct device pointer to the device used as clock cooling device.
 * @clock_name: string containing the clock used as cooling mechanism.
 *
 * This interface function registers the clock cooling device with the name
 * "thermal-clock-%x". The cooling device is based on clock frequencies.
 * The struct device is assumed to be capable of DVFS transitions.
 * The OPP layer is used to fetch and fill the available frequencies for
 * the referred device. The ordered frequency table is used to control
 * the clock cooling device cooling states and to limit clock transitions
 * based on the cooling state requested by the thermal framework.
 *
 * Return: a valid struct thermal_cooling_device pointer on success,
 * on failure, it returns a corresponding ERR_PTR().
 */
struct thermal_cooling_device *
clock_cooling_register(struct device *dev, const char *clock_name)
{
	struct thermal_cooling_device *cdev;
	struct clock_cooling_device *ccdev = NULL;
	char dev_name[THERMAL_NAME_LENGTH];
	int ret = 0;

	ccdev = devm_kzalloc(dev, sizeof(*ccdev), GFP_KERNEL);
	if (!ccdev)
		return ERR_PTR(-ENOMEM);

	mutex_init(&ccdev->lock);
	ccdev->dev = dev;
	ccdev->clk = devm_clk_get(dev, clock_name);
	if (IS_ERR(ccdev->clk))
		return ERR_CAST(ccdev->clk);

	ret = ida_simple_get(&clock_ida, 0, 0, GFP_KERNEL);
	if (ret < 0)
		return ERR_PTR(ret);
	ccdev->id = ret;

	snprintf(dev_name, sizeof(dev_name), "thermal-clock-%d", ccdev->id);

	cdev = thermal_cooling_device_register(dev_name, ccdev,
					       &clock_cooling_ops);
	if (IS_ERR(cdev)) {
		ida_simple_remove(&clock_ida, ccdev->id);
		return ERR_PTR(-EINVAL);
	}
	ccdev->cdev = cdev;
	ccdev->clk_rate_change_nb.notifier_call = clock_cooling_clock_notifier;

	/* Assuming someone has already filled the opp table for this device */
	ret = dev_pm_opp_init_cpufreq_table(dev, &ccdev->freq_table);
	if (ret) {
		ida_simple_remove(&clock_ida, ccdev->id);
		return ERR_PTR(ret);
	}
	ccdev->clock_state = 0;
	ccdev->clock_val = clock_cooling_get_frequency(ccdev, 0);

	clk_notifier_register(ccdev->clk, &ccdev->clk_rate_change_nb);

	return cdev;
}
EXPORT_SYMBOL_GPL(clock_cooling_register);

/**
 * clock_cooling_unregister - function to remove clock cooling device.
 * @cdev: thermal cooling device pointer.
 *
 * This interface function unregisters the "thermal-clock-%x" cooling device.
 */
void clock_cooling_unregister(struct thermal_cooling_device *cdev)
{
	struct clock_cooling_device *ccdev;

	if (!cdev)
		return;

	ccdev = cdev->devdata;

	clk_notifier_unregister(ccdev->clk, &ccdev->clk_rate_change_nb);
	dev_pm_opp_free_cpufreq_table(ccdev->dev, &ccdev->freq_table);

	thermal_cooling_device_unregister(ccdev->cdev);
	ida_simple_remove(&clock_ida, ccdev->id);
}
EXPORT_SYMBOL_GPL(clock_cooling_unregister);
