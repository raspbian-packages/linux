/*
 * spitz.c  --  SoC audio for Sharp SL-Cxx00 models Spitz, Borzoi and Akita
 *
 * Copyright 2005 Wolfson Microelectronics PLC.
 * Copyright 2005 Openedhand Ltd.
 *
 * Authors: Liam Girdwood <lrg@slimlogic.co.uk>
 *          Richard Purdie <richard@openedhand.com>
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 *
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/gpio.h>
#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/soc.h>

#include <asm/mach-types.h>
#include <mach/spitz.h>
#include "../codecs/wm8750.h"
#include "pxa2xx-i2s.h"

#define SPITZ_HP        0
#define SPITZ_MIC       1
#define SPITZ_LINE      2
#define SPITZ_HEADSET   3
#define SPITZ_HP_OFF    4
#define SPITZ_SPK_ON    0
#define SPITZ_SPK_OFF   1

 /* audio clock in Hz - rounded from 12.235MHz */
#define SPITZ_AUDIO_CLOCK 12288000

static int spitz_jack_func;
static int spitz_spk_func;
static int spitz_mic_gpio;

static void spitz_ext_control(struct snd_soc_codec *codec)
{
	struct snd_soc_dapm_context *dapm = &codec->dapm;

	if (spitz_spk_func == SPITZ_SPK_ON)
		snd_soc_dapm_enable_pin(dapm, "Ext Spk");
	else
		snd_soc_dapm_disable_pin(dapm, "Ext Spk");

	/* set up jack connection */
	switch (spitz_jack_func) {
	case SPITZ_HP:
		/* enable and unmute hp jack, disable mic bias */
		snd_soc_dapm_disable_pin(dapm, "Headset Jack");
		snd_soc_dapm_disable_pin(dapm, "Mic Jack");
		snd_soc_dapm_disable_pin(dapm, "Line Jack");
		snd_soc_dapm_enable_pin(dapm, "Headphone Jack");
		gpio_set_value(SPITZ_GPIO_MUTE_L, 1);
		gpio_set_value(SPITZ_GPIO_MUTE_R, 1);
		break;
	case SPITZ_MIC:
		/* enable mic jack and bias, mute hp */
		snd_soc_dapm_disable_pin(dapm, "Headphone Jack");
		snd_soc_dapm_disable_pin(dapm, "Headset Jack");
		snd_soc_dapm_disable_pin(dapm, "Line Jack");
		snd_soc_dapm_enable_pin(dapm, "Mic Jack");
		gpio_set_value(SPITZ_GPIO_MUTE_L, 0);
		gpio_set_value(SPITZ_GPIO_MUTE_R, 0);
		break;
	case SPITZ_LINE:
		/* enable line jack, disable mic bias and mute hp */
		snd_soc_dapm_disable_pin(dapm, "Headphone Jack");
		snd_soc_dapm_disable_pin(dapm, "Headset Jack");
		snd_soc_dapm_disable_pin(dapm, "Mic Jack");
		snd_soc_dapm_enable_pin(dapm, "Line Jack");
		gpio_set_value(SPITZ_GPIO_MUTE_L, 0);
		gpio_set_value(SPITZ_GPIO_MUTE_R, 0);
		break;
	case SPITZ_HEADSET:
		/* enable and unmute headset jack enable mic bias, mute L hp */
		snd_soc_dapm_disable_pin(dapm, "Headphone Jack");
		snd_soc_dapm_enable_pin(dapm, "Mic Jack");
		snd_soc_dapm_disable_pin(dapm, "Line Jack");
		snd_soc_dapm_enable_pin(dapm, "Headset Jack");
		gpio_set_value(SPITZ_GPIO_MUTE_L, 0);
		gpio_set_value(SPITZ_GPIO_MUTE_R, 1);
		break;
	case SPITZ_HP_OFF:

		/* jack removed, everything off */
		snd_soc_dapm_disable_pin(dapm, "Headphone Jack");
		snd_soc_dapm_disable_pin(dapm, "Headset Jack");
		snd_soc_dapm_disable_pin(dapm, "Mic Jack");
		snd_soc_dapm_disable_pin(dapm, "Line Jack");
		gpio_set_value(SPITZ_GPIO_MUTE_L, 0);
		gpio_set_value(SPITZ_GPIO_MUTE_R, 0);
		break;
	}
	snd_soc_dapm_sync(dapm);
}

static int spitz_startup(struct snd_pcm_substream *substream)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct snd_soc_codec *codec = rtd->codec;

	mutex_lock(&codec->mutex);

	/* check the jack status at stream startup */
	spitz_ext_control(codec);

	mutex_unlock(&codec->mutex);

	return 0;
}

static int spitz_hw_params(struct snd_pcm_substream *substream,
	struct snd_pcm_hw_params *params)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct snd_soc_dai *codec_dai = rtd->codec_dai;
	struct snd_soc_dai *cpu_dai = rtd->cpu_dai;
	unsigned int clk = 0;
	int ret = 0;

	switch (params_rate(params)) {
	case 8000:
	case 16000:
	case 48000:
	case 96000:
		clk = 12288000;
		break;
	case 11025:
	case 22050:
	case 44100:
		clk = 11289600;
		break;
	}

	/* set codec DAI configuration */
	ret = snd_soc_dai_set_fmt(codec_dai, SND_SOC_DAIFMT_I2S |
		SND_SOC_DAIFMT_NB_NF | SND_SOC_DAIFMT_CBS_CFS);
	if (ret < 0)
		return ret;

	/* set cpu DAI configuration */
	ret = snd_soc_dai_set_fmt(cpu_dai, SND_SOC_DAIFMT_I2S |
		SND_SOC_DAIFMT_NB_NF | SND_SOC_DAIFMT_CBS_CFS);
	if (ret < 0)
		return ret;

	/* set the codec system clock for DAC and ADC */
	ret = snd_soc_dai_set_sysclk(codec_dai, WM8750_SYSCLK, clk,
		SND_SOC_CLOCK_IN);
	if (ret < 0)
		return ret;

	/* set the I2S system clock as input (unused) */
	ret = snd_soc_dai_set_sysclk(cpu_dai, PXA2XX_I2S_SYSCLK, 0,
		SND_SOC_CLOCK_IN);
	if (ret < 0)
		return ret;

	return 0;
}

static struct snd_soc_ops spitz_ops = {
	.startup = spitz_startup,
	.hw_params = spitz_hw_params,
};

static int spitz_get_jack(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol)
{
	ucontrol->value.integer.value[0] = spitz_jack_func;
	return 0;
}

static int spitz_set_jack(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_kcontrol_chip(kcontrol);

	if (spitz_jack_func == ucontrol->value.integer.value[0])
		return 0;

	spitz_jack_func = ucontrol->value.integer.value[0];
	spitz_ext_control(codec);
	return 1;
}

static int spitz_get_spk(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol)
{
	ucontrol->value.integer.value[0] = spitz_spk_func;
	return 0;
}

static int spitz_set_spk(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec =  snd_kcontrol_chip(kcontrol);

	if (spitz_spk_func == ucontrol->value.integer.value[0])
		return 0;

	spitz_spk_func = ucontrol->value.integer.value[0];
	spitz_ext_control(codec);
	return 1;
}

static int spitz_mic_bias(struct snd_soc_dapm_widget *w,
	struct snd_kcontrol *k, int event)
{
	gpio_set_value_cansleep(spitz_mic_gpio, SND_SOC_DAPM_EVENT_ON(event));
	return 0;
}

/* spitz machine dapm widgets */
static const struct snd_soc_dapm_widget wm8750_dapm_widgets[] = {
	SND_SOC_DAPM_HP("Headphone Jack", NULL),
	SND_SOC_DAPM_MIC("Mic Jack", spitz_mic_bias),
	SND_SOC_DAPM_SPK("Ext Spk", NULL),
	SND_SOC_DAPM_LINE("Line Jack", NULL),

	/* headset is a mic and mono headphone */
	SND_SOC_DAPM_HP("Headset Jack", NULL),
};

/* Spitz machine audio_map */
static const struct snd_soc_dapm_route audio_map[] = {

	/* headphone connected to LOUT1, ROUT1 */
	{"Headphone Jack", NULL, "LOUT1"},
	{"Headphone Jack", NULL, "ROUT1"},

	/* headset connected to ROUT1 and LINPUT1 with bias (def below) */
	{"Headset Jack", NULL, "ROUT1"},

	/* ext speaker connected to LOUT2, ROUT2  */
	{"Ext Spk", NULL , "ROUT2"},
	{"Ext Spk", NULL , "LOUT2"},

	/* mic is connected to input 1 - with bias */
	{"LINPUT1", NULL, "Mic Bias"},
	{"Mic Bias", NULL, "Mic Jack"},

	/* line is connected to input 1 - no bias */
	{"LINPUT1", NULL, "Line Jack"},
};

static const char *jack_function[] = {"Headphone", "Mic", "Line", "Headset",
	"Off"};
static const char *spk_function[] = {"On", "Off"};
static const struct soc_enum spitz_enum[] = {
	SOC_ENUM_SINGLE_EXT(5, jack_function),
	SOC_ENUM_SINGLE_EXT(2, spk_function),
};

static const struct snd_kcontrol_new wm8750_spitz_controls[] = {
	SOC_ENUM_EXT("Jack Function", spitz_enum[0], spitz_get_jack,
		spitz_set_jack),
	SOC_ENUM_EXT("Speaker Function", spitz_enum[1], spitz_get_spk,
		spitz_set_spk),
};

/*
 * Logic for a wm8750 as connected on a Sharp SL-Cxx00 Device
 */
static int spitz_wm8750_init(struct snd_soc_pcm_runtime *rtd)
{
	struct snd_soc_codec *codec = rtd->codec;
	struct snd_soc_dapm_context *dapm = &codec->dapm;
	int err;

	/* NC codec pins */
	snd_soc_dapm_nc_pin(dapm, "RINPUT1");
	snd_soc_dapm_nc_pin(dapm, "LINPUT2");
	snd_soc_dapm_nc_pin(dapm, "RINPUT2");
	snd_soc_dapm_nc_pin(dapm, "LINPUT3");
	snd_soc_dapm_nc_pin(dapm, "RINPUT3");
	snd_soc_dapm_nc_pin(dapm, "OUT3");
	snd_soc_dapm_nc_pin(dapm, "MONO1");

	/* Add spitz specific controls */
	err = snd_soc_add_controls(codec, wm8750_spitz_controls,
				ARRAY_SIZE(wm8750_spitz_controls));
	if (err < 0)
		return err;

	/* Add spitz specific widgets */
	snd_soc_dapm_new_controls(dapm, wm8750_dapm_widgets,
				  ARRAY_SIZE(wm8750_dapm_widgets));

	/* Set up spitz specific audio paths */
	snd_soc_dapm_add_routes(dapm, audio_map, ARRAY_SIZE(audio_map));

	return 0;
}

/* spitz digital audio interface glue - connects codec <--> CPU */
static struct snd_soc_dai_link spitz_dai = {
	.name = "wm8750",
	.stream_name = "WM8750",
	.cpu_dai_name = "pxa2xx-i2s",
	.codec_dai_name = "wm8750-hifi",
	.platform_name = "pxa-pcm-audio",
	.codec_name = "wm8750.0-001b",
	.init = spitz_wm8750_init,
	.ops = &spitz_ops,
};

/* spitz audio machine driver */
static struct snd_soc_card snd_soc_spitz = {
	.name = "Spitz",
	.dai_link = &spitz_dai,
	.num_links = 1,
};

static struct platform_device *spitz_snd_device;

static int __init spitz_init(void)
{
	int ret;

	if (!(machine_is_spitz() || machine_is_borzoi() || machine_is_akita()))
		return -ENODEV;

	if (machine_is_borzoi() || machine_is_spitz())
		spitz_mic_gpio = SPITZ_GPIO_MIC_BIAS;
	else
		spitz_mic_gpio = AKITA_GPIO_MIC_BIAS;

	ret = gpio_request(spitz_mic_gpio, "MIC GPIO");
	if (ret)
		goto err1;

	ret = gpio_direction_output(spitz_mic_gpio, 0);
	if (ret)
		goto err2;

	spitz_snd_device = platform_device_alloc("soc-audio", -1);
	if (!spitz_snd_device) {
		ret = -ENOMEM;
		goto err2;
	}

	platform_set_drvdata(spitz_snd_device, &snd_soc_spitz);

	ret = platform_device_add(spitz_snd_device);
	if (ret)
		goto err3;

	return 0;

err3:
	platform_device_put(spitz_snd_device);
err2:
	gpio_free(spitz_mic_gpio);
err1:
	return ret;
}

static void __exit spitz_exit(void)
{
	platform_device_unregister(spitz_snd_device);
	gpio_free(spitz_mic_gpio);
}

module_init(spitz_init);
module_exit(spitz_exit);

MODULE_AUTHOR("Richard Purdie");
MODULE_DESCRIPTION("ALSA SoC Spitz");
MODULE_LICENSE("GPL");
