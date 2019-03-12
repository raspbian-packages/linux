/*
 * rt274.h  --  RT274 ALSA SoC audio driver
 *
 * Copyright 2016 Realtek Microelectronics
 * Author: Bard Liao <bardliao@realtek.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __RT274_H__
#define __RT274_H__

#define VERB_CMD(V, N, D) ((N << 20) | (V << 8) | D)

#define RT274_AUDIO_FUNCTION_GROUP			0x01
#define RT274_DAC_OUT0					0x02
#define RT274_DAC_OUT1					0x03
#define RT274_ADC_IN2					0x08
#define RT274_ADC_IN1					0x09
#define RT274_DIG_CVT					0x0a
#define RT274_DMIC1					0x12
#define RT274_DMIC2					0x13
#define RT274_MIC					0x19
#define RT274_LINE1					0x1a
#define RT274_LINE2					0x1b
#define RT274_LINE3					0x16
#define RT274_SPDIF					0x1e
#define RT274_VENDOR_REGISTERS				0x20
#define RT274_HP_OUT					0x21
#define RT274_MIXER_IN1					0x22
#define RT274_MIXER_IN2					0x23
#define RT274_INLINE_CMD				0x55

#define RT274_SET_PIN_SFT				6
#define RT274_SET_PIN_ENABLE				0x40
#define RT274_SET_PIN_DISABLE				0
#define RT274_SET_EAPD_HIGH				0x2
#define RT274_SET_EAPD_LOW				0

#define RT274_MUTE_SFT					7

/* Verb commands */
#define RT274_RESET\
	VERB_CMD(AC_VERB_SET_CODEC_RESET, RT274_AUDIO_FUNCTION_GROUP, 0)
#define RT274_GET_PARAM(NID, PARAM) VERB_CMD(AC_VERB_PARAMETERS, NID, PARAM)
#define RT274_SET_POWER(NID) VERB_CMD(AC_VERB_SET_POWER_STATE, NID, 0)
#define RT274_SET_AUDIO_POWER RT274_SET_POWER(RT274_AUDIO_FUNCTION_GROUP)
#define RT274_SET_HPO_POWER RT274_SET_POWER(RT274_HP_OUT)
#define RT274_SET_DMIC1_POWER RT274_SET_POWER(RT274_DMIC1)
#define RT274_LOUT_MUX\
	VERB_CMD(AC_VERB_SET_CONNECT_SEL, RT274_LINE3, 0)
#define RT274_HPO_MUX\
	VERB_CMD(AC_VERB_SET_CONNECT_SEL, RT274_HP_OUT, 0)
#define RT274_ADC0_MUX\
	VERB_CMD(AC_VERB_SET_CONNECT_SEL, RT274_MIXER_IN1, 0)
#define RT274_ADC1_MUX\
	VERB_CMD(AC_VERB_SET_CONNECT_SEL, RT274_MIXER_IN2, 0)
#define RT274_SET_MIC\
	VERB_CMD(AC_VERB_SET_PIN_WIDGET_CONTROL, RT274_MIC, 0)
#define RT274_SET_PIN_LOUT3\
	VERB_CMD(AC_VERB_SET_PIN_WIDGET_CONTROL, RT274_LINE3, 0)
#define RT274_SET_PIN_HPO\
	VERB_CMD(AC_VERB_SET_PIN_WIDGET_CONTROL, RT274_HP_OUT, 0)
#define RT274_SET_PIN_DMIC1\
	VERB_CMD(AC_VERB_SET_PIN_WIDGET_CONTROL, RT274_DMIC1, 0)
#define RT274_SET_PIN_SPDIF\
	VERB_CMD(AC_VERB_SET_PIN_WIDGET_CONTROL, RT274_SPDIF, 0)
#define RT274_SET_PIN_DIG_CVT\
	VERB_CMD(AC_VERB_SET_DIGI_CONVERT_1, RT274_DIG_CVT, 0)
#define RT274_SET_AMP_GAIN_HPO\
	VERB_CMD(AC_VERB_SET_AMP_GAIN_MUTE, RT274_HP_OUT, 0)
#define RT274_SET_AMP_GAIN_ADC_IN1\
	VERB_CMD(AC_VERB_SET_AMP_GAIN_MUTE, RT274_ADC_IN1, 0)
#define RT274_SET_AMP_GAIN_ADC_IN2\
	VERB_CMD(AC_VERB_SET_AMP_GAIN_MUTE, RT274_ADC_IN2, 0)
#define RT274_GET_HP_SENSE\
	VERB_CMD(AC_VERB_GET_PIN_SENSE, RT274_HP_OUT, 0)
#define RT274_GET_MIC_SENSE\
	VERB_CMD(AC_VERB_GET_PIN_SENSE, RT274_MIC, 0)
#define RT274_SET_DMIC2_DEFAULT\
	VERB_CMD(AC_VERB_SET_CONFIG_DEFAULT_BYTES_3, RT274_DMIC2, 0)
#define RT274_SET_SPDIF_DEFAULT\
	VERB_CMD(AC_VERB_SET_CONFIG_DEFAULT_BYTES_3, RT274_SPDIF, 0)
#define RT274_DAC0L_GAIN\
	VERB_CMD(AC_VERB_SET_AMP_GAIN_MUTE, RT274_DAC_OUT0, 0xa000)
#define RT274_DAC0R_GAIN\
	VERB_CMD(AC_VERB_SET_AMP_GAIN_MUTE, RT274_DAC_OUT0, 0x9000)
#define RT274_DAC1L_GAIN\
	VERB_CMD(AC_VERB_SET_AMP_GAIN_MUTE, RT274_DAC_OUT1, 0xa000)
#define RT274_DAC1R_GAIN\
	VERB_CMD(AC_VERB_SET_AMP_GAIN_MUTE, RT274_DAC_OUT1, 0x9000)
#define RT274_ADCL_GAIN\
	VERB_CMD(AC_VERB_SET_AMP_GAIN_MUTE, RT274_ADC_IN1, 0x6000)
#define RT274_ADCR_GAIN\
	VERB_CMD(AC_VERB_SET_AMP_GAIN_MUTE, RT274_ADC_IN1, 0x5000)
#define RT274_MIC_GAIN\
	VERB_CMD(AC_VERB_SET_AMP_GAIN_MUTE, RT274_MIC, 0x7000)
#define RT274_LOUTL_GAIN\
	VERB_CMD(AC_VERB_SET_AMP_GAIN_MUTE, RT274_LINE3, 0xa000)
#define RT274_LOUTR_GAIN\
	VERB_CMD(AC_VERB_SET_AMP_GAIN_MUTE, RT274_LINE3, 0x9000)
#define RT274_HPOL_GAIN\
	VERB_CMD(AC_VERB_SET_AMP_GAIN_MUTE, RT274_HP_OUT, 0xa000)
#define RT274_HPOR_GAIN\
	VERB_CMD(AC_VERB_SET_AMP_GAIN_MUTE, RT274_HP_OUT, 0x9000)
#define RT274_DAC_FORMAT\
	VERB_CMD(AC_VERB_SET_STREAM_FORMAT, RT274_DAC_OUT0, 0)
#define RT274_ADC_FORMAT\
	VERB_CMD(AC_VERB_SET_STREAM_FORMAT, RT274_ADC_IN1, 0)
#define RT274_COEF_INDEX\
	VERB_CMD(AC_VERB_SET_COEF_INDEX, RT274_VENDOR_REGISTERS, 0)
#define RT274_PROC_COEF\
	VERB_CMD(AC_VERB_SET_PROC_COEF, RT274_VENDOR_REGISTERS, 0)
#define RT274_UNSOLICITED_INLINE_CMD\
	VERB_CMD(AC_VERB_SET_UNSOLICITED_ENABLE, RT274_INLINE_CMD, 0)
#define RT274_UNSOLICITED_HP_OUT\
	VERB_CMD(AC_VERB_SET_UNSOLICITED_ENABLE, RT274_HP_OUT, 0)
#define RT274_UNSOLICITED_MIC\
	VERB_CMD(AC_VERB_SET_UNSOLICITED_ENABLE, RT274_MIC, 0)
#define RT274_COEF58_INDEX\
	VERB_CMD(AC_VERB_SET_COEF_INDEX, 0x58, 0)
#define RT274_COEF58_COEF\
	VERB_CMD(AC_VERB_SET_PROC_COEF, 0x58, 0)
#define RT274_COEF5b_INDEX\
	VERB_CMD(AC_VERB_SET_COEF_INDEX, 0x5b, 0)
#define RT274_COEF5b_COEF\
	VERB_CMD(AC_VERB_SET_PROC_COEF, 0x5b, 0)
#define RT274_SET_STREAMID_DAC0\
	VERB_CMD(AC_VERB_SET_CHANNEL_STREAMID, RT274_DAC_OUT0, 0)
#define RT274_SET_STREAMID_DAC1\
	VERB_CMD(AC_VERB_SET_CHANNEL_STREAMID, RT274_DAC_OUT1, 0)
#define RT274_SET_STREAMID_ADC1\
	VERB_CMD(AC_VERB_SET_CHANNEL_STREAMID, RT274_ADC_IN1, 0)
#define RT274_SET_STREAMID_ADC2\
	VERB_CMD(AC_VERB_SET_CHANNEL_STREAMID, RT274_ADC_IN2, 0)

/* Index registers */
#define RT274_EAPD_GPIO_IRQ_CTRL	0x10
#define RT274_PAD_CTRL12		0x35
#define RT274_I2S_CTRL1			0x63
#define RT274_I2S_CTRL2			0x64
#define RT274_MCLK_CTRL			0x71
#define RT274_CLK_CTRL			0x72
#define RT274_PLL2_CTRL			0x7b


/* EAPD GPIO IRQ control (Index 0x10) */
#define RT274_IRQ_DIS		(0x0 << 13)
#define RT274_IRQ_EN		(0x1 << 13)
#define RT274_IRQ_CLR		(0x1 << 12)
#define RT274_GPI2_SEL_MASK	(0x3 << 7)
#define RT274_GPI2_SEL_GPIO2	(0x0 << 7)
#define RT274_GPI2_SEL_I2S	(0x1 << 7)
#define RT274_GPI2_SEL_DMIC_CLK	(0x2 << 7)
#define RT274_GPI2_SEL_CBJ	(0x3 << 7)

/* Front I2S_Interface control 1 (Index 0x63) */
#define RT274_I2S_MODE_MASK	(0x1 << 11)
#define RT274_I2S_MODE_S	(0x0 << 11)
#define RT274_I2S_MODE_M	(0x1 << 11)
#define RT274_TDM_DIS		(0x0 << 10)
#define RT274_TDM_EN		(0x1 << 10)
#define RT274_TDM_CH_NUM	(0x1 << 7)
#define RT274_TDM_2CH		(0x0 << 7)
#define RT274_TDM_4CH		(0x1 << 7)
#define RT274_I2S_FMT_MASK	(0x3 << 8)
#define RT274_I2S_FMT_I2S	(0x0 << 8)
#define RT274_I2S_FMT_LJ	(0x1 << 8)
#define RT274_I2S_FMT_PCMA	(0x2 << 8)
#define RT274_I2S_FMT_PCMB	(0x3 << 8)

/* MCLK clock domain control (Index 0x71) */
#define RT274_MCLK_MODE_MASK	(0x1 << 14)
#define RT274_MCLK_MODE_DIS	(0x0 << 14)
#define RT274_MCLK_MODE_EN	(0x1 << 14)

/* Clock control (Index 0x72) */
#define RT274_CLK_SRC_MASK	(0x7 << 3)
#define RT274_CLK_SRC_MCLK	(0x0 << 3)
#define RT274_CLK_SRC_PLL2	(0x3 << 3)

/* PLL2 control (Index 0x7b) */
#define RT274_PLL2_SRC_MASK	(0x1 << 13)
#define RT274_PLL2_SRC_MCLK	(0x0 << 13)
#define RT274_PLL2_SRC_BCLK	(0x1 << 13)

/* HP-OUT (0x21) */
#define RT274_M_HP_MUX_SFT	14
#define RT274_HP_SEL_MASK	0x1
#define RT274_HP_SEL_SFT	0
#define RT274_HP_SEL_F		0
#define RT274_HP_SEL_S		1

/* ADC (0x22) (0x23) */
#define RT274_ADC_SEL_MASK	0x7
#define RT274_ADC_SEL_SFT	0
#define RT274_ADC_SEL_MIC	0
#define RT274_ADC_SEL_LINE1	1
#define RT274_ADC_SEL_LINE2	2
#define RT274_ADC_SEL_DMIC	3

#define RT274_SCLK_S_MCLK	0
#define RT274_SCLK_S_PLL1	1
#define RT274_SCLK_S_PLL2	2

#define RT274_PLL2_S_MCLK	0
#define RT274_PLL2_S_BCLK	1

enum {
	RT274_AIF1,
	RT274_AIFS,
};

#endif /* __RT274_H__ */

