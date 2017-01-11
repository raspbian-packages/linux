/*
 * da7219.h - DA7219 ALSA SoC Codec Driver
 *
 * Copyright (c) 2015 Dialog Semiconductor
 *
 * Author: Adam Thomson <Adam.Thomson.Opensource@diasemi.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#ifndef __DA7219_H
#define __DA7219_H

#include <linux/regmap.h>
#include <linux/regulator/consumer.h>
#include <sound/da7219.h>

/*
 * Registers
 */

#define DA7219_MIC_1_GAIN_STATUS	0x6
#define DA7219_MIXIN_L_GAIN_STATUS	0x8
#define DA7219_ADC_L_GAIN_STATUS	0xA
#define DA7219_DAC_L_GAIN_STATUS	0xC
#define DA7219_DAC_R_GAIN_STATUS	0xD
#define DA7219_HP_L_GAIN_STATUS		0xE
#define DA7219_HP_R_GAIN_STATUS		0xF
#define DA7219_MIC_1_SELECT		0x10
#define DA7219_CIF_TIMEOUT_CTRL		0x12
#define DA7219_CIF_CTRL			0x13
#define DA7219_SR_24_48			0x16
#define DA7219_SR			0x17
#define DA7219_CIF_I2C_ADDR_CFG		0x1B
#define DA7219_PLL_CTRL			0x20
#define DA7219_PLL_FRAC_TOP		0x22
#define DA7219_PLL_FRAC_BOT		0x23
#define DA7219_PLL_INTEGER		0x24
#define DA7219_PLL_SRM_STS		0x25
#define DA7219_DIG_ROUTING_DAI		0x2A
#define DA7219_DAI_CLK_MODE		0x2B
#define DA7219_DAI_CTRL			0x2C
#define DA7219_DAI_TDM_CTRL		0x2D
#define DA7219_DIG_ROUTING_DAC		0x2E
#define DA7219_ALC_CTRL1		0x2F
#define DA7219_DAI_OFFSET_LOWER		0x30
#define DA7219_DAI_OFFSET_UPPER		0x31
#define DA7219_REFERENCES		0x32
#define DA7219_MIXIN_L_SELECT		0x33
#define DA7219_MIXIN_L_GAIN		0x34
#define DA7219_ADC_L_GAIN		0x36
#define DA7219_ADC_FILTERS1		0x38
#define DA7219_MIC_1_GAIN		0x39
#define DA7219_SIDETONE_CTRL		0x3A
#define DA7219_SIDETONE_GAIN		0x3B
#define DA7219_DROUTING_ST_OUTFILT_1L	0x3C
#define DA7219_DROUTING_ST_OUTFILT_1R	0x3D
#define DA7219_DAC_FILTERS5		0x40
#define DA7219_DAC_FILTERS2		0x41
#define DA7219_DAC_FILTERS3		0x42
#define DA7219_DAC_FILTERS4		0x43
#define DA7219_DAC_FILTERS1		0x44
#define DA7219_DAC_L_GAIN		0x45
#define DA7219_DAC_R_GAIN		0x46
#define DA7219_CP_CTRL			0x47
#define DA7219_HP_L_GAIN		0x48
#define DA7219_HP_R_GAIN		0x49
#define DA7219_MIXOUT_L_SELECT		0x4B
#define DA7219_MIXOUT_R_SELECT		0x4C
#define DA7219_SYSTEM_MODES_INPUT	0x50
#define DA7219_SYSTEM_MODES_OUTPUT	0x51
#define DA7219_MICBIAS_CTRL		0x62
#define DA7219_MIC_1_CTRL		0x63
#define DA7219_MIXIN_L_CTRL		0x65
#define DA7219_ADC_L_CTRL		0x67
#define DA7219_DAC_L_CTRL		0x69
#define DA7219_DAC_R_CTRL		0x6A
#define DA7219_HP_L_CTRL		0x6B
#define DA7219_HP_R_CTRL		0x6C
#define DA7219_MIXOUT_L_CTRL		0x6E
#define DA7219_MIXOUT_R_CTRL		0x6F
#define DA7219_CHIP_ID1			0x81
#define DA7219_CHIP_ID2			0x82
#define DA7219_CHIP_REVISION		0x83
#define DA7219_IO_CTRL			0x91
#define DA7219_GAIN_RAMP_CTRL		0x92
#define DA7219_PC_COUNT			0x94
#define DA7219_CP_VOL_THRESHOLD1	0x95
#define DA7219_CP_DELAY			0x96
#define DA7219_DIG_CTRL			0x99
#define DA7219_ALC_CTRL2		0x9A
#define DA7219_ALC_CTRL3		0x9B
#define DA7219_ALC_NOISE		0x9C
#define DA7219_ALC_TARGET_MIN		0x9D
#define DA7219_ALC_TARGET_MAX		0x9E
#define DA7219_ALC_GAIN_LIMITS		0x9F
#define DA7219_ALC_ANA_GAIN_LIMITS	0xA0
#define DA7219_ALC_ANTICLIP_CTRL	0xA1
#define DA7219_ALC_ANTICLIP_LEVEL	0xA2
#define DA7219_ALC_OFFSET_AUTO_M_L	0xA3
#define DA7219_ALC_OFFSET_AUTO_U_L	0xA4
#define DA7219_DAC_NG_SETUP_TIME	0xAF
#define DA7219_DAC_NG_OFF_THRESH	0xB0
#define DA7219_DAC_NG_ON_THRESH		0xB1
#define DA7219_DAC_NG_CTRL		0xB2
#define DA7219_TONE_GEN_CFG1		0xB4
#define DA7219_TONE_GEN_CFG2		0xB5
#define DA7219_TONE_GEN_CYCLES		0xB6
#define DA7219_TONE_GEN_FREQ1_L		0xB7
#define DA7219_TONE_GEN_FREQ1_U		0xB8
#define DA7219_TONE_GEN_FREQ2_L		0xB9
#define DA7219_TONE_GEN_FREQ2_U		0xBA
#define DA7219_TONE_GEN_ON_PER		0xBB
#define DA7219_TONE_GEN_OFF_PER		0xBC
#define DA7219_SYSTEM_STATUS		0xE0
#define DA7219_SYSTEM_ACTIVE		0xFD


/*
 * Bit Fields
 */

#define DA7219_SWITCH_EN_MAX		0x1

/* DA7219_MIC_1_GAIN_STATUS = 0x6 */
#define DA7219_MIC_1_AMP_GAIN_STATUS_SHIFT	0
#define DA7219_MIC_1_AMP_GAIN_STATUS_MASK	(0x7 << 0)
#define DA7219_MIC_1_AMP_GAIN_MAX		0x7

/* DA7219_MIXIN_L_GAIN_STATUS = 0x8 */
#define DA7219_MIXIN_L_AMP_GAIN_STATUS_SHIFT	0
#define DA7219_MIXIN_L_AMP_GAIN_STATUS_MASK	(0xF << 0)

/* DA7219_ADC_L_GAIN_STATUS = 0xA */
#define DA7219_ADC_L_DIGITAL_GAIN_STATUS_SHIFT	0
#define DA7219_ADC_L_DIGITAL_GAIN_STATUS_MASK	(0x7F << 0)

/* DA7219_DAC_L_GAIN_STATUS = 0xC */
#define DA7219_DAC_L_DIGITAL_GAIN_STATUS_SHIFT	0
#define DA7219_DAC_L_DIGITAL_GAIN_STATUS_MASK	(0x7F << 0)

/* DA7219_DAC_R_GAIN_STATUS = 0xD */
#define DA7219_DAC_R_DIGITAL_GAIN_STATUS_SHIFT	0
#define DA7219_DAC_R_DIGITAL_GAIN_STATUS_MASK	(0x7F << 0)

/* DA7219_HP_L_GAIN_STATUS = 0xE */
#define DA7219_HP_L_AMP_GAIN_STATUS_SHIFT	0
#define DA7219_HP_L_AMP_GAIN_STATUS_MASK	(0x3F << 0)

/* DA7219_HP_R_GAIN_STATUS = 0xF */
#define DA7219_HP_R_AMP_GAIN_STATUS_SHIFT	0
#define DA7219_HP_R_AMP_GAIN_STATUS_MASK	(0x3F << 0)

/* DA7219_MIC_1_SELECT = 0x10 */
#define DA7219_MIC_1_AMP_IN_SEL_SHIFT	0
#define DA7219_MIC_1_AMP_IN_SEL_MASK	(0x3 << 0)

/* DA7219_CIF_TIMEOUT_CTRL = 0x12 */
#define DA7219_I2C_TIMEOUT_EN_SHIFT	0
#define DA7219_I2C_TIMEOUT_EN_MASK	(0x1 << 0)

/* DA7219_CIF_CTRL = 0x13 */
#define DA7219_CIF_I2C_WRITE_MODE_SHIFT		0
#define DA7219_CIF_I2C_WRITE_MODE_MASK		(0x1 << 0)
#define DA7219_CIF_REG_SOFT_RESET_SHIFT		7
#define DA7219_CIF_REG_SOFT_RESET_MASK		(0x1 << 7)

/* DA7219_SR_24_48 = 0x16 */
#define DA7219_SR_24_48_SHIFT	0
#define DA7219_SR_24_48_MASK	(0x1 << 0)

/* DA7219_SR = 0x17 */
#define DA7219_SR_SHIFT		0
#define DA7219_SR_MASK		(0xF << 0)
#define DA7219_SR_8000		(0x01 << 0)
#define DA7219_SR_11025		(0x02 << 0)
#define DA7219_SR_12000		(0x03 << 0)
#define DA7219_SR_16000		(0x05 << 0)
#define DA7219_SR_22050		(0x06 << 0)
#define DA7219_SR_24000		(0x07 << 0)
#define DA7219_SR_32000		(0x09 << 0)
#define DA7219_SR_44100		(0x0A << 0)
#define DA7219_SR_48000		(0x0B << 0)
#define DA7219_SR_88200		(0x0E << 0)
#define DA7219_SR_96000		(0x0F << 0)

/* DA7219_CIF_I2C_ADDR_CFG = 0x1B */
#define DA7219_CIF_I2C_ADDR_CFG_SHIFT	0
#define DA7219_CIF_I2C_ADDR_CFG_MASK	(0x3 << 0)

/* DA7219_PLL_CTRL = 0x20 */
#define DA7219_PLL_INDIV_SHIFT		2
#define DA7219_PLL_INDIV_MASK		(0x7 << 2)
#define DA7219_PLL_INDIV_2_TO_4_5_MHZ	(0x0 << 2)
#define DA7219_PLL_INDIV_4_5_TO_9_MHZ	(0x1 << 2)
#define DA7219_PLL_INDIV_9_TO_18_MHZ	(0x2 << 2)
#define DA7219_PLL_INDIV_18_TO_36_MHZ	(0x3 << 2)
#define DA7219_PLL_INDIV_36_TO_54_MHZ	(0x4 << 2)
#define DA7219_PLL_MCLK_SQR_EN_SHIFT	5
#define DA7219_PLL_MCLK_SQR_EN_MASK	(0x1 << 5)
#define DA7219_PLL_MODE_SHIFT		6
#define DA7219_PLL_MODE_MASK		(0x3 << 6)
#define DA7219_PLL_MODE_BYPASS		(0x0 << 6)
#define DA7219_PLL_MODE_NORMAL		(0x1 << 6)
#define DA7219_PLL_MODE_SRM		(0x2 << 6)

/* DA7219_PLL_FRAC_TOP = 0x22 */
#define DA7219_PLL_FBDIV_FRAC_TOP_SHIFT	0
#define DA7219_PLL_FBDIV_FRAC_TOP_MASK	(0x1F << 0)

/* DA7219_PLL_FRAC_BOT = 0x23 */
#define DA7219_PLL_FBDIV_FRAC_BOT_SHIFT	0
#define DA7219_PLL_FBDIV_FRAC_BOT_MASK	(0xFF << 0)

/* DA7219_PLL_INTEGER = 0x24 */
#define DA7219_PLL_FBDIV_INTEGER_SHIFT	0
#define DA7219_PLL_FBDIV_INTEGER_MASK	(0x7F << 0)

/* DA7219_PLL_SRM_STS = 0x25 */
#define DA7219_PLL_SRM_STATE_SHIFT	0
#define DA7219_PLL_SRM_STATE_MASK	(0xF << 0)
#define DA7219_PLL_SRM_STATUS_SHIFT	4
#define DA7219_PLL_SRM_STATUS_MASK	(0xF << 4)
#define DA7219_PLL_SRM_STS_MCLK		(0x1 << 4)
#define DA7219_PLL_SRM_STS_SRM_LOCK	(0x1 << 7)

/* DA7219_DIG_ROUTING_DAI = 0x2A */
#define DA7219_DAI_L_SRC_SHIFT	0
#define DA7219_DAI_L_SRC_MASK	(0x3 << 0)
#define DA7219_DAI_R_SRC_SHIFT	4
#define DA7219_DAI_R_SRC_MASK	(0x3 << 4)
#define DA7219_OUT_SRC_MAX	4

/* DA7219_DAI_CLK_MODE = 0x2B */
#define DA7219_DAI_BCLKS_PER_WCLK_SHIFT	0
#define DA7219_DAI_BCLKS_PER_WCLK_MASK	(0x3 << 0)
#define DA7219_DAI_BCLKS_PER_WCLK_32	(0x0 << 0)
#define DA7219_DAI_BCLKS_PER_WCLK_64	(0x1 << 0)
#define DA7219_DAI_BCLKS_PER_WCLK_128	(0x2 << 0)
#define DA7219_DAI_BCLKS_PER_WCLK_256	(0x3 << 0)
#define DA7219_DAI_CLK_POL_SHIFT	2
#define DA7219_DAI_CLK_POL_MASK		(0x1 << 2)
#define DA7219_DAI_CLK_POL_INV		(0x1 << 2)
#define DA7219_DAI_WCLK_POL_SHIFT	3
#define DA7219_DAI_WCLK_POL_MASK	(0x1 << 3)
#define DA7219_DAI_WCLK_POL_INV		(0x1 << 3)
#define DA7219_DAI_WCLK_TRI_STATE_SHIFT	4
#define DA7219_DAI_WCLK_TRI_STATE_MASK	(0x1 << 4)
#define DA7219_DAI_CLK_EN_SHIFT		7
#define DA7219_DAI_CLK_EN_MASK		(0x1 << 7)

/* DA7219_DAI_CTRL = 0x2C */
#define DA7219_DAI_FORMAT_SHIFT		0
#define DA7219_DAI_FORMAT_MASK		(0x3 << 0)
#define DA7219_DAI_FORMAT_I2S		(0x0 << 0)
#define DA7219_DAI_FORMAT_LEFT_J	(0x1 << 0)
#define DA7219_DAI_FORMAT_RIGHT_J	(0x2 << 0)
#define DA7219_DAI_FORMAT_DSP		(0x3 << 0)
#define DA7219_DAI_WORD_LENGTH_SHIFT	2
#define DA7219_DAI_WORD_LENGTH_MASK	(0x3 << 2)
#define DA7219_DAI_WORD_LENGTH_S16_LE	(0x0 << 2)
#define DA7219_DAI_WORD_LENGTH_S20_LE	(0x1 << 2)
#define DA7219_DAI_WORD_LENGTH_S24_LE	(0x2 << 2)
#define DA7219_DAI_WORD_LENGTH_S32_LE	(0x3 << 2)
#define DA7219_DAI_CH_NUM_SHIFT		4
#define DA7219_DAI_CH_NUM_MASK		(0x3 << 4)
#define DA7219_DAI_CH_NUM_MAX		2
#define DA7219_DAI_EN_SHIFT		7
#define DA7219_DAI_EN_MASK		(0x1 << 7)

/* DA7219_DAI_TDM_CTRL = 0x2D */
#define DA7219_DAI_TDM_CH_EN_SHIFT	0
#define DA7219_DAI_TDM_CH_EN_MASK	(0x3 << 0)
#define DA7219_DAI_OE_SHIFT		6
#define DA7219_DAI_OE_MASK		(0x1 << 6)
#define DA7219_DAI_TDM_MODE_EN_SHIFT	7
#define DA7219_DAI_TDM_MODE_EN_MASK	(0x1 << 7)
#define DA7219_DAI_TDM_MAX_SLOTS	2

/* DA7219_DIG_ROUTING_DAC = 0x2E */
#define DA7219_DAC_L_SRC_SHIFT		0
#define DA7219_DAC_L_SRC_MASK		(0x3 << 0)
#define DA7219_DAC_L_SRC_TONEGEN	(0x1 << 0)
#define DA7219_DAC_L_MONO_SHIFT		3
#define DA7219_DAC_L_MONO_MASK		(0x1 << 3)
#define DA7219_DAC_R_SRC_SHIFT		4
#define DA7219_DAC_R_SRC_MASK		(0x3 << 4)
#define DA7219_DAC_R_SRC_TONEGEN	(0x1 << 4)
#define DA7219_DAC_R_MONO_SHIFT		7
#define DA7219_DAC_R_MONO_MASK		(0x1 << 7)

/* DA7219_ALC_CTRL1 = 0x2F */
#define DA7219_ALC_OFFSET_EN_SHIFT	0
#define DA7219_ALC_OFFSET_EN_MASK	(0x1 << 0)
#define DA7219_ALC_SYNC_MODE_SHIFT	1
#define DA7219_ALC_SYNC_MODE_MASK	(0x1 << 1)
#define DA7219_ALC_EN_SHIFT		3
#define DA7219_ALC_EN_MASK		(0x1 << 3)
#define DA7219_ALC_AUTO_CALIB_EN_SHIFT	4
#define DA7219_ALC_AUTO_CALIB_EN_MASK	(0x1 << 4)
#define DA7219_ALC_CALIB_OVERFLOW_SHIFT	5
#define DA7219_ALC_CALIB_OVERFLOW_MASK	(0x1 << 5)

/* DA7219_DAI_OFFSET_LOWER = 0x30 */
#define DA7219_DAI_OFFSET_LOWER_SHIFT	0
#define DA7219_DAI_OFFSET_LOWER_MASK	(0xFF << 0)

/* DA7219_DAI_OFFSET_UPPER = 0x31 */
#define DA7219_DAI_OFFSET_UPPER_SHIFT	0
#define DA7219_DAI_OFFSET_UPPER_MASK	(0x7 << 0)
#define DA7219_DAI_OFFSET_MAX		0x2FF

/* DA7219_REFERENCES = 0x32 */
#define DA7219_BIAS_EN_SHIFT		3
#define DA7219_BIAS_EN_MASK		(0x1 << 3)
#define DA7219_VMID_FAST_CHARGE_SHIFT	4
#define DA7219_VMID_FAST_CHARGE_MASK	(0x1 << 4)

/* DA7219_MIXIN_L_SELECT = 0x33 */
#define DA7219_MIXIN_L_MIX_SELECT_SHIFT	0
#define DA7219_MIXIN_L_MIX_SELECT_MASK	(0x1 << 0)

/* DA7219_MIXIN_L_GAIN = 0x34 */
#define DA7219_MIXIN_L_AMP_GAIN_SHIFT	0
#define DA7219_MIXIN_L_AMP_GAIN_MASK	(0xF << 0)
#define DA7219_MIXIN_L_AMP_GAIN_MAX	0xF

/* DA7219_ADC_L_GAIN = 0x36 */
#define DA7219_ADC_L_DIGITAL_GAIN_SHIFT	0
#define DA7219_ADC_L_DIGITAL_GAIN_MASK	(0x7F << 0)
#define DA7219_ADC_L_DIGITAL_GAIN_MAX	0x7F

/* DA7219_ADC_FILTERS1 = 0x38 */
#define DA7219_ADC_VOICE_HPF_CORNER_SHIFT	0
#define DA7219_ADC_VOICE_HPF_CORNER_MASK	(0x7 << 0)
#define DA7219_VOICE_HPF_CORNER_MAX		8
#define DA7219_ADC_VOICE_EN_SHIFT		3
#define DA7219_ADC_VOICE_EN_MASK		(0x1 << 3)
#define DA7219_ADC_AUDIO_HPF_CORNER_SHIFT	4
#define DA7219_ADC_AUDIO_HPF_CORNER_MASK	(0x3 << 4)
#define DA7219_AUDIO_HPF_CORNER_MAX		4
#define DA7219_ADC_HPF_EN_SHIFT			7
#define DA7219_ADC_HPF_EN_MASK			(0x1 << 7)
#define DA7219_HPF_MODE_SHIFT			0
#define DA7219_HPF_DISABLED			((0x0 << 3) | (0x0 << 7))
#define DA7219_HPF_AUDIO_EN			((0x0 << 3) | (0x1 << 7))
#define DA7219_HPF_VOICE_EN			((0x1 << 3) | (0x1 << 7))
#define DA7219_HPF_MODE_MASK			((0x1 << 3) | (0x1 << 7))
#define DA7219_HPF_MODE_MAX			3

/* DA7219_MIC_1_GAIN = 0x39 */
#define DA7219_MIC_1_AMP_GAIN_SHIFT	0
#define DA7219_MIC_1_AMP_GAIN_MASK	(0x7 << 0)

/* DA7219_SIDETONE_CTRL = 0x3A */
#define DA7219_SIDETONE_MUTE_EN_SHIFT	6
#define DA7219_SIDETONE_MUTE_EN_MASK	(0x1 << 6)
#define DA7219_SIDETONE_EN_SHIFT	7
#define DA7219_SIDETONE_EN_MASK		(0x1 << 7)

/* DA7219_SIDETONE_GAIN = 0x3B */
#define DA7219_SIDETONE_GAIN_SHIFT	0
#define DA7219_SIDETONE_GAIN_MASK	(0xF << 0)
#define DA7219_SIDETONE_GAIN_MAX	0xE

/* DA7219_DROUTING_ST_OUTFILT_1L = 0x3C */
#define DA7219_OUTFILT_ST_1L_SRC_SHIFT		0
#define DA7219_OUTFILT_ST_1L_SRC_MASK		(0x7 << 0)
#define DA7219_DMIX_ST_SRC_OUTFILT1L_SHIFT	0
#define DA7219_DMIX_ST_SRC_OUTFILT1R_SHIFT	1
#define DA7219_DMIX_ST_SRC_SIDETONE_SHIFT	2
#define DA7219_DMIX_ST_SRC_OUTFILT1L		(0x1 << 0)
#define DA7219_DMIX_ST_SRC_OUTFILT1R		(0x1 << 1)

/* DA7219_DROUTING_ST_OUTFILT_1R = 0x3D */
#define DA7219_OUTFILT_ST_1R_SRC_SHIFT	0
#define DA7219_OUTFILT_ST_1R_SRC_MASK	(0x7 << 0)

/* DA7219_DAC_FILTERS5 = 0x40 */
#define DA7219_DAC_SOFTMUTE_RATE_SHIFT	4
#define DA7219_DAC_SOFTMUTE_RATE_MASK	(0x7 << 4)
#define DA7219_DAC_SOFTMUTE_RATE_MAX	7
#define DA7219_DAC_SOFTMUTE_EN_SHIFT	7
#define DA7219_DAC_SOFTMUTE_EN_MASK	(0x1 << 7)

/* DA7219_DAC_FILTERS2 = 0x41 */
#define DA7219_DAC_EQ_BAND1_SHIFT	0
#define DA7219_DAC_EQ_BAND1_MASK	(0xF << 0)
#define DA7219_DAC_EQ_BAND2_SHIFT	4
#define DA7219_DAC_EQ_BAND2_MASK	(0xF << 4)
#define DA7219_DAC_EQ_BAND_MAX		0xF

/* DA7219_DAC_FILTERS3 = 0x42 */
#define DA7219_DAC_EQ_BAND3_SHIFT	0
#define DA7219_DAC_EQ_BAND3_MASK	(0xF << 0)
#define DA7219_DAC_EQ_BAND4_SHIFT	4
#define DA7219_DAC_EQ_BAND4_MASK	(0xF << 4)

/* DA7219_DAC_FILTERS4 = 0x43 */
#define DA7219_DAC_EQ_BAND5_SHIFT	0
#define DA7219_DAC_EQ_BAND5_MASK	(0xF << 0)
#define DA7219_DAC_EQ_EN_SHIFT		7
#define DA7219_DAC_EQ_EN_MASK		(0x1 << 7)

/* DA7219_DAC_FILTERS1 = 0x44 */
#define DA7219_DAC_VOICE_HPF_CORNER_SHIFT	0
#define DA7219_DAC_VOICE_HPF_CORNER_MASK	(0x7 << 0)
#define DA7219_DAC_VOICE_EN_SHIFT		3
#define DA7219_DAC_VOICE_EN_MASK		(0x1 << 3)
#define DA7219_DAC_AUDIO_HPF_CORNER_SHIFT	4
#define DA7219_DAC_AUDIO_HPF_CORNER_MASK	(0x3 << 4)
#define DA7219_DAC_HPF_EN_SHIFT			7
#define DA7219_DAC_HPF_EN_MASK			(0x1 << 7)

/* DA7219_DAC_L_GAIN = 0x45 */
#define DA7219_DAC_L_DIGITAL_GAIN_SHIFT	0
#define DA7219_DAC_L_DIGITAL_GAIN_MASK	(0x7F << 0)
#define DA7219_DAC_DIGITAL_GAIN_MAX	0x7F
#define DA7219_DAC_DIGITAL_GAIN_0DB	(0x6F << 0)

/* DA7219_DAC_R_GAIN = 0x46 */
#define DA7219_DAC_R_DIGITAL_GAIN_SHIFT	0
#define DA7219_DAC_R_DIGITAL_GAIN_MASK	(0x7F << 0)

/* DA7219_CP_CTRL = 0x47 */
#define DA7219_CP_MCHANGE_SHIFT		4
#define DA7219_CP_MCHANGE_MASK		(0x3 << 4)
#define DA7219_CP_MCHANGE_REL_MASK	0x3
#define DA7219_CP_MCHANGE_MAX		3
#define DA7219_CP_MCHANGE_LARGEST_VOL	0x1
#define DA7219_CP_MCHANGE_DAC_VOL	0x2
#define DA7219_CP_MCHANGE_SIG_MAG	0x3
#define DA7219_CP_EN_SHIFT		7
#define DA7219_CP_EN_MASK		(0x1 << 7)

/* DA7219_HP_L_GAIN = 0x48 */
#define DA7219_HP_L_AMP_GAIN_SHIFT	0
#define DA7219_HP_L_AMP_GAIN_MASK	(0x3F << 0)
#define DA7219_HP_AMP_GAIN_MAX		0x3F
#define DA7219_HP_AMP_GAIN_0DB		(0x39 << 0)

/* DA7219_HP_R_GAIN = 0x49 */
#define DA7219_HP_R_AMP_GAIN_SHIFT	0
#define DA7219_HP_R_AMP_GAIN_MASK	(0x3F << 0)

/* DA7219_MIXOUT_L_SELECT = 0x4B */
#define DA7219_MIXOUT_L_MIX_SELECT_SHIFT	0
#define DA7219_MIXOUT_L_MIX_SELECT_MASK		(0x1 << 0)

/* DA7219_MIXOUT_R_SELECT = 0x4C */
#define DA7219_MIXOUT_R_MIX_SELECT_SHIFT	0
#define DA7219_MIXOUT_R_MIX_SELECT_MASK		(0x1 << 0)

/* DA7219_SYSTEM_MODES_INPUT = 0x50 */
#define DA7219_MODE_SUBMIT_SHIFT	0
#define DA7219_MODE_SUBMIT_MASK		(0x1 << 0)
#define DA7219_ADC_MODE_SHIFT		1
#define DA7219_ADC_MODE_MASK		(0x7F << 1)

/* DA7219_SYSTEM_MODES_OUTPUT = 0x51 */
#define DA7219_MODE_SUBMIT_SHIFT	0
#define DA7219_MODE_SUBMIT_MASK		(0x1 << 0)
#define DA7219_DAC_MODE_SHIFT		1
#define DA7219_DAC_MODE_MASK		(0x7F << 1)

/* DA7219_MICBIAS_CTRL = 0x62 */
#define DA7219_MICBIAS1_LEVEL_SHIFT	0
#define DA7219_MICBIAS1_LEVEL_MASK	(0x7 << 0)
#define DA7219_MICBIAS1_EN_SHIFT	3
#define DA7219_MICBIAS1_EN_MASK		(0x1 << 3)

/* DA7219_MIC_1_CTRL = 0x63 */
#define DA7219_MIC_1_AMP_RAMP_EN_SHIFT	5
#define DA7219_MIC_1_AMP_RAMP_EN_MASK	(0x1 << 5)
#define DA7219_MIC_1_AMP_MUTE_EN_SHIFT	6
#define DA7219_MIC_1_AMP_MUTE_EN_MASK	(0x1 << 6)
#define DA7219_MIC_1_AMP_EN_SHIFT	7
#define DA7219_MIC_1_AMP_EN_MASK	(0x1 << 7)

/* DA7219_MIXIN_L_CTRL = 0x65 */
#define DA7219_MIXIN_L_MIX_EN_SHIFT		3
#define DA7219_MIXIN_L_MIX_EN_MASK		(0x1 << 3)
#define DA7219_MIXIN_L_AMP_ZC_EN_SHIFT		4
#define DA7219_MIXIN_L_AMP_ZC_EN_MASK		(0x1 << 4)
#define DA7219_MIXIN_L_AMP_RAMP_EN_SHIFT	5
#define DA7219_MIXIN_L_AMP_RAMP_EN_MASK		(0x1 << 5)
#define DA7219_MIXIN_L_AMP_MUTE_EN_SHIFT	6
#define DA7219_MIXIN_L_AMP_MUTE_EN_MASK		(0x1 << 6)
#define DA7219_MIXIN_L_AMP_EN_SHIFT		7
#define DA7219_MIXIN_L_AMP_EN_MASK		(0x1 << 7)

/* DA7219_ADC_L_CTRL = 0x67 */
#define DA7219_ADC_L_BIAS_SHIFT		0
#define DA7219_ADC_L_BIAS_MASK		(0x3 << 0)
#define DA7219_ADC_L_RAMP_EN_SHIFT	5
#define DA7219_ADC_L_RAMP_EN_MASK	(0x1 << 5)
#define DA7219_ADC_L_MUTE_EN_SHIFT	6
#define DA7219_ADC_L_MUTE_EN_MASK	(0x1 << 6)
#define DA7219_ADC_L_EN_SHIFT		7
#define DA7219_ADC_L_EN_MASK		(0x1 << 7)

/* DA7219_DAC_L_CTRL = 0x69 */
#define DA7219_DAC_L_RAMP_EN_SHIFT	5
#define DA7219_DAC_L_RAMP_EN_MASK	(0x1 << 5)
#define DA7219_DAC_L_MUTE_EN_SHIFT	6
#define DA7219_DAC_L_MUTE_EN_MASK	(0x1 << 6)
#define DA7219_DAC_L_EN_SHIFT		7
#define DA7219_DAC_L_EN_MASK		(0x1 << 7)

/* DA7219_DAC_R_CTRL = 0x6A */
#define DA7219_DAC_R_RAMP_EN_SHIFT	5
#define DA7219_DAC_R_RAMP_EN_MASK	(0x1 << 5)
#define DA7219_DAC_R_MUTE_EN_SHIFT	6
#define DA7219_DAC_R_MUTE_EN_MASK	(0x1 << 6)
#define DA7219_DAC_R_EN_SHIFT		7
#define DA7219_DAC_R_EN_MASK		(0x1 << 7)

/* DA7219_HP_L_CTRL = 0x6B */
#define DA7219_HP_L_AMP_MIN_GAIN_EN_SHIFT	2
#define DA7219_HP_L_AMP_MIN_GAIN_EN_MASK	(0x1 << 2)
#define DA7219_HP_L_AMP_OE_SHIFT		3
#define DA7219_HP_L_AMP_OE_MASK			(0x1 << 3)
#define DA7219_HP_L_AMP_ZC_EN_SHIFT		4
#define DA7219_HP_L_AMP_ZC_EN_MASK		(0x1 << 4)
#define DA7219_HP_L_AMP_RAMP_EN_SHIFT		5
#define DA7219_HP_L_AMP_RAMP_EN_MASK		(0x1 << 5)
#define DA7219_HP_L_AMP_MUTE_EN_SHIFT		6
#define DA7219_HP_L_AMP_MUTE_EN_MASK		(0x1 << 6)
#define DA7219_HP_L_AMP_EN_SHIFT		7
#define DA7219_HP_L_AMP_EN_MASK			(0x1 << 7)

/* DA7219_HP_R_CTRL = 0x6C */
#define DA7219_HP_R_AMP_MIN_GAIN_EN_SHIFT	2
#define DA7219_HP_R_AMP_MIN_GAIN_EN_MASK	(0x1 << 2)
#define DA7219_HP_R_AMP_OE_SHIFT		3
#define DA7219_HP_R_AMP_OE_MASK			(0x1 << 3)
#define DA7219_HP_R_AMP_ZC_EN_SHIFT		4
#define DA7219_HP_R_AMP_ZC_EN_MASK		(0x1 << 4)
#define DA7219_HP_R_AMP_RAMP_EN_SHIFT		5
#define DA7219_HP_R_AMP_RAMP_EN_MASK		(0x1 << 5)
#define DA7219_HP_R_AMP_MUTE_EN_SHIFT		6
#define DA7219_HP_R_AMP_MUTE_EN_MASK		(0x1 << 6)
#define DA7219_HP_R_AMP_EN_SHIFT		7
#define DA7219_HP_R_AMP_EN_MASK			(0x1 << 7)

/* DA7219_MIXOUT_L_CTRL = 0x6E */
#define DA7219_MIXOUT_L_AMP_EN_SHIFT	7
#define DA7219_MIXOUT_L_AMP_EN_MASK	(0x1 << 7)

/* DA7219_MIXOUT_R_CTRL = 0x6F */
#define DA7219_MIXOUT_R_AMP_EN_SHIFT	7
#define DA7219_MIXOUT_R_AMP_EN_MASK	(0x1 << 7)

/* DA7219_CHIP_ID1 = 0x81 */
#define DA7219_CHIP_ID1_SHIFT	0
#define DA7219_CHIP_ID1_MASK	(0xFF << 0)

/* DA7219_CHIP_ID2 = 0x82 */
#define DA7219_CHIP_ID2_SHIFT	0
#define DA7219_CHIP_ID2_MASK	(0xFF << 0)

/* DA7219_CHIP_REVISION = 0x83 */
#define DA7219_CHIP_MINOR_SHIFT	0
#define DA7219_CHIP_MINOR_MASK	(0xF << 0)
#define DA7219_CHIP_MAJOR_SHIFT	4
#define DA7219_CHIP_MAJOR_MASK	(0xF << 4)

/* DA7219_IO_CTRL = 0x91 */
#define DA7219_IO_VOLTAGE_LEVEL_SHIFT		0
#define DA7219_IO_VOLTAGE_LEVEL_MASK		(0x1 << 0)
#define DA7219_IO_VOLTAGE_LEVEL_2_5V_3_6V	0
#define DA7219_IO_VOLTAGE_LEVEL_1_2V_2_8V	1

/* DA7219_GAIN_RAMP_CTRL = 0x92 */
#define DA7219_GAIN_RAMP_RATE_SHIFT	0
#define DA7219_GAIN_RAMP_RATE_MASK	(0x3 << 0)
#define DA7219_GAIN_RAMP_RATE_X8	(0x0 << 0)
#define DA7219_GAIN_RAMP_RATE_NOMINAL	(0x1 << 0)
#define DA7219_GAIN_RAMP_RATE_MAX	4

/* DA7219_PC_COUNT = 0x94 */
#define DA7219_PC_FREERUN_SHIFT		0
#define DA7219_PC_FREERUN_MASK		(0x1 << 0)
#define DA7219_PC_RESYNC_AUTO_SHIFT	1
#define DA7219_PC_RESYNC_AUTO_MASK	(0x1 << 1)

/* DA7219_CP_VOL_THRESHOLD1 = 0x95 */
#define DA7219_CP_THRESH_VDD2_SHIFT	0
#define DA7219_CP_THRESH_VDD2_MASK	(0x3F << 0)
#define DA7219_CP_THRESH_VDD2_MAX	0x3F

/* DA7219_DIG_CTRL = 0x99 */
#define DA7219_DAC_L_INV_SHIFT	3
#define DA7219_DAC_L_INV_MASK	(0x1 << 3)
#define DA7219_DAC_R_INV_SHIFT	7
#define DA7219_DAC_R_INV_MASK	(0x1 << 7)

/* DA7219_ALC_CTRL2 = 0x9A */
#define DA7219_ALC_ATTACK_SHIFT		0
#define DA7219_ALC_ATTACK_MASK		(0xF << 0)
#define DA7219_ALC_ATTACK_MAX		13
#define DA7219_ALC_RELEASE_SHIFT	4
#define DA7219_ALC_RELEASE_MASK		(0xF << 4)
#define DA7219_ALC_RELEASE_MAX		11

/* DA7219_ALC_CTRL3 = 0x9B */
#define DA7219_ALC_HOLD_SHIFT		0
#define DA7219_ALC_HOLD_MASK		(0xF << 0)
#define DA7219_ALC_HOLD_MAX		16
#define DA7219_ALC_INTEG_ATTACK_SHIFT	4
#define DA7219_ALC_INTEG_ATTACK_MASK	(0x3 << 4)
#define DA7219_ALC_INTEG_RELEASE_SHIFT	6
#define DA7219_ALC_INTEG_RELEASE_MASK	(0x3 << 6)
#define DA7219_ALC_INTEG_MAX		4

/* DA7219_ALC_NOISE = 0x9C */
#define DA7219_ALC_NOISE_SHIFT		0
#define DA7219_ALC_NOISE_MASK		(0x3F << 0)
#define DA7219_ALC_THRESHOLD_MAX	0x3F

/* DA7219_ALC_TARGET_MIN = 0x9D */
#define DA7219_ALC_THRESHOLD_MIN_SHIFT	0
#define DA7219_ALC_THRESHOLD_MIN_MASK	(0x3F << 0)

/* DA7219_ALC_TARGET_MAX = 0x9E */
#define DA7219_ALC_THRESHOLD_MAX_SHIFT	0
#define DA7219_ALC_THRESHOLD_MAX_MASK	(0x3F << 0)

/* DA7219_ALC_GAIN_LIMITS = 0x9F */
#define DA7219_ALC_ATTEN_MAX_SHIFT	0
#define DA7219_ALC_ATTEN_MAX_MASK	(0xF << 0)
#define DA7219_ALC_GAIN_MAX_SHIFT	4
#define DA7219_ALC_GAIN_MAX_MASK	(0xF << 4)
#define DA7219_ALC_ATTEN_GAIN_MAX	0xF

/* DA7219_ALC_ANA_GAIN_LIMITS = 0xA0 */
#define DA7219_ALC_ANA_GAIN_MIN_SHIFT	0
#define DA7219_ALC_ANA_GAIN_MIN_MASK	(0x7 << 0)
#define DA7219_ALC_ANA_GAIN_MIN		0x1
#define DA7219_ALC_ANA_GAIN_MAX_SHIFT	4
#define DA7219_ALC_ANA_GAIN_MAX_MASK	(0x7 << 4)
#define DA7219_ALC_ANA_GAIN_MAX		0x7

/* DA7219_ALC_ANTICLIP_CTRL = 0xA1 */
#define DA7219_ALC_ANTICLIP_STEP_SHIFT	0
#define DA7219_ALC_ANTICLIP_STEP_MASK	(0x3 << 0)
#define DA7219_ALC_ANTICLIP_STEP_MAX	4
#define DA7219_ALC_ANTIPCLIP_EN_SHIFT	7
#define DA7219_ALC_ANTIPCLIP_EN_MASK	(0x1 << 7)

/* DA7219_ALC_ANTICLIP_LEVEL = 0xA2 */
#define DA7219_ALC_ANTICLIP_LEVEL_SHIFT	0
#define DA7219_ALC_ANTICLIP_LEVEL_MASK	(0x7F << 0)

/* DA7219_ALC_OFFSET_AUTO_M_L = 0xA3 */
#define DA7219_ALC_OFFSET_AUTO_M_L_SHIFT	0
#define DA7219_ALC_OFFSET_AUTO_M_L_MASK		(0xFF << 0)

/* DA7219_ALC_OFFSET_AUTO_U_L = 0xA4 */
#define DA7219_ALC_OFFSET_AUTO_U_L_SHIFT	0
#define DA7219_ALC_OFFSET_AUTO_U_L_MASK		(0xF << 0)

/* DA7219_DAC_NG_SETUP_TIME = 0xAF */
#define DA7219_DAC_NG_SETUP_TIME_SHIFT	0
#define DA7219_DAC_NG_SETUP_TIME_MASK	(0x3 << 0)
#define DA7219_DAC_NG_SETUP_TIME_MAX	4
#define DA7219_DAC_NG_RAMPUP_RATE_SHIFT	2
#define DA7219_DAC_NG_RAMPUP_RATE_MASK	(0x1 << 2)
#define DA7219_DAC_NG_RAMPDN_RATE_SHIFT	3
#define DA7219_DAC_NG_RAMPDN_RATE_MASK	(0x1 << 3)
#define DA7219_DAC_NG_RAMP_RATE_MAX	2

/* DA7219_DAC_NG_OFF_THRESH = 0xB0 */
#define DA7219_DAC_NG_OFF_THRESHOLD_SHIFT	0
#define DA7219_DAC_NG_OFF_THRESHOLD_MASK	(0x7 << 0)
#define DA7219_DAC_NG_THRESHOLD_MAX		0x7

/* DA7219_DAC_NG_ON_THRESH = 0xB1 */
#define DA7219_DAC_NG_ON_THRESHOLD_SHIFT	0
#define DA7219_DAC_NG_ON_THRESHOLD_MASK		(0x7 << 0)

/* DA7219_DAC_NG_CTRL = 0xB2 */
#define DA7219_DAC_NG_EN_SHIFT	7
#define DA7219_DAC_NG_EN_MASK	(0x1 << 7)

/* DA7219_TONE_GEN_CFG1 = 0xB4 */
#define DA7219_DTMF_REG_SHIFT		0
#define DA7219_DTMF_REG_MASK		(0xF << 0)
#define DA7219_DTMF_REG_MAX		16
#define DA7219_DTMF_EN_SHIFT		4
#define DA7219_DTMF_EN_MASK		(0x1 << 4)
#define DA7219_START_STOPN_SHIFT	7
#define DA7219_START_STOPN_MASK		(0x1 << 7)

/* DA7219_TONE_GEN_CFG2 = 0xB5 */
#define DA7219_SWG_SEL_SHIFT		0
#define DA7219_SWG_SEL_MASK		(0x3 << 0)
#define DA7219_SWG_SEL_MAX		4
#define DA7219_SWG_SEL_SRAMP		(0x3 << 0)
#define DA7219_TONE_GEN_GAIN_SHIFT	4
#define DA7219_TONE_GEN_GAIN_MASK	(0xF << 4)
#define DA7219_TONE_GEN_GAIN_MAX	0xF
#define DA7219_TONE_GEN_GAIN_MINUS_9DB	(0x3 << 4)
#define DA7219_TONE_GEN_GAIN_MINUS_15DB	(0x5 << 4)

/* DA7219_TONE_GEN_CYCLES = 0xB6 */
#define DA7219_BEEP_CYCLES_SHIFT	0
#define DA7219_BEEP_CYCLES_MASK		(0x7 << 0)

/* DA7219_TONE_GEN_FREQ1_L = 0xB7 */
#define DA7219_FREQ1_L_SHIFT	0
#define DA7219_FREQ1_L_MASK	(0xFF << 0)
#define DA7219_FREQ_MAX		0xFFFF

/* DA7219_TONE_GEN_FREQ1_U = 0xB8 */
#define DA7219_FREQ1_U_SHIFT	0
#define DA7219_FREQ1_U_MASK	(0xFF << 0)

/* DA7219_TONE_GEN_FREQ2_L = 0xB9 */
#define DA7219_FREQ2_L_SHIFT	0
#define DA7219_FREQ2_L_MASK	(0xFF << 0)

/* DA7219_TONE_GEN_FREQ2_U = 0xBA */
#define DA7219_FREQ2_U_SHIFT	0
#define DA7219_FREQ2_U_MASK	(0xFF << 0)

/* DA7219_TONE_GEN_ON_PER = 0xBB */
#define DA7219_BEEP_ON_PER_SHIFT	0
#define DA7219_BEEP_ON_PER_MASK		(0x3F << 0)
#define DA7219_BEEP_ON_OFF_MAX		0x3F

/* DA7219_TONE_GEN_OFF_PER = 0xBC */
#define DA7219_BEEP_OFF_PER_SHIFT	0
#define DA7219_BEEP_OFF_PER_MASK	(0x3F << 0)

/* DA7219_SYSTEM_STATUS = 0xE0 */
#define DA7219_SC1_BUSY_SHIFT	0
#define DA7219_SC1_BUSY_MASK	(0x1 << 0)
#define DA7219_SC2_BUSY_SHIFT	1
#define DA7219_SC2_BUSY_MASK	(0x1 << 1)

/* DA7219_SYSTEM_ACTIVE = 0xFD */
#define DA7219_SYSTEM_ACTIVE_SHIFT	0
#define DA7219_SYSTEM_ACTIVE_MASK	(0x1 << 0)


/*
 * General defines & data
 */

/* Register inversion */
#define DA7219_NO_INVERT	0
#define DA7219_INVERT		1

/* Byte related defines */
#define DA7219_BYTE_SHIFT	8
#define DA7219_BYTE_MASK	0xFF

/* PLL Output Frequencies */
#define DA7219_PLL_FREQ_OUT_90316	90316800
#define DA7219_PLL_FREQ_OUT_98304	98304000

/* PLL Frequency Dividers */
#define DA7219_PLL_INDIV_2_TO_4_5_MHZ_VAL	1
#define DA7219_PLL_INDIV_4_5_TO_9_MHZ_VAL	2
#define DA7219_PLL_INDIV_9_TO_18_MHZ_VAL	4
#define DA7219_PLL_INDIV_18_TO_36_MHZ_VAL	8
#define DA7219_PLL_INDIV_36_TO_54_MHZ_VAL	16

/* SRM */
#define DA7219_SRM_CHECK_RETRIES	8

/* System Controller */
#define DA7219_SYS_STAT_CHECK_RETRIES	6
#define DA7219_SYS_STAT_CHECK_DELAY	50

enum da7219_clk_src {
	DA7219_CLKSRC_MCLK = 0,
	DA7219_CLKSRC_MCLK_SQR,
};

enum da7219_sys_clk {
	DA7219_SYSCLK_MCLK = 0,
	DA7219_SYSCLK_PLL,
	DA7219_SYSCLK_PLL_SRM,
};

/* Regulators */
enum da7219_supplies {
	DA7219_SUPPLY_VDD = 0,
	DA7219_SUPPLY_VDDMIC,
	DA7219_SUPPLY_VDDIO,
	DA7219_NUM_SUPPLIES,
};

struct da7219_aad_priv;

/* Private data */
struct da7219_priv {
	struct da7219_aad_priv *aad;
	struct da7219_pdata *pdata;

	bool wakeup_source;
	struct regulator_bulk_data supplies[DA7219_NUM_SUPPLIES];
	struct regmap *regmap;
	struct mutex lock;

	struct clk *mclk;
	unsigned int mclk_rate;
	int clk_src;

	bool master;
	bool alc_en;
};

#endif /* __DA7219_H */
