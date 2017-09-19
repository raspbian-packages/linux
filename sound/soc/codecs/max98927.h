/*
 * max98927.h  --  MAX98927 ALSA Soc Audio driver
 *
 * Copyright 2013-15 Maxim Integrated Products
 * Author: Ryan Lee <ryans.lee@maximintegrated.com>
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 *
 */
#ifndef _MAX98927_H
#define _MAX98927_H

/* Register Values */
#define MAX98927_R0001_INT_RAW1 0x0001
#define MAX98927_R0002_INT_RAW2 0x0002
#define MAX98927_R0003_INT_RAW3 0x0003
#define MAX98927_R0004_INT_STATE1 0x0004
#define MAX98927_R0005_INT_STATE2 0x0005
#define MAX98927_R0006_INT_STATE3 0x0006
#define MAX98927_R0007_INT_FLAG1 0x0007
#define MAX98927_R0008_INT_FLAG2 0x0008
#define MAX98927_R0009_INT_FLAG3 0x0009
#define MAX98927_R000A_INT_EN1 0x000A
#define MAX98927_R000B_INT_EN2 0x000B
#define MAX98927_R000C_INT_EN3 0x000C
#define MAX98927_R000D_INT_FLAG_CLR1	0x000D
#define MAX98927_R000E_INT_FLAG_CLR2	0x000E
#define MAX98927_R000F_INT_FLAG_CLR3	0x000F
#define MAX98927_R0010_IRQ_CTRL 0x0010
#define MAX98927_R0011_CLK_MON 0x0011
#define MAX98927_R0012_WDOG_CTRL 0x0012
#define MAX98927_R0013_WDOG_RST 0x0013
#define MAX98927_R0014_MEAS_ADC_THERM_WARN_THRESH 0x0014
#define MAX98927_R0015_MEAS_ADC_THERM_SHDN_THRESH 0x0015
#define MAX98927_R0016_MEAS_ADC_THERM_HYSTERESIS 0x0016
#define MAX98927_R0017_PIN_CFG 0x0017
#define MAX98927_R0018_PCM_RX_EN_A 0x0018
#define MAX98927_R0019_PCM_RX_EN_B 0x0019
#define MAX98927_R001A_PCM_TX_EN_A 0x001A
#define MAX98927_R001B_PCM_TX_EN_B 0x001B
#define MAX98927_R001C_PCM_TX_HIZ_CTRL_A 0x001C
#define MAX98927_R001D_PCM_TX_HIZ_CTRL_B 0x001D
#define MAX98927_R001E_PCM_TX_CH_SRC_A 0x001E
#define MAX98927_R001F_PCM_TX_CH_SRC_B 0x001F
#define MAX98927_R0020_PCM_MODE_CFG 0x0020
#define MAX98927_R0021_PCM_MASTER_MODE 0x0021
#define MAX98927_R0022_PCM_CLK_SETUP 0x0022
#define MAX98927_R0023_PCM_SR_SETUP1 0x0023
#define MAX98927_R0024_PCM_SR_SETUP2	0x0024
#define MAX98927_R0025_PCM_TO_SPK_MONOMIX_A 0x0025
#define MAX98927_R0026_PCM_TO_SPK_MONOMIX_B 0x0026
#define MAX98927_R0027_ICC_RX_EN_A 0x0027
#define MAX98927_R0028_ICC_RX_EN_B 0x0028
#define MAX98927_R002B_ICC_TX_EN_A 0x002B
#define MAX98927_R002C_ICC_TX_EN_B 0x002C
#define MAX98927_R002E_ICC_HIZ_MANUAL_MODE 0x002E
#define MAX98927_R002F_ICC_TX_HIZ_EN_A 0x002F
#define MAX98927_R0030_ICC_TX_HIZ_EN_B 0x0030
#define MAX98927_R0031_ICC_LNK_EN 0x0031
#define MAX98927_R0032_PDM_TX_EN 0x0032
#define MAX98927_R0033_PDM_TX_HIZ_CTRL 0x0033
#define MAX98927_R0034_PDM_TX_CTRL 0x0034
#define MAX98927_R0035_PDM_RX_CTRL 0x0035
#define MAX98927_R0036_AMP_VOL_CTRL 0x0036
#define MAX98927_R0037_AMP_DSP_CFG 0x0037
#define MAX98927_R0038_TONE_GEN_DC_CFG 0x0038
#define MAX98927_R0039_DRE_CTRL 0x0039
#define MAX98927_R003A_AMP_EN 0x003A
#define MAX98927_R003B_SPK_SRC_SEL 0x003B
#define MAX98927_R003C_SPK_GAIN 0x003C
#define MAX98927_R003D_SSM_CFG 0x003D
#define MAX98927_R003E_MEAS_EN 0x003E
#define MAX98927_R003F_MEAS_DSP_CFG 0x003F
#define MAX98927_R0040_BOOST_CTRL0 0x0040
#define MAX98927_R0041_BOOST_CTRL3 0x0041
#define MAX98927_R0042_BOOST_CTRL1 0x0042
#define MAX98927_R0043_MEAS_ADC_CFG 0x0043
#define MAX98927_R0044_MEAS_ADC_BASE_MSB 0x0044
#define MAX98927_R0045_MEAS_ADC_BASE_LSB 0x0045
#define MAX98927_R0046_ADC_CH0_DIVIDE 0x0046
#define MAX98927_R0047_ADC_CH1_DIVIDE 0x0047
#define MAX98927_R0048_ADC_CH2_DIVIDE 0x0048
#define MAX98927_R0049_ADC_CH0_FILT_CFG 0x0049
#define MAX98927_R004A_ADC_CH1_FILT_CFG 0x004A
#define MAX98927_R004B_ADC_CH2_FILT_CFG 0x004B
#define MAX98927_R004C_MEAS_ADC_CH0_READ 0x004C
#define MAX98927_R004D_MEAS_ADC_CH1_READ 0x004D
#define MAX98927_R004E_MEAS_ADC_CH2_READ 0x004E
#define MAX98927_R0051_BROWNOUT_STATUS 0x0051
#define MAX98927_R0052_BROWNOUT_EN 0x0052
#define MAX98927_R0053_BROWNOUT_INFINITE_HOLD 0x0053
#define MAX98927_R0054_BROWNOUT_INFINITE_HOLD_CLR 0x0054
#define MAX98927_R0055_BROWNOUT_LVL_HOLD 0x0055
#define MAX98927_R005A_BROWNOUT_LVL1_THRESH 0x005A
#define MAX98927_R005B_BROWNOUT_LVL2_THRESH 0x005B
#define MAX98927_R005C_BROWNOUT_LVL3_THRESH 0x005C
#define MAX98927_R005D_BROWNOUT_LVL4_THRESH 0x005D
#define MAX98927_R005E_BROWNOUT_THRESH_HYSTERYSIS 0x005E
#define MAX98927_R005F_BROWNOUT_AMP_LIMITER_ATK_REL 0x005F
#define MAX98927_R0060_BROWNOUT_AMP_GAIN_ATK_REL 0x0060
#define MAX98927_R0061_BROWNOUT_AMP1_CLIP_MODE 0x0061
#define MAX98927_R0072_BROWNOUT_LVL1_CUR_LIMIT 0x0072
#define MAX98927_R0073_BROWNOUT_LVL1_AMP1_CTRL1 0x0073
#define MAX98927_R0074_BROWNOUT_LVL1_AMP1_CTRL2 0x0074
#define MAX98927_R0075_BROWNOUT_LVL1_AMP1_CTRL3 0x0075
#define MAX98927_R0076_BROWNOUT_LVL2_CUR_LIMIT 0x0076
#define MAX98927_R0077_BROWNOUT_LVL2_AMP1_CTRL1 0x0077
#define MAX98927_R0078_BROWNOUT_LVL2_AMP1_CTRL2 0x0078
#define MAX98927_R0079_BROWNOUT_LVL2_AMP1_CTRL3 0x0079
#define MAX98927_R007A_BROWNOUT_LVL3_CUR_LIMIT 0x007A
#define MAX98927_R007B_BROWNOUT_LVL3_AMP1_CTRL1 0x007B
#define MAX98927_R007C_BROWNOUT_LVL3_AMP1_CTRL2 0x007C
#define MAX98927_R007D_BROWNOUT_LVL3_AMP1_CTRL3 0x007D
#define MAX98927_R007E_BROWNOUT_LVL4_CUR_LIMIT 0x007E
#define MAX98927_R007F_BROWNOUT_LVL4_AMP1_CTRL1 0x007F
#define MAX98927_R0080_BROWNOUT_LVL4_AMP1_CTRL2 0x0080
#define MAX98927_R0081_BROWNOUT_LVL4_AMP1_CTRL3 0x0081
#define MAX98927_R0082_ENV_TRACK_VOUT_HEADROOM 0x0082
#define MAX98927_R0083_ENV_TRACK_BOOST_VOUT_DELAY 0x0083
#define MAX98927_R0084_ENV_TRACK_REL_RATE 0x0084
#define MAX98927_R0085_ENV_TRACK_HOLD_RATE 0x0085
#define MAX98927_R0086_ENV_TRACK_CTRL 0x0086
#define MAX98927_R0087_ENV_TRACK_BOOST_VOUT_READ 0x0087
#define MAX98927_R00FF_GLOBAL_SHDN 0x00FF
#define MAX98927_R0100_SOFT_RESET 0x0100
#define MAX98927_R01FF_REV_ID 0x01FF

/* MAX98927_R0018_PCM_RX_EN_A */
#define MAX98927_PCM_RX_CH0_EN (0x1 << 0)
#define MAX98927_PCM_RX_CH1_EN (0x1 << 1)
#define MAX98927_PCM_RX_CH2_EN (0x1 << 2)
#define MAX98927_PCM_RX_CH3_EN (0x1 << 3)
#define MAX98927_PCM_RX_CH4_EN (0x1 << 4)
#define MAX98927_PCM_RX_CH5_EN (0x1 << 5)
#define MAX98927_PCM_RX_CH6_EN (0x1 << 6)
#define MAX98927_PCM_RX_CH7_EN (0x1 << 7)

/* MAX98927_R001A_PCM_TX_EN_A */
#define MAX98927_PCM_TX_CH0_EN (0x1 << 0)
#define MAX98927_PCM_TX_CH1_EN (0x1 << 1)
#define MAX98927_PCM_TX_CH2_EN (0x1 << 2)
#define MAX98927_PCM_TX_CH3_EN (0x1 << 3)
#define MAX98927_PCM_TX_CH4_EN (0x1 << 4)
#define MAX98927_PCM_TX_CH5_EN (0x1 << 5)
#define MAX98927_PCM_TX_CH6_EN (0x1 << 6)
#define MAX98927_PCM_TX_CH7_EN (0x1 << 7)

/* MAX98927_R001E_PCM_TX_CH_SRC_A */
#define MAX98927_PCM_TX_CH_SRC_A_V_SHIFT (0)
#define MAX98927_PCM_TX_CH_SRC_A_I_SHIFT (4)

/* MAX98927_R001F_PCM_TX_CH_SRC_B */
#define MAX98927_PCM_TX_CH_INTERLEAVE_MASK (0x1 << 5)

/* MAX98927_R0020_PCM_MODE_CFG */
#define MAX98927_PCM_MODE_CFG_PCM_BCLKEDGE (0x1 << 2)
#define MAX98927_PCM_MODE_CFG_FORMAT_MASK (0x7 << 3)
#define MAX98927_PCM_MODE_CFG_FORMAT_SHIFT (3)
#define MAX98927_PCM_FORMAT_I2S (0x0 << 0)
#define MAX98927_PCM_FORMAT_LJ (0x1 << 0)

#define MAX98927_PCM_MODE_CFG_CHANSZ_MASK (0x3 << 6)
#define MAX98927_PCM_MODE_CFG_CHANSZ_16 (0x1 << 6)
#define MAX98927_PCM_MODE_CFG_CHANSZ_24 (0x2 << 6)
#define MAX98927_PCM_MODE_CFG_CHANSZ_32 (0x3 << 6)

/* MAX98927_R0021_PCM_MASTER_MODE */
#define MAX98927_PCM_MASTER_MODE_MASK (0x3 << 0)
#define MAX98927_PCM_MASTER_MODE_SLAVE (0x0 << 0)
#define MAX98927_PCM_MASTER_MODE_MASTER (0x3 << 0)

#define MAX98927_PCM_MASTER_MODE_MCLK_MASK (0xF << 2)
#define MAX98927_PCM_MASTER_MODE_MCLK_RATE_SHIFT (2)

/* MAX98927_R0022_PCM_CLK_SETUP */
#define MAX98927_PCM_CLK_SETUP_BSEL_MASK (0xF << 0)

/* MAX98927_R0023_PCM_SR_SETUP1 */
#define MAX98927_PCM_SR_SET1_SR_MASK (0xF << 0)

#define MAX98927_PCM_SR_SET1_SR_8000 (0x0 << 0)
#define MAX98927_PCM_SR_SET1_SR_11025 (0x1 << 0)
#define MAX98927_PCM_SR_SET1_SR_12000 (0x2 << 0)
#define MAX98927_PCM_SR_SET1_SR_16000 (0x3 << 0)
#define MAX98927_PCM_SR_SET1_SR_22050 (0x4 << 0)
#define MAX98927_PCM_SR_SET1_SR_24000 (0x5 << 0)
#define MAX98927_PCM_SR_SET1_SR_32000 (0x6 << 0)
#define MAX98927_PCM_SR_SET1_SR_44100 (0x7 << 0)
#define MAX98927_PCM_SR_SET1_SR_48000 (0x8 << 0)

/* MAX98927_R0024_PCM_SR_SETUP2 */
#define MAX98927_PCM_SR_SET2_SR_MASK (0xF << 4)
#define MAX98927_PCM_SR_SET2_SR_SHIFT (4)
#define MAX98927_PCM_SR_SET2_IVADC_SR_MASK (0xf << 0)

/* MAX98927_R0025_PCM_TO_SPK_MONOMIX_A */
#define MAX98927_PCM_TO_SPK_MONOMIX_CFG_MASK (0x3 << 6)
#define MAX98927_PCM_TO_SPK_MONOMIX_CFG_SHIFT (6)

/* MAX98927_R0035_PDM_RX_CTRL */
#define MAX98927_PDM_RX_EN_MASK (0x1 << 0)

/* MAX98927_R0036_AMP_VOL_CTRL */
#define MAX98927_AMP_VOL_SEL (0x1 << 7)
#define MAX98927_AMP_VOL_SEL_WIDTH (1)
#define MAX98927_AMP_VOL_SEL_SHIFT (7)
#define MAX98927_AMP_VOL_MASK (0x7f << 0)
#define MAX98927_AMP_VOL_WIDTH (7)
#define MAX98927_AMP_VOL_SHIFT (0)

/* MAX98927_R0037_AMP_DSP_CFG */
#define MAX98927_AMP_DSP_CFG_DCBLK_EN (0x1 << 0)
#define MAX98927_AMP_DSP_CFG_DITH_EN (0x1 << 1)
#define MAX98927_AMP_DSP_CFG_RMP_BYPASS (0x1 << 4)
#define MAX98927_AMP_DSP_CFG_DAC_INV (0x1 << 5)
#define MAX98927_AMP_DSP_CFG_RMP_SHIFT (4)

/* MAX98927_R0039_DRE_CTRL */
#define MAX98927_DRE_CTRL_DRE_EN	(0x1 << 0)
#define MAX98927_DRE_EN_SHIFT 0x1

/* MAX98927_R003A_AMP_EN */
#define MAX98927_AMP_EN_MASK (0x1 << 0)

/* MAX98927_R003B_SPK_SRC_SEL */
#define MAX98927_SPK_SRC_MASK (0x3 << 0)

/* MAX98927_R003C_SPK_GAIN */
#define MAX98927_SPK_PCM_GAIN_MASK (0x7 << 0)
#define MAX98927_SPK_PDM_GAIN_MASK (0x7 << 4)
#define MAX98927_SPK_GAIN_WIDTH (3)

/* MAX98927_R003E_MEAS_EN */
#define MAX98927_MEAS_V_EN (0x1 << 0)
#define MAX98927_MEAS_I_EN (0x1 << 1)

/* MAX98927_R0040_BOOST_CTRL0 */
#define MAX98927_BOOST_CTRL0_VOUT_MASK (0x1f << 0)
#define MAX98927_BOOST_CTRL0_PVDD_MASK (0x1 << 7)
#define MAX98927_BOOST_CTRL0_PVDD_EN_SHIFT (7)

/* MAX98927_R0052_BROWNOUT_EN */
#define MAX98927_BROWNOUT_BDE_EN (0x1 << 0)
#define MAX98927_BROWNOUT_AMP_EN (0x1 << 1)
#define MAX98927_BROWNOUT_DSP_EN (0x1 << 2)
#define MAX98927_BROWNOUT_DSP_SHIFT (2)

/* MAX98927_R0100_SOFT_RESET */
#define MAX98927_SOFT_RESET (0x1 << 0)

/* MAX98927_R00FF_GLOBAL_SHDN */
#define MAX98927_GLOBAL_EN_MASK (0x1 << 0)

struct max98927_priv {
	struct regmap *regmap;
	struct snd_soc_codec *codec;
	struct max98927_pdata *pdata;
	unsigned int spk_gain;
	unsigned int sysclk;
	unsigned int v_l_slot;
	unsigned int i_l_slot;
	bool interleave_mode;
	unsigned int ch_size;
	unsigned int rate;
	unsigned int iface;
	unsigned int master;
	unsigned int digital_gain;
};
#endif
