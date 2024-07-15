// SPDX-License-Identifier: GPL-2.0-only
/*
 * patch_cs8409-tables.c  --  HD audio interface patch for Cirrus Logic CS8409 HDA bridge chip
 *
 * Copyright (C) 2021 Cirrus Logic, Inc. and
 *                    Cirrus Logic International Semiconductor Ltd.
 *
 * Author: Lucas Tanure <tanureal@opensource.cirrus.com>
 */

#include "patch_cs8409.h"

/******************************************************************************
 *                          CS42L42 Specific Data
 *
 ******************************************************************************/

static const DECLARE_TLV_DB_SCALE(cs42l42_dac_db_scale, CS42L42_HP_VOL_REAL_MIN * 100, 100, 1);

static const DECLARE_TLV_DB_SCALE(cs42l42_adc_db_scale, CS42L42_AMIC_VOL_REAL_MIN * 100, 100, 1);

const struct snd_kcontrol_new cs42l42_dac_volume_mixer = {
	.iface = SNDRV_CTL_ELEM_IFACE_MIXER,
	.index = 0,
	.subdevice = (HDA_SUBDEV_AMP_FLAG | HDA_SUBDEV_NID_FLAG),
	.access = (SNDRV_CTL_ELEM_ACCESS_READWRITE | SNDRV_CTL_ELEM_ACCESS_TLV_READ),
	.info = cs42l42_volume_info,
	.get = cs42l42_volume_get,
	.put = cs42l42_volume_put,
	.tlv = { .p = cs42l42_dac_db_scale },
	.private_value = HDA_COMPOSE_AMP_VAL_OFS(CS8409_PIN_ASP1_TRANSMITTER_A, 3, CS8409_CODEC0,
			 HDA_OUTPUT, CS42L42_VOL_DAC) | HDA_AMP_VAL_MIN_MUTE
};

const struct snd_kcontrol_new cs42l42_adc_volume_mixer = {
	.iface = SNDRV_CTL_ELEM_IFACE_MIXER,
	.index = 0,
	.subdevice = (HDA_SUBDEV_AMP_FLAG | HDA_SUBDEV_NID_FLAG),
	.access = (SNDRV_CTL_ELEM_ACCESS_READWRITE | SNDRV_CTL_ELEM_ACCESS_TLV_READ),
	.info = cs42l42_volume_info,
	.get = cs42l42_volume_get,
	.put = cs42l42_volume_put,
	.tlv = { .p = cs42l42_adc_db_scale },
	.private_value = HDA_COMPOSE_AMP_VAL_OFS(CS8409_PIN_ASP1_RECEIVER_A, 1, CS8409_CODEC0,
			 HDA_INPUT, CS42L42_VOL_ADC) | HDA_AMP_VAL_MIN_MUTE
};

const struct hda_pcm_stream cs42l42_48k_pcm_analog_playback = {
	.rates = SNDRV_PCM_RATE_48000, /* fixed rate */
};

const struct hda_pcm_stream cs42l42_48k_pcm_analog_capture = {
	.rates = SNDRV_PCM_RATE_48000, /* fixed rate */
};

/******************************************************************************
 *                   BULLSEYE / WARLOCK / CYBORG Specific Arrays
 *                               CS8409/CS42L42
 ******************************************************************************/

const struct hda_verb cs8409_cs42l42_init_verbs[] = {
	{ CS8409_PIN_AFG, AC_VERB_SET_GPIO_WAKE_MASK, 0x0018 },		/* WAKE from GPIO 3,4 */
	{ CS8409_PIN_VENDOR_WIDGET, AC_VERB_SET_PROC_STATE, 0x0001 },	/* Enable VPW processing */
	{ CS8409_PIN_VENDOR_WIDGET, AC_VERB_SET_COEF_INDEX, 0x0002 },	/* Configure GPIO 6,7 */
	{ CS8409_PIN_VENDOR_WIDGET, AC_VERB_SET_PROC_COEF,  0x0080 },	/* I2C mode */
	{ CS8409_PIN_VENDOR_WIDGET, AC_VERB_SET_COEF_INDEX, 0x005b },	/* Set I2C bus speed */
	{ CS8409_PIN_VENDOR_WIDGET, AC_VERB_SET_PROC_COEF,  0x0200 },	/* 100kHz I2C_STO = 2 */
	{} /* terminator */
};

static const struct hda_pintbl cs8409_cs42l42_pincfgs[] = {
	{ CS8409_PIN_ASP1_TRANSMITTER_A, 0x042120f0 },	/* ASP-1-TX */
	{ CS8409_PIN_ASP1_RECEIVER_A, 0x04a12050 },	/* ASP-1-RX */
	{ CS8409_PIN_ASP2_TRANSMITTER_A, 0x901000f0 },	/* ASP-2-TX */
	{ CS8409_PIN_DMIC1_IN, 0x90a00090 },		/* DMIC-1 */
	{} /* terminator */
};

static const struct hda_pintbl cs8409_cs42l42_pincfgs_no_dmic[] = {
	{ CS8409_PIN_ASP1_TRANSMITTER_A, 0x042120f0 },	/* ASP-1-TX */
	{ CS8409_PIN_ASP1_RECEIVER_A, 0x04a12050 },	/* ASP-1-RX */
	{ CS8409_PIN_ASP2_TRANSMITTER_A, 0x901000f0 },	/* ASP-2-TX */
	{} /* terminator */
};

/* Vendor specific HW configuration for CS42L42 */
static const struct cs8409_i2c_param cs42l42_init_reg_seq[] = {
	{ CS42L42_I2C_TIMEOUT, 0xB0 },
	{ CS42L42_ADC_CTL, 0x00 },
	{ 0x1D02, 0x06 },
	{ CS42L42_ADC_VOLUME, 0x9F },
	{ CS42L42_OSC_SWITCH, 0x01 },
	{ CS42L42_MCLK_CTL, 0x02 },
	{ CS42L42_SRC_CTL, 0x03 },
	{ CS42L42_MCLK_SRC_SEL, 0x00 },
	{ CS42L42_ASP_FRM_CFG, 0x13 },
	{ CS42L42_FSYNC_P_LOWER, 0xFF },
	{ CS42L42_FSYNC_P_UPPER, 0x00 },
	{ CS42L42_ASP_CLK_CFG, 0x20 },
	{ CS42L42_SPDIF_CLK_CFG, 0x0D },
	{ CS42L42_ASP_RX_DAI0_CH1_AP_RES, 0x02 },
	{ CS42L42_ASP_RX_DAI0_CH1_BIT_MSB, 0x00 },
	{ CS42L42_ASP_RX_DAI0_CH1_BIT_LSB, 0x00 },
	{ CS42L42_ASP_RX_DAI0_CH2_AP_RES, 0x02 },
	{ CS42L42_ASP_RX_DAI0_CH2_BIT_MSB, 0x00 },
	{ CS42L42_ASP_RX_DAI0_CH2_BIT_LSB, 0x20 },
	{ CS42L42_ASP_RX_DAI0_CH3_AP_RES, 0x02 },
	{ CS42L42_ASP_RX_DAI0_CH3_BIT_MSB, 0x00 },
	{ CS42L42_ASP_RX_DAI0_CH3_BIT_LSB, 0x80 },
	{ CS42L42_ASP_RX_DAI0_CH4_AP_RES, 0x02 },
	{ CS42L42_ASP_RX_DAI0_CH4_BIT_MSB, 0x00 },
	{ CS42L42_ASP_RX_DAI0_CH4_BIT_LSB, 0xA0 },
	{ CS42L42_ASP_RX_DAI0_EN, 0x0C },
	{ CS42L42_ASP_TX_CH_EN, 0x01 },
	{ CS42L42_ASP_TX_CH_AP_RES, 0x02 },
	{ CS42L42_ASP_TX_CH1_BIT_MSB, 0x00 },
	{ CS42L42_ASP_TX_CH1_BIT_LSB, 0x00 },
	{ CS42L42_ASP_TX_SZ_EN, 0x01 },
	{ CS42L42_PWR_CTL1, 0x0A },
	{ CS42L42_PWR_CTL2, 0x84 },
	{ CS42L42_MIXER_CHA_VOL, 0x3F },
	{ CS42L42_MIXER_CHB_VOL, 0x3F },
	{ CS42L42_MIXER_ADC_VOL, 0x3f },
	{ CS42L42_HP_CTL, 0x03 },
	{ CS42L42_MIC_DET_CTL1, 0xB6 },
	{ CS42L42_TIPSENSE_CTL, 0xC2 },
	{ CS42L42_HS_CLAMP_DISABLE, 0x01 },
	{ CS42L42_HS_SWITCH_CTL, 0xF3 },
	{ CS42L42_PWR_CTL3, 0x20 },
	{ CS42L42_RSENSE_CTL2, 0x00 },
	{ CS42L42_RSENSE_CTL3, 0x00 },
	{ CS42L42_TSENSE_CTL, 0x80 },
	{ CS42L42_HS_BIAS_CTL, 0xC0 },
	{ CS42L42_PWR_CTL1, 0x02 },
	{ CS42L42_ADC_OVFL_INT_MASK, 0xff },
	{ CS42L42_MIXER_INT_MASK, 0xff },
	{ CS42L42_SRC_INT_MASK, 0xff },
	{ CS42L42_ASP_RX_INT_MASK, 0xff },
	{ CS42L42_ASP_TX_INT_MASK, 0xff },
	{ CS42L42_CODEC_INT_MASK, 0xff },
	{ CS42L42_SRCPL_INT_MASK, 0xff },
	{ CS42L42_VPMON_INT_MASK, 0xff },
	{ CS42L42_PLL_LOCK_INT_MASK, 0xff },
	{ CS42L42_TSRS_PLUG_INT_MASK, 0xff },
	{ CS42L42_DET_INT1_MASK, 0xff },
	{ CS42L42_DET_INT2_MASK, 0xff },
};

/* Vendor specific hw configuration for CS8409 */
const struct cs8409_cir_param cs8409_cs42l42_hw_cfg[] = {
	/* +PLL1/2_EN, +I2C_EN */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_DEV_CFG1, 0xb008 },
	/* ASP1/2_EN=0, ASP1_STP=1 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_DEV_CFG2, 0x0002 },
	/* ASP1/2_BUS_IDLE=10, +GPIO_I2C */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_DEV_CFG3, 0x0a80 },
	/* ASP1.A: TX.LAP=0, TX.LSZ=24 bits, TX.LCS=0 */
	{ CS8409_PIN_VENDOR_WIDGET, ASP1_A_TX_CTRL1, 0x0800 },
	/* ASP1.A: TX.RAP=0, TX.RSZ=24 bits, TX.RCS=32 */
	{ CS8409_PIN_VENDOR_WIDGET, ASP1_A_TX_CTRL2, 0x0820 },
	/* ASP2.A: TX.LAP=0, TX.LSZ=24 bits, TX.LCS=0 */
	{ CS8409_PIN_VENDOR_WIDGET, ASP2_A_TX_CTRL1, 0x0800 },
	/* ASP2.A: TX.RAP=1, TX.RSZ=24 bits, TX.RCS=0 */
	{ CS8409_PIN_VENDOR_WIDGET, ASP2_A_TX_CTRL2, 0x2800 },
	/* ASP1.A: RX.LAP=0, RX.LSZ=24 bits, RX.LCS=0 */
	{ CS8409_PIN_VENDOR_WIDGET, ASP1_A_RX_CTRL1, 0x0800 },
	/* ASP1.A: RX.RAP=0, RX.RSZ=24 bits, RX.RCS=0 */
	{ CS8409_PIN_VENDOR_WIDGET, ASP1_A_RX_CTRL2, 0x0800 },
	/* ASP1: LCHI = 00h */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_ASP1_CLK_CTRL1, 0x8000 },
	/* ASP1: MC/SC_SRCSEL=PLL1, LCPR=FFh */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_ASP1_CLK_CTRL2, 0x28ff },
	/* ASP1: MCEN=0, FSD=011, SCPOL_IN/OUT=0, SCDIV=1:4 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_ASP1_CLK_CTRL3, 0x0062 },
	/* ASP2: LCHI=1Fh */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_ASP2_CLK_CTRL1, 0x801f },
	/* ASP2: MC/SC_SRCSEL=PLL1, LCPR=3Fh */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_ASP2_CLK_CTRL2, 0x283f },
	/* ASP2: 5050=1, MCEN=0, FSD=010, SCPOL_IN/OUT=1, SCDIV=1:16 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_ASP2_CLK_CTRL3, 0x805c },
	/* DMIC1_MO=10b, DMIC1/2_SR=1 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_DMIC_CFG, 0x0023 },
	/* ASP1/2_BEEP=0 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_BEEP_CFG, 0x0000 },
	/* ASP1/2_EN=1, ASP1_STP=1 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_DEV_CFG2, 0x0062 },
	/* -PLL2_EN */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_DEV_CFG1, 0x9008 },
	/* TX2.A: pre-scale att.=0 dB */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PRE_SCALE_ATTN2, 0x0000 },
	/* ASP1/2_xxx_EN=1, ASP1/2_MCLK_EN=0, DMIC1_SCL_EN=1 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PAD_CFG_SLW_RATE_CTRL, 0xfc03 },
	/* test mode on */
	{ CS8409_PIN_VENDOR_WIDGET, 0xc0, 0x9999 },
	/* GPIO hysteresis = 30 us */
	{ CS8409_PIN_VENDOR_WIDGET, 0xc5, 0x0000 },
	/* test mode off */
	{ CS8409_PIN_VENDOR_WIDGET, 0xc0, 0x0000 },
	{} /* Terminator */
};

const struct cs8409_cir_param cs8409_cs42l42_bullseye_atn[] = {
	/* EQ_SEL=1, EQ1/2_EN=0 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_CTRL1, 0x4000 },
	/* +EQ_ACC */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W2, 0x4000 },
	/* +EQ2_EN */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_CTRL1, 0x4010 },
	/* EQ_DATA_HI=0x0647 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W1, 0x0647 },
	/* +EQ_WRT, +EQ_ACC, EQ_ADR=0, EQ_DATA_LO=0x67 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W2, 0xc0c7 },
	/* EQ_DATA_HI=0x0647 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W1, 0x0647 },
	/* +EQ_WRT, +EQ_ACC, EQ_ADR=1, EQ_DATA_LO=0x67 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W2, 0xc1c7 },
	/* EQ_DATA_HI=0xf370 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W1, 0xf370 },
	/* +EQ_WRT, +EQ_ACC, EQ_ADR=2, EQ_DATA_LO=0x71 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W2, 0xc271 },
	/* EQ_DATA_HI=0x1ef8 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W1, 0x1ef8 },
	/* +EQ_WRT, +EQ_ACC, EQ_ADR=3, EQ_DATA_LO=0x48 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W2, 0xc348 },
	/* EQ_DATA_HI=0xc110 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W1, 0xc110 },
	/* +EQ_WRT, +EQ_ACC, EQ_ADR=4, EQ_DATA_LO=0x5a */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W2, 0xc45a },
	/* EQ_DATA_HI=0x1f29 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W1, 0x1f29 },
	/* +EQ_WRT, +EQ_ACC, EQ_ADR=5, EQ_DATA_LO=0x74 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W2, 0xc574 },
	/* EQ_DATA_HI=0x1d7a */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W1, 0x1d7a },
	/* +EQ_WRT, +EQ_ACC, EQ_ADR=6, EQ_DATA_LO=0x53 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W2, 0xc653 },
	/* EQ_DATA_HI=0xc38c */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W1, 0xc38c },
	/* +EQ_WRT, +EQ_ACC, EQ_ADR=7, EQ_DATA_LO=0x14 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W2, 0xc714 },
	/* EQ_DATA_HI=0x1ca3 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W1, 0x1ca3 },
	/* +EQ_WRT, +EQ_ACC, EQ_ADR=8, EQ_DATA_LO=0xc7 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W2, 0xc8c7 },
	/* EQ_DATA_HI=0xc38c */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W1, 0xc38c },
	/* +EQ_WRT, +EQ_ACC, EQ_ADR=9, EQ_DATA_LO=0x14 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W2, 0xc914 },
	/* -EQ_ACC, -EQ_WRT */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PFE_COEF_W2, 0x0000 },
	{} /* Terminator */
};

struct sub_codec cs8409_cs42l42_codec = {
	.addr = CS42L42_I2C_ADDR,
	.reset_gpio = CS8409_CS42L42_RESET,
	.irq_mask = CS8409_CS42L42_INT,
	.init_seq = cs42l42_init_reg_seq,
	.init_seq_num = ARRAY_SIZE(cs42l42_init_reg_seq),
	.hp_jack_in = 0,
	.mic_jack_in = 0,
	.paged = 1,
	.suspended = 1,
	.no_type_dect = 0,
};

/******************************************************************************
 *                          Dolphin Specific Arrays
 *                            CS8409/ 2 X CS42L42
 ******************************************************************************/

const struct hda_verb dolphin_init_verbs[] = {
	{ 0x01, AC_VERB_SET_GPIO_WAKE_MASK, DOLPHIN_WAKE }, /* WAKE from GPIO 0,4 */
	{ CS8409_PIN_VENDOR_WIDGET, AC_VERB_SET_PROC_STATE, 0x0001 }, /* Enable VPW processing  */
	{ CS8409_PIN_VENDOR_WIDGET, AC_VERB_SET_COEF_INDEX, 0x0002 }, /* Configure GPIO 6,7 */
	{ CS8409_PIN_VENDOR_WIDGET, AC_VERB_SET_PROC_COEF,  0x0080 }, /* I2C mode */
	{ CS8409_PIN_VENDOR_WIDGET, AC_VERB_SET_COEF_INDEX, 0x005b }, /* Set I2C bus speed */
	{ CS8409_PIN_VENDOR_WIDGET, AC_VERB_SET_PROC_COEF,  0x0200 }, /* 100kHz I2C_STO = 2 */
	{} /* terminator */
};

static const struct hda_pintbl dolphin_pincfgs[] = {
	{ 0x24, 0x022210f0 }, /* ASP-1-TX-A */
	{ 0x25, 0x010240f0 }, /* ASP-1-TX-B */
	{ 0x34, 0x02a21050 }, /* ASP-1-RX */
	{} /* terminator */
};

/* Vendor specific HW configuration for CS42L42 */
static const struct cs8409_i2c_param dolphin_c0_init_reg_seq[] = {
	{ CS42L42_I2C_TIMEOUT, 0xB0 },
	{ CS42L42_ADC_CTL, 0x00 },
	{ 0x1D02, 0x06 },
	{ CS42L42_ADC_VOLUME, 0x9F },
	{ CS42L42_OSC_SWITCH, 0x01 },
	{ CS42L42_MCLK_CTL, 0x02 },
	{ CS42L42_SRC_CTL, 0x03 },
	{ CS42L42_MCLK_SRC_SEL, 0x00 },
	{ CS42L42_ASP_FRM_CFG, 0x13 },
	{ CS42L42_FSYNC_P_LOWER, 0xFF },
	{ CS42L42_FSYNC_P_UPPER, 0x00 },
	{ CS42L42_ASP_CLK_CFG, 0x20 },
	{ CS42L42_SPDIF_CLK_CFG, 0x0D },
	{ CS42L42_ASP_RX_DAI0_CH1_AP_RES, 0x02 },
	{ CS42L42_ASP_RX_DAI0_CH1_BIT_MSB, 0x00 },
	{ CS42L42_ASP_RX_DAI0_CH1_BIT_LSB, 0x00 },
	{ CS42L42_ASP_RX_DAI0_CH2_AP_RES, 0x02 },
	{ CS42L42_ASP_RX_DAI0_CH2_BIT_MSB, 0x00 },
	{ CS42L42_ASP_RX_DAI0_CH2_BIT_LSB, 0x20 },
	{ CS42L42_ASP_RX_DAI0_EN, 0x0C },
	{ CS42L42_ASP_TX_CH_EN, 0x01 },
	{ CS42L42_ASP_TX_CH_AP_RES, 0x02 },
	{ CS42L42_ASP_TX_CH1_BIT_MSB, 0x00 },
	{ CS42L42_ASP_TX_CH1_BIT_LSB, 0x00 },
	{ CS42L42_ASP_TX_SZ_EN, 0x01 },
	{ CS42L42_PWR_CTL1, 0x0A },
	{ CS42L42_PWR_CTL2, 0x84 },
	{ CS42L42_HP_CTL, 0x03 },
	{ CS42L42_MIXER_CHA_VOL, 0x3F },
	{ CS42L42_MIXER_CHB_VOL, 0x3F },
	{ CS42L42_MIXER_ADC_VOL, 0x3f },
	{ CS42L42_MIC_DET_CTL1, 0xB6 },
	{ CS42L42_TIPSENSE_CTL, 0xC2 },
	{ CS42L42_HS_CLAMP_DISABLE, 0x01 },
	{ CS42L42_HS_SWITCH_CTL, 0xF3 },
	{ CS42L42_PWR_CTL3, 0x20 },
	{ CS42L42_RSENSE_CTL2, 0x00 },
	{ CS42L42_RSENSE_CTL3, 0x00 },
	{ CS42L42_TSENSE_CTL, 0x80 },
	{ CS42L42_HS_BIAS_CTL, 0xC0 },
	{ CS42L42_PWR_CTL1, 0x02 },
	{ CS42L42_ADC_OVFL_INT_MASK, 0xff },
	{ CS42L42_MIXER_INT_MASK, 0xff },
	{ CS42L42_SRC_INT_MASK, 0xff },
	{ CS42L42_ASP_RX_INT_MASK, 0xff },
	{ CS42L42_ASP_TX_INT_MASK, 0xff },
	{ CS42L42_CODEC_INT_MASK, 0xff },
	{ CS42L42_SRCPL_INT_MASK, 0xff },
	{ CS42L42_VPMON_INT_MASK, 0xff },
	{ CS42L42_PLL_LOCK_INT_MASK, 0xff },
	{ CS42L42_TSRS_PLUG_INT_MASK, 0xff },
	{ CS42L42_DET_INT1_MASK, 0xff },
	{ CS42L42_DET_INT2_MASK, 0xff }
};

static const struct cs8409_i2c_param dolphin_c1_init_reg_seq[] = {
	{ CS42L42_I2C_TIMEOUT, 0xB0 },
	{ CS42L42_ADC_CTL, 0x00 },
	{ 0x1D02, 0x06 },
	{ CS42L42_ADC_VOLUME, 0x9F },
	{ CS42L42_OSC_SWITCH, 0x01 },
	{ CS42L42_MCLK_CTL, 0x02 },
	{ CS42L42_SRC_CTL, 0x03 },
	{ CS42L42_MCLK_SRC_SEL, 0x00 },
	{ CS42L42_ASP_FRM_CFG, 0x13 },
	{ CS42L42_FSYNC_P_LOWER, 0xFF },
	{ CS42L42_FSYNC_P_UPPER, 0x00 },
	{ CS42L42_ASP_CLK_CFG, 0x20 },
	{ CS42L42_SPDIF_CLK_CFG, 0x0D },
	{ CS42L42_ASP_RX_DAI0_CH1_AP_RES, 0x02 },
	{ CS42L42_ASP_RX_DAI0_CH1_BIT_MSB, 0x00 },
	{ CS42L42_ASP_RX_DAI0_CH1_BIT_LSB, 0x80 },
	{ CS42L42_ASP_RX_DAI0_CH2_AP_RES, 0x02 },
	{ CS42L42_ASP_RX_DAI0_CH2_BIT_MSB, 0x00 },
	{ CS42L42_ASP_RX_DAI0_CH2_BIT_LSB, 0xA0 },
	{ CS42L42_ASP_RX_DAI0_EN, 0x0C },
	{ CS42L42_ASP_TX_CH_EN, 0x00 },
	{ CS42L42_ASP_TX_CH_AP_RES, 0x02 },
	{ CS42L42_ASP_TX_CH1_BIT_MSB, 0x00 },
	{ CS42L42_ASP_TX_CH1_BIT_LSB, 0x00 },
	{ CS42L42_ASP_TX_SZ_EN, 0x00 },
	{ CS42L42_PWR_CTL1, 0x0E },
	{ CS42L42_PWR_CTL2, 0x84 },
	{ CS42L42_HP_CTL, 0x01 },
	{ CS42L42_MIXER_CHA_VOL, 0x3F },
	{ CS42L42_MIXER_CHB_VOL, 0x3F },
	{ CS42L42_MIXER_ADC_VOL, 0x3f },
	{ CS42L42_MIC_DET_CTL1, 0xB6 },
	{ CS42L42_TIPSENSE_CTL, 0xC2 },
	{ CS42L42_HS_CLAMP_DISABLE, 0x01 },
	{ CS42L42_HS_SWITCH_CTL, 0xF3 },
	{ CS42L42_PWR_CTL3, 0x20 },
	{ CS42L42_RSENSE_CTL2, 0x00 },
	{ CS42L42_RSENSE_CTL3, 0x00 },
	{ CS42L42_TSENSE_CTL, 0x80 },
	{ CS42L42_HS_BIAS_CTL, 0xC0 },
	{ CS42L42_PWR_CTL1, 0x06 },
	{ CS42L42_ADC_OVFL_INT_MASK, 0xff },
	{ CS42L42_MIXER_INT_MASK, 0xff },
	{ CS42L42_SRC_INT_MASK, 0xff },
	{ CS42L42_ASP_RX_INT_MASK, 0xff },
	{ CS42L42_ASP_TX_INT_MASK, 0xff },
	{ CS42L42_CODEC_INT_MASK, 0xff },
	{ CS42L42_SRCPL_INT_MASK, 0xff },
	{ CS42L42_VPMON_INT_MASK, 0xff },
	{ CS42L42_PLL_LOCK_INT_MASK, 0xff },
	{ CS42L42_TSRS_PLUG_INT_MASK, 0xff },
	{ CS42L42_DET_INT1_MASK, 0xff },
	{ CS42L42_DET_INT2_MASK, 0xff }
};

/* Vendor specific hw configuration for CS8409 */
const struct cs8409_cir_param dolphin_hw_cfg[] = {
	/* +PLL1/2_EN, +I2C_EN */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_DEV_CFG1, 0xb008 },
	/* ASP1_EN=0, ASP1_STP=1 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_DEV_CFG2, 0x0002 },
	/* ASP1/2_BUS_IDLE=10, +GPIO_I2C */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_DEV_CFG3, 0x0a80 },
	/* ASP1.A: TX.LAP=0, TX.LSZ=24 bits, TX.LCS=0 */
	{ CS8409_PIN_VENDOR_WIDGET, ASP1_A_TX_CTRL1, 0x0800 },
	/* ASP1.A: TX.RAP=0, TX.RSZ=24 bits, TX.RCS=32 */
	{ CS8409_PIN_VENDOR_WIDGET, ASP1_A_TX_CTRL2, 0x0820 },
	/* ASP1.B: TX.LAP=0, TX.LSZ=24 bits, TX.LCS=128 */
	{ CS8409_PIN_VENDOR_WIDGET, ASP1_B_TX_CTRL1, 0x0880 },
	/* ASP1.B: TX.RAP=0, TX.RSZ=24 bits, TX.RCS=160 */
	{ CS8409_PIN_VENDOR_WIDGET, ASP1_B_TX_CTRL2, 0x08a0 },
	/* ASP1.A: RX.LAP=0, RX.LSZ=24 bits, RX.LCS=0 */
	{ CS8409_PIN_VENDOR_WIDGET, ASP1_A_RX_CTRL1, 0x0800 },
	/* ASP1.A: RX.RAP=0, RX.RSZ=24 bits, RX.RCS=0 */
	{ CS8409_PIN_VENDOR_WIDGET, ASP1_A_RX_CTRL2, 0x0800 },
	/* ASP1: LCHI = 00h */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_ASP1_CLK_CTRL1, 0x8000 },
	/* ASP1: MC/SC_SRCSEL=PLL1, LCPR=FFh */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_ASP1_CLK_CTRL2, 0x28ff },
	/* ASP1: MCEN=0, FSD=011, SCPOL_IN/OUT=0, SCDIV=1:4 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_ASP1_CLK_CTRL3, 0x0062 },
	/* ASP1/2_BEEP=0 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_BEEP_CFG, 0x0000 },
	/* ASP1_EN=1, ASP1_STP=1 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_DEV_CFG2, 0x0022 },
	/* -PLL2_EN */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_DEV_CFG1, 0x9008 },
	/* ASP1_xxx_EN=1, ASP1_MCLK_EN=0 */
	{ CS8409_PIN_VENDOR_WIDGET, CS8409_PAD_CFG_SLW_RATE_CTRL, 0x5400 },
	/* test mode on */
	{ CS8409_PIN_VENDOR_WIDGET, 0xc0, 0x9999 },
	/* GPIO hysteresis = 30 us */
	{ CS8409_PIN_VENDOR_WIDGET, 0xc5, 0x0000 },
	/* test mode off */
	{ CS8409_PIN_VENDOR_WIDGET, 0xc0, 0x0000 },
	{} /* Terminator */
};

struct sub_codec dolphin_cs42l42_0 = {
	.addr = DOLPHIN_C0_I2C_ADDR,
	.reset_gpio = DOLPHIN_C0_RESET,
	.irq_mask = DOLPHIN_C0_INT,
	.init_seq = dolphin_c0_init_reg_seq,
	.init_seq_num = ARRAY_SIZE(dolphin_c0_init_reg_seq),
	.hp_jack_in = 0,
	.mic_jack_in = 0,
	.paged = 1,
	.suspended = 1,
	.no_type_dect = 0,
};

struct sub_codec dolphin_cs42l42_1 = {
	.addr = DOLPHIN_C1_I2C_ADDR,
	.reset_gpio = DOLPHIN_C1_RESET,
	.irq_mask = DOLPHIN_C1_INT,
	.init_seq = dolphin_c1_init_reg_seq,
	.init_seq_num = ARRAY_SIZE(dolphin_c1_init_reg_seq),
	.hp_jack_in = 0,
	.mic_jack_in = 0,
	.paged = 1,
	.suspended = 1,
	.no_type_dect = 1,
};

/******************************************************************************
 *                         CS8409 Patch Driver Structs
 *                    Arrays Used for all projects using CS8409
 ******************************************************************************/

const struct snd_pci_quirk cs8409_fixup_tbl[] = {
	SND_PCI_QUIRK(0x1028, 0x0A11, "Bullseye", CS8409_BULLSEYE),
	SND_PCI_QUIRK(0x1028, 0x0A12, "Bullseye", CS8409_BULLSEYE),
	SND_PCI_QUIRK(0x1028, 0x0A23, "Bullseye", CS8409_BULLSEYE),
	SND_PCI_QUIRK(0x1028, 0x0A24, "Bullseye", CS8409_BULLSEYE),
	SND_PCI_QUIRK(0x1028, 0x0A25, "Bullseye", CS8409_BULLSEYE),
	SND_PCI_QUIRK(0x1028, 0x0A29, "Bullseye", CS8409_BULLSEYE),
	SND_PCI_QUIRK(0x1028, 0x0A2A, "Bullseye", CS8409_BULLSEYE),
	SND_PCI_QUIRK(0x1028, 0x0A2B, "Bullseye", CS8409_BULLSEYE),
	SND_PCI_QUIRK(0x1028, 0x0A77, "Cyborg", CS8409_CYBORG),
	SND_PCI_QUIRK(0x1028, 0x0A78, "Cyborg", CS8409_CYBORG),
	SND_PCI_QUIRK(0x1028, 0x0A79, "Cyborg", CS8409_CYBORG),
	SND_PCI_QUIRK(0x1028, 0x0A7A, "Cyborg", CS8409_CYBORG),
	SND_PCI_QUIRK(0x1028, 0x0A7D, "Cyborg", CS8409_CYBORG),
	SND_PCI_QUIRK(0x1028, 0x0A7E, "Cyborg", CS8409_CYBORG),
	SND_PCI_QUIRK(0x1028, 0x0A7F, "Cyborg", CS8409_CYBORG),
	SND_PCI_QUIRK(0x1028, 0x0A80, "Cyborg", CS8409_CYBORG),
	SND_PCI_QUIRK(0x1028, 0x0AB0, "Warlock", CS8409_WARLOCK),
	SND_PCI_QUIRK(0x1028, 0x0AB2, "Warlock", CS8409_WARLOCK),
	SND_PCI_QUIRK(0x1028, 0x0AB1, "Warlock", CS8409_WARLOCK),
	SND_PCI_QUIRK(0x1028, 0x0AB3, "Warlock", CS8409_WARLOCK),
	SND_PCI_QUIRK(0x1028, 0x0AB4, "Warlock", CS8409_WARLOCK),
	SND_PCI_QUIRK(0x1028, 0x0AB5, "Warlock", CS8409_WARLOCK),
	SND_PCI_QUIRK(0x1028, 0x0ACF, "Dolphin", CS8409_DOLPHIN),
	SND_PCI_QUIRK(0x1028, 0x0AD0, "Dolphin", CS8409_DOLPHIN),
	SND_PCI_QUIRK(0x1028, 0x0AD1, "Dolphin", CS8409_DOLPHIN),
	SND_PCI_QUIRK(0x1028, 0x0AD2, "Dolphin", CS8409_DOLPHIN),
	SND_PCI_QUIRK(0x1028, 0x0AD3, "Dolphin", CS8409_DOLPHIN),
	SND_PCI_QUIRK(0x1028, 0x0AD9, "Warlock", CS8409_WARLOCK),
	SND_PCI_QUIRK(0x1028, 0x0ADA, "Warlock", CS8409_WARLOCK),
	SND_PCI_QUIRK(0x1028, 0x0ADB, "Warlock", CS8409_WARLOCK),
	SND_PCI_QUIRK(0x1028, 0x0ADC, "Warlock", CS8409_WARLOCK),
	SND_PCI_QUIRK(0x1028, 0x0ADF, "Cyborg", CS8409_CYBORG),
	SND_PCI_QUIRK(0x1028, 0x0AE0, "Cyborg", CS8409_CYBORG),
	SND_PCI_QUIRK(0x1028, 0x0AE1, "Cyborg", CS8409_CYBORG),
	SND_PCI_QUIRK(0x1028, 0x0AE2, "Cyborg", CS8409_CYBORG),
	SND_PCI_QUIRK(0x1028, 0x0AE9, "Cyborg", CS8409_CYBORG),
	SND_PCI_QUIRK(0x1028, 0x0AEA, "Cyborg", CS8409_CYBORG),
	SND_PCI_QUIRK(0x1028, 0x0AEB, "Cyborg", CS8409_CYBORG),
	SND_PCI_QUIRK(0x1028, 0x0AEC, "Cyborg", CS8409_CYBORG),
	SND_PCI_QUIRK(0x1028, 0x0AED, "Cyborg", CS8409_CYBORG),
	SND_PCI_QUIRK(0x1028, 0x0AEE, "Cyborg", CS8409_CYBORG),
	SND_PCI_QUIRK(0x1028, 0x0AEF, "Cyborg", CS8409_CYBORG),
	SND_PCI_QUIRK(0x1028, 0x0AF0, "Cyborg", CS8409_CYBORG),
	SND_PCI_QUIRK(0x1028, 0x0AF4, "Warlock", CS8409_WARLOCK),
	SND_PCI_QUIRK(0x1028, 0x0AF5, "Warlock", CS8409_WARLOCK),
	SND_PCI_QUIRK(0x1028, 0x0B92, "Warlock MLK", CS8409_WARLOCK_MLK),
	SND_PCI_QUIRK(0x1028, 0x0B93, "Warlock MLK Dual Mic", CS8409_WARLOCK_MLK_DUAL_MIC),
	SND_PCI_QUIRK(0x1028, 0x0B94, "Warlock MLK", CS8409_WARLOCK_MLK),
	SND_PCI_QUIRK(0x1028, 0x0B95, "Warlock MLK Dual Mic", CS8409_WARLOCK_MLK_DUAL_MIC),
	SND_PCI_QUIRK(0x1028, 0x0B96, "Warlock MLK", CS8409_WARLOCK_MLK),
	SND_PCI_QUIRK(0x1028, 0x0B97, "Warlock MLK Dual Mic", CS8409_WARLOCK_MLK_DUAL_MIC),
	SND_PCI_QUIRK(0x1028, 0x0BA5, "Odin", CS8409_ODIN),
	SND_PCI_QUIRK(0x1028, 0x0BA6, "Odin", CS8409_ODIN),
	SND_PCI_QUIRK(0x1028, 0x0BA8, "Odin", CS8409_ODIN),
	SND_PCI_QUIRK(0x1028, 0x0BAA, "Odin", CS8409_ODIN),
	SND_PCI_QUIRK(0x1028, 0x0BAE, "Odin", CS8409_ODIN),
	SND_PCI_QUIRK(0x1028, 0x0BB2, "Warlock MLK", CS8409_WARLOCK_MLK),
	SND_PCI_QUIRK(0x1028, 0x0BB3, "Warlock MLK", CS8409_WARLOCK_MLK),
	SND_PCI_QUIRK(0x1028, 0x0BB4, "Warlock MLK", CS8409_WARLOCK_MLK),
	SND_PCI_QUIRK(0x1028, 0x0BB5, "Warlock N3 15 TGL-U Nuvoton EC", CS8409_WARLOCK),
	SND_PCI_QUIRK(0x1028, 0x0BB6, "Warlock V3 15 TGL-U Nuvoton EC", CS8409_WARLOCK),
	SND_PCI_QUIRK(0x1028, 0x0BB8, "Warlock MLK", CS8409_WARLOCK_MLK),
	SND_PCI_QUIRK(0x1028, 0x0BB9, "Warlock MLK Dual Mic", CS8409_WARLOCK_MLK_DUAL_MIC),
	SND_PCI_QUIRK(0x1028, 0x0BBA, "Warlock MLK", CS8409_WARLOCK_MLK),
	SND_PCI_QUIRK(0x1028, 0x0BBB, "Warlock MLK Dual Mic", CS8409_WARLOCK_MLK_DUAL_MIC),
	SND_PCI_QUIRK(0x1028, 0x0BBC, "Warlock MLK", CS8409_WARLOCK_MLK),
	SND_PCI_QUIRK(0x1028, 0x0BBD, "Warlock MLK Dual Mic", CS8409_WARLOCK_MLK_DUAL_MIC),
	SND_PCI_QUIRK(0x1028, 0x0BD4, "Dolphin", CS8409_DOLPHIN),
	SND_PCI_QUIRK(0x1028, 0x0BD5, "Dolphin", CS8409_DOLPHIN),
	SND_PCI_QUIRK(0x1028, 0x0BD6, "Dolphin", CS8409_DOLPHIN),
	SND_PCI_QUIRK(0x1028, 0x0BD7, "Dolphin", CS8409_DOLPHIN),
	SND_PCI_QUIRK(0x1028, 0x0BD8, "Dolphin", CS8409_DOLPHIN),
	SND_PCI_QUIRK(0x1028, 0x0C43, "Dolphin", CS8409_DOLPHIN),
	SND_PCI_QUIRK(0x1028, 0x0C50, "Dolphin", CS8409_DOLPHIN),
	SND_PCI_QUIRK(0x1028, 0x0C51, "Dolphin", CS8409_DOLPHIN),
	SND_PCI_QUIRK(0x1028, 0x0C52, "Dolphin", CS8409_DOLPHIN),
	{} /* terminator */
};

/* Dell Inspiron models with cs8409/cs42l42 */
const struct hda_model_fixup cs8409_models[] = {
	{ .id = CS8409_BULLSEYE, .name = "bullseye" },
	{ .id = CS8409_WARLOCK, .name = "warlock" },
	{ .id = CS8409_WARLOCK_MLK, .name = "warlock mlk" },
	{ .id = CS8409_WARLOCK_MLK_DUAL_MIC, .name = "warlock mlk dual mic" },
	{ .id = CS8409_CYBORG, .name = "cyborg" },
	{ .id = CS8409_DOLPHIN, .name = "dolphin" },
	{ .id = CS8409_ODIN, .name = "odin" },
	{}
};

const struct hda_fixup cs8409_fixups[] = {
	[CS8409_BULLSEYE] = {
		.type = HDA_FIXUP_PINS,
		.v.pins = cs8409_cs42l42_pincfgs,
		.chained = true,
		.chain_id = CS8409_FIXUPS,
	},
	[CS8409_WARLOCK] = {
		.type = HDA_FIXUP_PINS,
		.v.pins = cs8409_cs42l42_pincfgs,
		.chained = true,
		.chain_id = CS8409_FIXUPS,
	},
	[CS8409_WARLOCK_MLK] = {
		.type = HDA_FIXUP_PINS,
		.v.pins = cs8409_cs42l42_pincfgs,
		.chained = true,
		.chain_id = CS8409_FIXUPS,
	},
	[CS8409_WARLOCK_MLK_DUAL_MIC] = {
		.type = HDA_FIXUP_PINS,
		.v.pins = cs8409_cs42l42_pincfgs,
		.chained = true,
		.chain_id = CS8409_FIXUPS,
	},
	[CS8409_CYBORG] = {
		.type = HDA_FIXUP_PINS,
		.v.pins = cs8409_cs42l42_pincfgs,
		.chained = true,
		.chain_id = CS8409_FIXUPS,
	},
	[CS8409_FIXUPS] = {
		.type = HDA_FIXUP_FUNC,
		.v.func = cs8409_cs42l42_fixups,
	},
	[CS8409_DOLPHIN] = {
		.type = HDA_FIXUP_PINS,
		.v.pins = dolphin_pincfgs,
		.chained = true,
		.chain_id = CS8409_DOLPHIN_FIXUPS,
	},
	[CS8409_DOLPHIN_FIXUPS] = {
		.type = HDA_FIXUP_FUNC,
		.v.func = dolphin_fixups,
	},
	[CS8409_ODIN] = {
		.type = HDA_FIXUP_PINS,
		.v.pins = cs8409_cs42l42_pincfgs_no_dmic,
		.chained = true,
		.chain_id = CS8409_FIXUPS,
	},
};
