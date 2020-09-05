/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * cs42l52.h -- CS42L52 ALSA SoC audio driver
 *
 * Copyright 2012 CirrusLogic, Inc.
 *
 * Author: Georgi Vlaev <joe@nucleusys.com>
 * Author: Brian Austin <brian.austin@cirrus.com>
 */

#ifndef __CS42L52_H__
#define __CS42L52_H__

#define CS42L52_NAME				"CS42L52"
#define CS42L52_DEFAULT_CLK			12000000
#define CS42L52_MIN_CLK				11000000
#define CS42L52_MAX_CLK				27000000
#define CS42L52_DEFAULT_FORMAT			SNDRV_PCM_FMTBIT_S16_LE
#define CS42L52_DEFAULT_MAX_CHANS		2
#define CS42L52_SYSCLK				1

#define CS42L52_CHIP_SWICTH			(1 << 17)
#define CS42L52_ALL_IN_ONE			(1 << 16)
#define CS42L52_CHIP_ONE			0x00
#define CS42L52_CHIP_TWO			0x01
#define CS42L52_CHIP_THR			0x02
#define CS42L52_CHIP_MASK			0x0f

#define CS42L52_FIX_BITS_CTL			0x00
#define CS42L52_CHIP				0x01
#define CS42L52_CHIP_ID				0xE0
#define CS42L52_CHIP_ID_MASK			0xF8
#define CS42L52_CHIP_REV_A0			0x00
#define CS42L52_CHIP_REV_A1			0x01
#define CS42L52_CHIP_REV_B0			0x02
#define CS42L52_CHIP_REV_MASK			0x07

#define CS42L52_PWRCTL1				0x02
#define CS42L52_PWRCTL1_PDN_ALL			0x9F
#define CS42L52_PWRCTL1_PDN_CHRG		0x80
#define CS42L52_PWRCTL1_PDN_PGAB		0x10
#define CS42L52_PWRCTL1_PDN_PGAA		0x08
#define CS42L52_PWRCTL1_PDN_ADCB		0x04
#define CS42L52_PWRCTL1_PDN_ADCA		0x02
#define CS42L52_PWRCTL1_PDN_CODEC		0x01

#define CS42L52_PWRCTL2				0x03
#define CS42L52_PWRCTL2_OVRDB			(1 << 4)
#define CS42L52_PWRCTL2_OVRDA			(1 << 3)
#define	CS42L52_PWRCTL2_PDN_MICB		(1 << 2)
#define CS42L52_PWRCTL2_PDN_MICB_SHIFT		2
#define CS42L52_PWRCTL2_PDN_MICA		(1 << 1)
#define CS42L52_PWRCTL2_PDN_MICA_SHIFT		1
#define CS42L52_PWRCTL2_PDN_MICBIAS		(1 << 0)
#define CS42L52_PWRCTL2_PDN_MICBIAS_SHIFT	0

#define CS42L52_PWRCTL3				0x04
#define CS42L52_PWRCTL3_HPB_PDN_SHIFT		6
#define CS42L52_PWRCTL3_HPB_ON_LOW		0x00
#define CS42L52_PWRCTL3_HPB_ON_HIGH		0x01
#define CS42L52_PWRCTL3_HPB_ALWAYS_ON		0x02
#define CS42L52_PWRCTL3_HPB_ALWAYS_OFF		0x03
#define CS42L52_PWRCTL3_HPA_PDN_SHIFT		4
#define CS42L52_PWRCTL3_HPA_ON_LOW		0x00
#define CS42L52_PWRCTL3_HPA_ON_HIGH		0x01
#define CS42L52_PWRCTL3_HPA_ALWAYS_ON		0x02
#define CS42L52_PWRCTL3_HPA_ALWAYS_OFF		0x03
#define CS42L52_PWRCTL3_SPKB_PDN_SHIFT		2
#define CS42L52_PWRCTL3_SPKB_ON_LOW		0x00
#define CS42L52_PWRCTL3_SPKB_ON_HIGH		0x01
#define CS42L52_PWRCTL3_SPKB_ALWAYS_ON		0x02
#define CS42L52_PWRCTL3_PDN_SPKB		(1 << 2)
#define CS42L52_PWRCTL3_PDN_SPKA		(1 << 0)
#define CS42L52_PWRCTL3_SPKA_PDN_SHIFT		0
#define CS42L52_PWRCTL3_SPKA_ON_LOW		0x00
#define CS42L52_PWRCTL3_SPKA_ON_HIGH		0x01
#define CS42L52_PWRCTL3_SPKA_ALWAYS_ON		0x02

#define CS42L52_DEFAULT_OUTPUT_STATE		0x05
#define CS42L52_PWRCTL3_CONF_MASK		0x03

#define CS42L52_CLK_CTL				0x05
#define CLK_AUTODECT_ENABLE			(1 << 7)
#define CLK_SPEED_SHIFT				5
#define CLK_DS_MODE				0x00
#define CLK_SS_MODE				0x01
#define CLK_HS_MODE				0x02
#define CLK_QS_MODE				0x03
#define CLK_32K_SR_SHIFT			4
#define CLK_32K					0x01
#define CLK_NO_32K				0x00
#define CLK_27M_MCLK_SHIFT			3
#define CLK_27M_MCLK				0x01
#define CLK_NO_27M				0x00
#define CLK_RATIO_SHIFT				1
#define CLK_R_128				0x00
#define CLK_R_125				0x01
#define CLK_R_132				0x02
#define CLK_R_136				0x03

#define CS42L52_IFACE_CTL1			0x06
#define CS42L52_IFACE_CTL1_MASTER		(1 << 7)
#define CS42L52_IFACE_CTL1_SLAVE		(0 << 7)
#define CS42L52_IFACE_CTL1_INV_SCLK		(1 << 6)
#define CS42L52_IFACE_CTL1_ADC_FMT_I2S		(1 << 5)
#define CS42L52_IFACE_CTL1_ADC_FMT_LEFT_J	(0 << 5)
#define CS42L52_IFACE_CTL1_DSP_MODE_EN		(1 << 4)
#define CS42L52_IFACE_CTL1_DAC_FMT_LEFT_J	(0 << 2)
#define CS42L52_IFACE_CTL1_DAC_FMT_I2S		(1 << 2)
#define CS42L52_IFACE_CTL1_DAC_FMT_RIGHT_J	(2 << 2)
#define CS42L52_IFACE_CTL1_WL_32BIT		(0x00)
#define CS42L52_IFACE_CTL1_WL_24BIT		(0x01)
#define CS42L52_IFACE_CTL1_WL_20BIT		(0x02)
#define CS42L52_IFACE_CTL1_WL_16BIT		(0x03)
#define CS42L52_IFACE_CTL1_WL_MASK		0xFFFF

#define CS42L52_IFACE_CTL2			0x07
#define CS42L52_IFACE_CTL2_SC_MC_EQ		(1 << 6)
#define CS42L52_IFACE_CTL2_LOOPBACK		(1 << 5)
#define CS42L52_IFACE_CTL2_S_MODE_OUTPUT_EN	(0 << 4)
#define CS42L52_IFACE_CTL2_S_MODE_OUTPUT_HIZ	(1 << 4)
#define CS42L52_IFACE_CTL2_HP_SW_INV		(1 << 3)
#define CS42L52_IFACE_CTL2_BIAS_LVL		0x07

#define CS42L52_ADC_PGA_A			0x08
#define CS42L52_ADC_PGA_B			0x09
#define CS42L52_ADC_SEL_SHIFT			5
#define CS42L52_ADC_SEL_AIN1			0x00
#define CS42L52_ADC_SEL_AIN2			0x01
#define CS42L52_ADC_SEL_AIN3			0x02
#define CS42L52_ADC_SEL_AIN4			0x03
#define CS42L52_ADC_SEL_PGA			0x04

#define CS42L52_ANALOG_HPF_CTL			0x0A
#define CS42L52_HPF_CTL_ANLGSFTB		(1 << 3)
#define CS42L52_HPF_CTL_ANLGSFTA                (1 << 0)

#define CS42L52_ADC_HPF_FREQ			0x0B
#define CS42L52_ADC_MISC_CTL			0x0C
#define CS42L52_ADC_MISC_CTL_SOURCE_DSP		(1 << 6)

#define CS42L52_PB_CTL1				0x0D
#define CS42L52_PB_CTL1_HP_GAIN_SHIFT		5
#define CS42L52_PB_CTL1_HP_GAIN_03959		0x00
#define CS42L52_PB_CTL1_HP_GAIN_04571		0x01
#define CS42L52_PB_CTL1_HP_GAIN_05111		0x02
#define CS42L52_PB_CTL1_HP_GAIN_06047		0x03
#define CS42L52_PB_CTL1_HP_GAIN_07099		0x04
#define CS42L52_PB_CTL1_HP_GAIN_08399		0x05
#define CS42L52_PB_CTL1_HP_GAIN_10000		0x06
#define CS42L52_PB_CTL1_HP_GAIN_11430		0x07
#define CS42L52_PB_CTL1_INV_PCMB		(1 << 3)
#define CS42L52_PB_CTL1_INV_PCMA		(1 << 2)
#define CS42L52_PB_CTL1_MSTB_MUTE		(1 << 1)
#define CS42L52_PB_CTL1_MSTA_MUTE		(1 << 0)
#define CS42L52_PB_CTL1_MUTE_MASK		0x03
#define CS42L52_PB_CTL1_MUTE			3
#define CS42L52_PB_CTL1_UNMUTE			0

#define CS42L52_MISC_CTL			0x0E
#define CS42L52_MISC_CTL_DEEMPH			(1 << 2)
#define CS42L52_MISC_CTL_DIGSFT			(1 << 1)
#define CS42L52_MISC_CTL_DIGZC			(1 << 0)

#define CS42L52_PB_CTL2				0x0F
#define CS42L52_PB_CTL2_HPB_MUTE		(1 << 7)
#define CS42L52_PB_CTL2_HPA_MUTE		(1 << 6)
#define CS42L52_PB_CTL2_SPKB_MUTE		(1 << 5)
#define CS42L52_PB_CTL2_SPKA_MUTE		(1 << 4)
#define CS42L52_PB_CTL2_SPK_SWAP		(1 << 2)
#define CS42L52_PB_CTL2_SPK_MONO		(1 << 1)
#define CS42L52_PB_CTL2_SPK_MUTE50		(1 << 0)

#define	CS42L52_MICA_CTL			0x10
#define CS42L52_MICB_CTL			0x11
#define	CS42L52_MIC_CTL_MIC_SEL_MASK		0xBF
#define	CS42L52_MIC_CTL_MIC_SEL_SHIFT		6
#define CS42L52_MIC_CTL_TYPE_MASK		0x20
#define CS42L52_MIC_CTL_TYPE_SHIFT		5


#define CS42L52_PGAA_CTL			0x12
#define CS42L52_PGAB_CTL			0x13
#define CS42L52_PGAX_CTL_VOL_12DB		24
#define CS42L52_PGAX_CTL_VOL_6DB		12 /*step size 0.5db*/

#define CS42L52_PASSTHRUA_VOL			0x14
#define CS42L52_PASSTHRUB_VOL			0x15

#define CS42L52_ADCA_VOL			0x16
#define CS42L52_ADCB_VOL			0x17
#define CS42L52_ADCX_VOL_24DB			24 /*step size 1db*/
#define CS42L52_ADCX_VOL_12DB			12
#define CS42L52_ADCX_VOL_6DB			6

#define CS42L52_ADCA_MIXER_VOL			0x18
#define CS42L52_ADCB_MIXER_VOL			0x19
#define CS42L52_ADC_MIXER_VOL_12DB		0x18

#define CS42L52_PCMA_MIXER_VOL			0x1A
#define CS42L52_PCMB_MIXER_VOL			0x1B

#define CS42L52_BEEP_FREQ			0x1C
#define CS42L52_BEEP_VOL			0x1D
#define CS42L52_BEEP_TONE_CTL			0x1E
#define CS42L52_BEEP_RATE_SHIFT			4
#define CS42L52_BEEP_RATE_MASK			0x0F

#define CS42L52_TONE_CTL			0x1F
#define CS42L52_BEEP_EN_MASK			0x3F

#define CS42L52_MASTERA_VOL			0x20
#define CS42L52_MASTERB_VOL			0x21

#define CS42L52_HPA_VOL				0x22
#define CS42L52_HPB_VOL				0x23
#define CS42L52_DEFAULT_HP_VOL			0xF0

#define CS42L52_SPKA_VOL			0x24
#define CS42L52_SPKB_VOL			0x25
#define CS42L52_DEFAULT_SPK_VOL			0xF0

#define CS42L52_ADC_PCM_MIXER			0x26

#define CS42L52_LIMITER_CTL1			0x27
#define CS42L52_LIMITER_CTL2			0x28
#define CS42L52_LIMITER_AT_RATE			0x29

#define CS42L52_ALC_CTL				0x2A
#define CS42L52_ALC_CTL_ALCB_ENABLE_SHIFT	7
#define CS42L52_ALC_CTL_ALCA_ENABLE_SHIFT	6
#define CS42L52_ALC_CTL_FASTEST_ATTACK		0

#define CS42L52_ALC_RATE			0x2B
#define CS42L52_ALC_SLOWEST_RELEASE		0x3F

#define CS42L52_ALC_THRESHOLD			0x2C
#define CS42L52_ALC_MAX_RATE_SHIFT		5
#define CS42L52_ALC_MIN_RATE_SHIFT		2
#define CS42L52_ALC_RATE_0DB			0
#define CS42L52_ALC_RATE_3DB			1
#define CS42L52_ALC_RATE_6DB			2

#define CS42L52_NOISE_GATE_CTL			0x2D
#define CS42L52_NG_ENABLE_SHIFT			6
#define CS42L52_NG_THRESHOLD_SHIFT		2
#define CS42L52_NG_MIN_70DB			2
#define CS42L52_NG_DELAY_SHIFT			0
#define CS42L52_NG_DELAY_100MS			1

#define CS42L52_CLK_STATUS			0x2E
#define CS42L52_BATT_COMPEN			0x2F

#define CS42L52_BATT_LEVEL			0x30
#define CS42L52_SPK_STATUS			0x31
#define CS42L52_SPK_STATUS_PIN_SHIFT		3
#define CS42L52_SPK_STATUS_PIN_HIGH		1

#define CS42L52_TEM_CTL				0x32
#define CS42L52_TEM_CTL_SET			0x80
#define CS42L52_THE_FOLDBACK			0x33
#define CS42L52_CHARGE_PUMP			0x34
#define CS42L52_CHARGE_PUMP_MASK		0xF0
#define CS42L52_CHARGE_PUMP_SHIFT		4
#define CS42L52_FIX_BITS1			0x3E
#define CS42L52_FIX_BITS2			0x47

#define CS42L52_MAX_REGISTER			0x47

#endif
