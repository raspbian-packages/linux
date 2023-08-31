// SPDX-License-Identifier: GPL-2.0
// TLV320ADCX140 Sound driver
// Copyright (C) 2020 Texas Instruments Incorporated - https://www.ti.com/

#ifndef _TLV320ADCX140_H
#define _TLV320ADCX140_H

#define ADCX140_RATES	(SNDRV_PCM_RATE_44100 | \
			 SNDRV_PCM_RATE_48000 | \
			 SNDRV_PCM_RATE_96000 | \
			 SNDRV_PCM_RATE_192000)

#define ADCX140_FORMATS	(SNDRV_PCM_FMTBIT_S16_LE | \
			 SNDRV_PCM_FMTBIT_S20_3LE | \
			 SNDRV_PCM_FMTBIT_S24_3LE | \
			 SNDRV_PCM_FMTBIT_S24_LE | \
			 SNDRV_PCM_FMTBIT_S32_LE)

#define ADCX140_PAGE_SELECT	0x00
#define ADCX140_SW_RESET	0x01
#define ADCX140_SLEEP_CFG 	0x02
#define ADCX140_SHDN_CFG	0x05
#define ADCX140_ASI_CFG0	0x07
#define ADCX140_ASI_CFG1	0x08
#define ADCX140_ASI_CFG2	0x09
#define ADCX140_ASI_CH1		0x0b
#define ADCX140_ASI_CH2		0x0c
#define ADCX140_ASI_CH3		0x0d
#define ADCX140_ASI_CH4		0x0e
#define ADCX140_ASI_CH5		0x0f
#define ADCX140_ASI_CH6		0x10
#define ADCX140_ASI_CH7		0x11
#define ADCX140_ASI_CH8		0x12
#define ADCX140_MST_CFG0	0x13
#define ADCX140_MST_CFG1	0x14
#define ADCX140_ASI_STS		0x15
#define ADCX140_CLK_SRC		0x16
#define ADCX140_PDMCLK_CFG	0x1f
#define ADCX140_PDM_CFG		0x20
#define ADCX140_GPIO_CFG0	0x21
#define ADCX140_GPO_CFG0	0x22
#define ADCX140_GPO_CFG1	0x23
#define ADCX140_GPO_CFG2	0x24
#define ADCX140_GPO_CFG3	0x25
#define ADCX140_GPO_VAL		0x29
#define ADCX140_GPIO_MON	0x2a
#define ADCX140_GPI_CFG0	0x2b
#define ADCX140_GPI_CFG1	0x2c
#define ADCX140_GPI_MON		0x2f
#define ADCX140_INT_CFG		0x32
#define ADCX140_INT_MASK0	0x33
#define ADCX140_INT_LTCH0	0x36
#define ADCX140_BIAS_CFG	0x3b
#define ADCX140_CH1_CFG0	0x3c
#define ADCX140_CH1_CFG1	0x3d
#define ADCX140_CH1_CFG2	0x3e
#define ADCX140_CH1_CFG3	0x3f
#define ADCX140_CH1_CFG4	0x40
#define ADCX140_CH2_CFG0	0x41
#define ADCX140_CH2_CFG1	0x42
#define ADCX140_CH2_CFG2	0x43
#define ADCX140_CH2_CFG3	0x44
#define ADCX140_CH2_CFG4	0x45
#define ADCX140_CH3_CFG0	0x46
#define ADCX140_CH3_CFG1	0x47
#define ADCX140_CH3_CFG2	0x48
#define ADCX140_CH3_CFG3	0x49
#define ADCX140_CH3_CFG4 	0x4a
#define ADCX140_CH4_CFG0	0x4b
#define ADCX140_CH4_CFG1	0x4c
#define ADCX140_CH4_CFG2	0x4d
#define ADCX140_CH4_CFG3	0x4e
#define ADCX140_CH4_CFG4	0x4f
#define ADCX140_CH5_CFG2	0x52
#define ADCX140_CH5_CFG3	0x53
#define ADCX140_CH5_CFG4	0x54
#define ADCX140_CH6_CFG2	0x57
#define ADCX140_CH6_CFG3	0x58
#define ADCX140_CH6_CFG4	0x59
#define ADCX140_CH7_CFG2	0x5c
#define ADCX140_CH7_CFG3	0x5d
#define ADCX140_CH7_CFG4	0x5e
#define ADCX140_CH8_CFG2	0x61
#define ADCX140_CH8_CFG3	0x62
#define ADCX140_CH8_CFG4	0x63
#define ADCX140_DSP_CFG0	0x6b
#define ADCX140_DSP_CFG1	0x6c
#define ADCX140_DRE_CFG0	0x6d
#define ADCX140_AGC_CFG0	0x70
#define ADCX140_IN_CH_EN	0x73
#define ADCX140_ASI_OUT_CH_EN	0x74
#define ADCX140_PWR_CFG		0x75
#define ADCX140_DEV_STS0	0x76
#define ADCX140_DEV_STS1	0x77
#define ADCX140_PHASE_CALIB		0X7b

#define ADCX140_RESET	BIT(0)

#define ADCX140_WAKE_DEV	BIT(0)
#define ADCX140_AREG_INTERNAL	BIT(7)

#define ADCX140_BCLKINV_BIT	BIT(2)
#define ADCX140_FSYNCINV_BIT	BIT(3)
#define ADCX140_INV_MSK		(ADCX140_BCLKINV_BIT | ADCX140_FSYNCINV_BIT)
#define ADCX140_BCLK_FSYNC_MASTER	BIT(7)
#define ADCX140_I2S_MODE_BIT	BIT(6)
#define ADCX140_LEFT_JUST_BIT	BIT(7)
#define ADCX140_ASI_FORMAT_MSK	(ADCX140_I2S_MODE_BIT | ADCX140_LEFT_JUST_BIT)

#define ADCX140_16_BIT_WORD	0x0
#define ADCX140_20_BIT_WORD	BIT(4)
#define ADCX140_24_BIT_WORD	BIT(5)
#define ADCX140_32_BIT_WORD	(BIT(4) | BIT(5))
#define ADCX140_WORD_LEN_MSK	0x30

#define ADCX140_MAX_CHANNELS	8

#define ADCX140_MIC_BIAS_VAL_VREF	0
#define ADCX140_MIC_BIAS_VAL_VREF_1096	1
#define ADCX140_MIC_BIAS_VAL_AVDD	6
#define ADCX140_MIC_BIAS_VAL_MSK GENMASK(6, 4)
#define ADCX140_MIC_BIAS_SHIFT		4

#define ADCX140_MIC_BIAS_VREF_275V	0
#define ADCX140_MIC_BIAS_VREF_25V	1
#define ADCX140_MIC_BIAS_VREF_1375V	2
#define ADCX140_MIC_BIAS_VREF_MSK GENMASK(1, 0)

#define ADCX140_PWR_CTRL_MSK    GENMASK(7, 5)
#define ADCX140_PWR_CFG_BIAS_PDZ	BIT(7)
#define ADCX140_PWR_CFG_ADC_PDZ		BIT(6)
#define ADCX140_PWR_CFG_PLL_PDZ		BIT(5)

#define ADCX140_TX_OFFSET_MASK		GENMASK(4, 0)

#define ADCX140_NUM_PDM_EDGES		4
#define ADCX140_PDM_EDGE_SHIFT		7

#define ADCX140_NUM_GPI_PINS		4
#define ADCX140_GPI_SHIFT		4
#define ADCX140_GPI1_INDEX		0
#define ADCX140_GPI2_INDEX		1
#define ADCX140_GPI3_INDEX		2
#define ADCX140_GPI4_INDEX		3

#define ADCX140_NUM_GPOS		4
#define ADCX140_NUM_GPO_CFGS		2
#define ADCX140_GPO_SHIFT		4
#define ADCX140_GPO_CFG_MAX		4
#define ADCX140_GPO_DRV_MAX		5

#define ADCX140_TX_FILL    BIT(0)

#define ADCX140_NUM_GPIO_CFGS		2
#define ADCX140_GPIO_SHIFT		4
#define ADCX140_GPIO_CFG_MAX		15
#define ADCX140_GPIO_DRV_MAX		5

#endif /* _TLV320ADCX140_ */
