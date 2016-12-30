/*
 * da732x_reg.h --- Dialog DA732X ALSA SoC Audio Registers Header File
 *
 * Copyright (C) 2012 Dialog Semiconductor GmbH
 *
 * Author: Michal Hajduk <Michal.Hajduk@diasemi.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __DA732X_REG_H_
#define __DA732X_REG_H_

/* DA732X registers */
#define	DA732X_REG_STATUS_EXT		0x00
#define DA732X_REG_STATUS		0x01
#define DA732X_REG_REF1			0x02
#define DA732X_REG_BIAS_EN		0x03
#define DA732X_REG_BIAS1		0x04
#define DA732X_REG_BIAS2		0x05
#define DA732X_REG_BIAS3		0x06
#define DA732X_REG_BIAS4		0x07
#define DA732X_REG_MICBIAS2		0x0F
#define DA732X_REG_MICBIAS1		0x10
#define DA732X_REG_MICDET		0x11
#define DA732X_REG_MIC1_PRE		0x12
#define DA732X_REG_MIC1			0x13
#define DA732X_REG_MIC2_PRE		0x14
#define DA732X_REG_MIC2			0x15
#define DA732X_REG_AUX1L		0x16
#define DA732X_REG_AUX1R		0x17
#define DA732X_REG_MIC3_PRE		0x18
#define DA732X_REG_MIC3			0x19
#define DA732X_REG_INP_PINBIAS		0x1A
#define DA732X_REG_INP_ZC_EN		0x1B
#define DA732X_REG_INP_MUX		0x1D
#define DA732X_REG_HP_DET		0x20
#define DA732X_REG_HPL_DAC_OFFSET	0x21
#define DA732X_REG_HPL_DAC_OFF_CNTL	0x22
#define DA732X_REG_HPL_OUT_OFFSET	0x23
#define DA732X_REG_HPL			0x24
#define DA732X_REG_HPL_VOL		0x25
#define DA732X_REG_HPR_DAC_OFFSET	0x26
#define DA732X_REG_HPR_DAC_OFF_CNTL	0x27
#define DA732X_REG_HPR_OUT_OFFSET	0x28
#define DA732X_REG_HPR			0x29
#define DA732X_REG_HPR_VOL		0x2A
#define DA732X_REG_LIN2			0x2B
#define DA732X_REG_LIN3			0x2C
#define DA732X_REG_LIN4			0x2D
#define DA732X_REG_OUT_ZC_EN		0x2E
#define DA732X_REG_HP_LIN1_GNDSEL	0x37
#define DA732X_REG_CP_HP1		0x3A
#define DA732X_REG_CP_HP2		0x3B
#define DA732X_REG_CP_CTRL1		0x40
#define DA732X_REG_CP_CTRL2		0x41
#define DA732X_REG_CP_CTRL3		0x42
#define DA732X_REG_CP_LEVEL_MASK	0x43
#define DA732X_REG_CP_DET		0x44
#define DA732X_REG_CP_STATUS		0x45
#define DA732X_REG_CP_THRESH1		0x46
#define DA732X_REG_CP_THRESH2		0x47
#define DA732X_REG_CP_THRESH3		0x48
#define DA732X_REG_CP_THRESH4		0x49
#define DA732X_REG_CP_THRESH5		0x4A
#define DA732X_REG_CP_THRESH6		0x4B
#define DA732X_REG_CP_THRESH7		0x4C
#define DA732X_REG_CP_THRESH8		0x4D
#define DA732X_REG_PLL_DIV_LO		0x50
#define DA732X_REG_PLL_DIV_MID		0x51
#define DA732X_REG_PLL_DIV_HI		0x52
#define DA732X_REG_PLL_CTRL		0x53
#define DA732X_REG_CLK_CTRL		0x54
#define DA732X_REG_CLK_DSP		0x5A
#define DA732X_REG_CLK_EN1		0x5B
#define DA732X_REG_CLK_EN2		0x5C
#define DA732X_REG_CLK_EN3		0x5D
#define DA732X_REG_CLK_EN4		0x5E
#define DA732X_REG_CLK_EN5		0x5F
#define DA732X_REG_AIF_MCLK		0x60
#define DA732X_REG_AIFA1		0x61
#define DA732X_REG_AIFA2		0x62
#define DA732X_REG_AIFA3		0x63
#define DA732X_REG_AIFB1		0x64
#define DA732X_REG_AIFB2		0x65
#define DA732X_REG_AIFB3		0x66
#define DA732X_REG_PC_CTRL		0x6A
#define DA732X_REG_DATA_ROUTE		0x70
#define DA732X_REG_DSP_CTRL		0x71
#define DA732X_REG_CIF_CTRL2		0x74
#define DA732X_REG_HANDSHAKE		0x75
#define DA732X_REG_MBOX0		0x76
#define DA732X_REG_MBOX1		0x77
#define DA732X_REG_MBOX2		0x78
#define DA732X_REG_MBOX_STATUS		0x79
#define DA732X_REG_SPARE1_OUT		0x7D
#define DA732X_REG_SPARE2_OUT		0x7E
#define DA732X_REG_SPARE1_IN		0x7F
#define DA732X_REG_ID			0x81
#define DA732X_REG_ADC1_PD		0x90
#define DA732X_REG_ADC1_HPF		0x93
#define DA732X_REG_ADC1_SEL		0x94
#define DA732X_REG_ADC1_EQ12		0x95
#define DA732X_REG_ADC1_EQ34		0x96
#define DA732X_REG_ADC1_EQ5		0x97
#define DA732X_REG_ADC2_PD		0x98
#define DA732X_REG_ADC2_HPF		0x9B
#define DA732X_REG_ADC2_SEL		0x9C
#define DA732X_REG_ADC2_EQ12		0x9D
#define DA732X_REG_ADC2_EQ34		0x9E
#define DA732X_REG_ADC2_EQ5		0x9F
#define DA732X_REG_DAC1_HPF		0xA0
#define DA732X_REG_DAC1_L_VOL		0xA1
#define DA732X_REG_DAC1_R_VOL		0xA2
#define DA732X_REG_DAC1_SEL		0xA3
#define DA732X_REG_DAC1_SOFTMUTE	0xA4
#define DA732X_REG_DAC1_EQ12		0xA5
#define DA732X_REG_DAC1_EQ34		0xA6
#define DA732X_REG_DAC1_EQ5		0xA7
#define DA732X_REG_DAC2_HPF		0xB0
#define DA732X_REG_DAC2_L_VOL		0xB1
#define DA732X_REG_DAC2_R_VOL		0xB2
#define DA732X_REG_DAC2_SEL		0xB3
#define DA732X_REG_DAC2_SOFTMUTE	0xB4
#define DA732X_REG_DAC2_EQ12		0xB5
#define DA732X_REG_DAC2_EQ34		0xB6
#define DA732X_REG_DAC2_EQ5		0xB7
#define DA732X_REG_DAC3_HPF		0xC0
#define DA732X_REG_DAC3_VOL		0xC1
#define DA732X_REG_DAC3_SEL		0xC3
#define DA732X_REG_DAC3_SOFTMUTE	0xC4
#define DA732X_REG_DAC3_EQ12		0xC5
#define DA732X_REG_DAC3_EQ34		0xC6
#define DA732X_REG_DAC3_EQ5		0xC7
#define DA732X_REG_BIQ_BYP		0xD2
#define DA732X_REG_DMA_CMD		0xD3
#define DA732X_REG_DMA_ADDR0		0xD4
#define DA732X_REG_DMA_ADDR1		0xD5
#define DA732X_REG_DMA_DATA0		0xD6
#define DA732X_REG_DMA_DATA1		0xD7
#define DA732X_REG_DMA_DATA2		0xD8
#define DA732X_REG_DMA_DATA3		0xD9
#define DA732X_REG_DMA_STATUS		0xDA
#define DA732X_REG_BROWNOUT		0xDF
#define DA732X_REG_UNLOCK		0xE0

#define	DA732X_MAX_REG			DA732X_REG_UNLOCK
/*
 * Bits
 */

/* DA732X_REG_STATUS_EXT (addr=0x00) */
#define	DA732X_STATUS_EXT_DSP			(1 << 4)
#define	DA732X_STATUS_EXT_CLEAR			(0 << 0)

/* DA732X_REG_STATUS	(addr=0x01) */
#define DA732X_STATUS_PLL_LOCK			(1 << 0)
#define DA732X_STATUS_PLL_MCLK_DET		(1 << 1)
#define DA732X_STATUS_HPDET_OUT			(1 << 2)
#define DA732X_STATUS_INP_MIXDET_1		(1 << 3)
#define DA732X_STATUS_INP_MIXDET_2		(1 << 4)
#define DA732X_STATUS_BO_STATUS			(1 << 5)

/* DA732X_REG_REF1	(addr=0x02) */
#define DA732X_VMID_FASTCHG			(1 << 1)
#define DA732X_VMID_FASTDISCHG			(1 << 2)
#define DA732X_REFBUFX2_EN			(1 << 6)
#define DA732X_REFBUFX2_DIS			(0 << 6)

/* DA732X_REG_BIAS_EN	(addr=0x03) */
#define DA732X_BIAS_BOOST_MASK			(3 << 0)
#define DA732X_BIAS_BOOST_100PC			(0 << 0)
#define DA732X_BIAS_BOOST_133PC			(1 << 0)
#define DA732X_BIAS_BOOST_88PC			(2 << 0)
#define DA732X_BIAS_BOOST_50PC			(3 << 0)
#define DA732X_BIAS_EN				(1 << 7)
#define DA732X_BIAS_DIS				(0 << 7)

/* DA732X_REG_BIAS1	(addr=0x04) */
#define DA732X_BIAS1_HP_DAC_BIAS_MASK		(3 << 0)
#define DA732X_BIAS1_HP_DAC_BIAS_100PC		(0 << 0)
#define DA732X_BIAS1_HP_DAC_BIAS_150PC		(1 << 0)
#define DA732X_BIAS1_HP_DAC_BIAS_50PC		(2 << 0)
#define DA732X_BIAS1_HP_DAC_BIAS_75PC		(3 << 0)
#define DA732X_BIAS1_HP_OUT_BIAS_MASK		(7 << 4)
#define DA732X_BIAS1_HP_OUT_BIAS_100PC		(0 << 4)
#define DA732X_BIAS1_HP_OUT_BIAS_125PC		(1 << 4)
#define DA732X_BIAS1_HP_OUT_BIAS_150PC		(2 << 4)
#define DA732X_BIAS1_HP_OUT_BIAS_175PC		(3 << 4)
#define DA732X_BIAS1_HP_OUT_BIAS_200PC		(4 << 4)
#define DA732X_BIAS1_HP_OUT_BIAS_250PC		(5 << 4)
#define DA732X_BIAS1_HP_OUT_BIAS_300PC		(6 << 4)
#define DA732X_BIAS1_HP_OUT_BIAS_350PC		(7 << 4)

/* DA732X_REG_BIAS2	(addr=0x05) */
#define DA732X_BIAS2_LINE2_DAC_BIAS_MASK	(3 << 0)
#define DA732X_BIAS2_LINE2_DAC_BIAS_100PC	(0 << 0)
#define DA732X_BIAS2_LINE2_DAC_BIAS_150PC	(1 << 0)
#define DA732X_BIAS2_LINE2_DAC_BIAS_50PC	(2 << 0)
#define DA732X_BIAS2_LINE2_DAC_BIAS_75PC	(3 << 0)
#define DA732X_BIAS2_LINE2_OUT_BIAS_MASK	(7 << 4)
#define DA732X_BIAS2_LINE2_OUT_BIAS_100PC	(0 << 4)
#define DA732X_BIAS2_LINE2_OUT_BIAS_125PC	(1 << 4)
#define DA732X_BIAS2_LINE2_OUT_BIAS_150PC	(2 << 4)
#define DA732X_BIAS2_LINE2_OUT_BIAS_175PC	(3 << 4)
#define DA732X_BIAS2_LINE2_OUT_BIAS_200PC	(4 << 4)
#define DA732X_BIAS2_LINE2_OUT_BIAS_250PC	(5 << 4)
#define DA732X_BIAS2_LINE2_OUT_BIAS_300PC	(6 << 4)
#define DA732X_BIAS2_LINE2_OUT_BIAS_350PC	(7 << 4)

/* DA732X_REG_BIAS3	(addr=0x06) */
#define DA732X_BIAS3_LINE3_DAC_BIAS_MASK	(3 << 0)
#define DA732X_BIAS3_LINE3_DAC_BIAS_100PC	(0 << 0)
#define DA732X_BIAS3_LINE3_DAC_BIAS_150PC	(1 << 0)
#define DA732X_BIAS3_LINE3_DAC_BIAS_50PC	(2 << 0)
#define DA732X_BIAS3_LINE3_DAC_BIAS_75PC	(3 << 0)
#define DA732X_BIAS3_LINE3_OUT_BIAS_MASK	(7 << 4)
#define DA732X_BIAS3_LINE3_OUT_BIAS_100PC	(0 << 4)
#define DA732X_BIAS3_LINE3_OUT_BIAS_125PC	(1 << 4)
#define DA732X_BIAS3_LINE3_OUT_BIAS_150PC	(2 << 4)
#define DA732X_BIAS3_LINE3_OUT_BIAS_175PC	(3 << 4)
#define DA732X_BIAS3_LINE3_OUT_BIAS_200PC	(4 << 4)
#define DA732X_BIAS3_LINE3_OUT_BIAS_250PC	(5 << 4)
#define DA732X_BIAS3_LINE3_OUT_BIAS_300PC	(6 << 4)
#define DA732X_BIAS3_LINE3_OUT_BIAS_350PC	(7 << 4)

/* DA732X_REG_BIAS4	(addr=0x07) */
#define DA732X_BIAS4_LINE4_DAC_BIAS_MASK	(3 << 0)
#define DA732X_BIAS4_LINE4_DAC_BIAS_100PC	(0 << 0)
#define DA732X_BIAS4_LINE4_DAC_BIAS_150PC	(1 << 0)
#define DA732X_BIAS4_LINE4_DAC_BIAS_50PC	(2 << 0)
#define DA732X_BIAS4_LINE4_DAC_BIAS_75PC	(3 << 0)
#define DA732X_BIAS4_LINE4_OUT_BIAS_MASK	(7 << 4)
#define DA732X_BIAS4_LINE4_OUT_BIAS_100PC	(0 << 4)
#define DA732X_BIAS4_LINE4_OUT_BIAS_125PC	(1 << 4)
#define DA732X_BIAS4_LINE4_OUT_BIAS_150PC	(2 << 4)
#define DA732X_BIAS4_LINE4_OUT_BIAS_175PC	(3 << 4)
#define DA732X_BIAS4_LINE4_OUT_BIAS_200PC	(4 << 4)
#define DA732X_BIAS4_LINE4_OUT_BIAS_250PC	(5 << 4)
#define DA732X_BIAS4_LINE4_OUT_BIAS_300PC	(6 << 4)
#define DA732X_BIAS4_LINE4_OUT_BIAS_350PC	(7 << 4)

/* DA732X_REG_SIF_VDD_SEL	(addr=0x08) */
#define DA732X_SIF_VDD_SEL_AIFA_VDD2		(1 << 0)
#define DA732X_SIF_VDD_SEL_AIFB_VDD2		(1 << 1)
#define DA732X_SIF_VDD_SEL_CIFA_VDD2		(1 << 4)

/* DA732X_REG_MICBIAS2/1	(addr=0x0F/0x10) */
#define DA732X_MICBIAS_VOLTAGE_MASK		(0x0F << 0)
#define DA732X_MICBIAS_VOLTAGE_2V		(0x00 << 0)
#define DA732X_MICBIAS_VOLTAGE_2V05		(0x01 << 0)
#define DA732X_MICBIAS_VOLTAGE_2V1		(0x02 << 0)
#define DA732X_MICBIAS_VOLTAGE_2V15		(0x03 << 0)
#define DA732X_MICBIAS_VOLTAGE_2V2		(0x04 << 0)
#define DA732X_MICBIAS_VOLTAGE_2V25		(0x05 << 0)
#define DA732X_MICBIAS_VOLTAGE_2V3		(0x06 << 0)
#define DA732X_MICBIAS_VOLTAGE_2V35		(0x07 << 0)
#define DA732X_MICBIAS_VOLTAGE_2V4		(0x08 << 0)
#define DA732X_MICBIAS_VOLTAGE_2V45		(0x09 << 0)
#define DA732X_MICBIAS_VOLTAGE_2V5		(0x0A << 0)
#define DA732X_MICBIAS_EN			(1 << 7)
#define DA732X_MICBIAS_EN_SHIFT			7
#define DA732X_MICBIAS_VOLTAGE_SHIFT		0
#define	DA732X_MICBIAS_VOLTAGE_MAX		0x0B

/* DA732X_REG_MICDET	(addr=0x11) */
#define DA732X_MICDET_INP_MICRES		(1 << 0)
#define DA732X_MICDET_INP_MICHOOK		(1 << 1)
#define DA732X_MICDET_INP_DEBOUNCE_PRD_8MS	(0 << 0)
#define DA732X_MICDET_INP_DEBOUNCE_PRD_16MS	(1 << 0)
#define DA732X_MICDET_INP_DEBOUNCE_PRD_32MS	(2 << 0)
#define DA732X_MICDET_INP_DEBOUNCE_PRD_64MS	(3 << 0)
#define DA732X_MICDET_INP_MICDET_EN		(1 << 7)

/* DA732X_REG_MIC1/2/3_PRE (addr=0x11/0x14/0x18) */
#define	DA732X_MICBOOST_MASK			0x7
#define	DA732X_MICBOOST_SHIFT			0
#define	DA732X_MICBOOST_MIN			0x1
#define	DA732X_MICBOOST_MAX			DA732X_MICBOOST_MASK

/* DA732X_REG_MIC1/2/3	(addr=0x13/0x15/0x19) */
#define	DA732X_MIC_VOL_SHIFT			0
#define	DA732X_MIC_VOL_VAL_MASK			0x1F
#define DA732X_MIC_MUTE_SHIFT			6
#define DA732X_MIC_EN_SHIFT			7
#define DA732X_MIC_VOL_VAL_MIN			0x7
#define	DA732X_MIC_VOL_VAL_MAX			DA732X_MIC_VOL_VAL_MASK

/* DA732X_REG_AUX1L/R	(addr=0x16/0x17) */
#define	DA732X_AUX_VOL_SHIFT			0
#define	DA732X_AUX_VOL_MASK			0x7
#define DA732X_AUX_MUTE_SHIFT			6
#define DA732X_AUX_EN_SHIFT			7
#define	DA732X_AUX_VOL_VAL_MAX			DA732X_AUX_VOL_MASK

/* DA732X_REG_INP_PINBIAS	(addr=0x1A) */
#define DA732X_INP_MICL_PINBIAS_EN		(1 << 0)
#define DA732X_INP_MICR_PINBIAS_EN		(1 << 1)
#define DA732X_INP_AUX1L_PINBIAS_EN		(1 << 2)
#define DA732X_INP_AUX1R_PINBIAS_EN		(1 << 3)
#define DA732X_INP_AUX2_PINBIAS_EN		(1 << 4)

/* DA732X_REG_INP_ZC_EN	(addr=0x1B) */
#define	DA732X_MIC1_PRE_ZC_EN			(1 << 0)
#define	DA732X_MIC1_ZC_EN			(1 << 1)
#define	DA732X_MIC2_PRE_ZC_EN			(1 << 2)
#define	DA732X_MIC2_ZC_EN			(1 << 3)
#define	DA732X_AUXL_ZC_EN			(1 << 4)
#define	DA732X_AUXR_ZC_EN			(1 << 5)
#define	DA732X_MIC3_PRE_ZC_EN			(1 << 6)
#define	DA732X_MIC3_ZC_EN			(1 << 7)

/* DA732X_REG_INP_MUX	(addr=0x1D) */
#define DA732X_INP_ADC1L_MUX_SEL_AUX1L		(0 << 0)
#define DA732X_INP_ADC1L_MUX_SEL_MIC1		(1 << 0)
#define DA732X_INP_ADC1R_MUX_SEL_MASK		(3 << 2)
#define DA732X_INP_ADC1R_MUX_SEL_AUX1R		(0 << 2)
#define DA732X_INP_ADC1R_MUX_SEL_MIC2		(1 << 2)
#define DA732X_INP_ADC1R_MUX_SEL_MIC3		(2 << 2)
#define DA732X_INP_ADC2L_MUX_SEL_AUX1L		(0 << 4)
#define DA732X_INP_ADC2L_MUX_SEL_MICL		(1 << 4)
#define DA732X_INP_ADC2R_MUX_SEL_MASK		(3 << 6)
#define DA732X_INP_ADC2R_MUX_SEL_AUX1R		(0 << 6)
#define DA732X_INP_ADC2R_MUX_SEL_MICR		(1 << 6)
#define DA732X_INP_ADC2R_MUX_SEL_AUX2		(2 << 6)
#define	DA732X_ADC1L_MUX_SEL_SHIFT		0
#define	DA732X_ADC1R_MUX_SEL_SHIFT		2
#define	DA732X_ADC2L_MUX_SEL_SHIFT		4
#define	DA732X_ADC2R_MUX_SEL_SHIFT		6

/* DA732X_REG_HP_DET		(addr=0x20) */
#define DA732X_HP_DET_AZ			(1 << 0)
#define DA732X_HP_DET_SEL1			(1 << 1)
#define DA732X_HP_DET_IS_MASK			(3 << 2)
#define DA732X_HP_DET_IS_0_5UA			(0 << 2)
#define DA732X_HP_DET_IS_1UA			(1 << 2)
#define DA732X_HP_DET_IS_2UA			(2 << 2)
#define DA732X_HP_DET_IS_4UA			(3 << 2)
#define DA732X_HP_DET_RS_MASK			(3 << 4)
#define DA732X_HP_DET_RS_INFINITE		(0 << 4)
#define DA732X_HP_DET_RS_100KOHM		(1 << 4)
#define DA732X_HP_DET_RS_10KOHM			(2 << 4)
#define DA732X_HP_DET_RS_1KOHM			(3 << 4)
#define DA732X_HP_DET_EN			(1 << 7)

/* DA732X_REG_HPL_DAC_OFFSET	(addr=0x21/0x26) */
#define DA732X_HP_DAC_OFFSET_TRIM_MASK		(0x3F << 0)
#define DA732X_HP_DAC_OFFSET_DAC_SIGN		(1 << 6)

/* DA732X_REG_HPL_DAC_OFF_CNTL	(addr=0x22/0x27) */
#define DA732X_HP_DAC_OFF_CNTL_CONT_MASK	(7 << 0)
#define DA732X_HP_DAC_OFF_CNTL_COMPO		(1 << 3)
#define	DA732X_HP_DAC_OFF_CALIBRATION		(1 << 0)
#define	DA732X_HP_DAC_OFF_SCALE_STEPS		(1 << 1)
#define	DA732X_HP_DAC_OFF_MASK			0x7F
#define DA732X_HP_DAC_COMPO_SHIFT		3

/* DA732X_REG_HPL_OUT_OFFSET	(addr=0x23/0x28) */
#define DA732X_HP_OUT_OFFSET_MASK		(0xFF << 0)
#define	DA732X_HP_DAC_OFFSET_TRIM_VAL		0x7F

/* DA732X_REG_HPL/R	(addr=0x24/0x29) */
#define DA732X_HP_OUT_SIGN			(1 << 0)
#define DA732X_HP_OUT_COMP			(1 << 1)
#define DA732X_HP_OUT_RESERVED			(1 << 2)
#define DA732X_HP_OUT_COMPO			(1 << 3)
#define DA732X_HP_OUT_DAC_EN			(1 << 4)
#define DA732X_HP_OUT_HIZ_EN			(1 << 5)
#define	DA732X_HP_OUT_HIZ_DIS			(0 << 5)
#define DA732X_HP_OUT_MUTE			(1 << 6)
#define DA732X_HP_OUT_EN			(1 << 7)
#define	DA732X_HP_OUT_COMPO_SHIFT		3
#define	DA732X_HP_OUT_DAC_EN_SHIFT		4
#define	DA732X_HP_HIZ_SHIFT			5
#define	DA732X_HP_MUTE_SHIFT			6
#define DA732X_HP_OUT_EN_SHIFT			7

#define DA732X_OUT_HIZ_EN			(1 << 5)
#define	DA732X_OUT_HIZ_DIS			(0 << 5)

/* DA732X_REG_HPL/R_VOL	(addr=0x25/0x2A) */
#define	DA732X_HP_VOL_VAL_MASK			0xF
#define	DA732X_HP_VOL_SHIFT			0
#define	DA732X_HP_VOL_VAL_MAX			DA732X_HP_VOL_VAL_MASK

/* DA732X_REG_LIN2/3/4	(addr=0x2B/0x2C/0x2D) */
#define DA732X_LOUT_VOL_SHIFT			0
#define DA732X_LOUT_VOL_MASK			0x0F
#define DA732X_LOUT_DAC_OFF			(0 << 4)
#define DA732X_LOUT_DAC_EN			(1 << 4)
#define DA732X_LOUT_HIZ_N_DIS			(0 << 5)
#define DA732X_LOUT_HIZ_N_EN			(1 << 5)
#define DA732X_LOUT_UNMUTED			(0 << 6)
#define DA732X_LOUT_MUTED			(1 << 6)
#define DA732X_LOUT_EN				(0 << 7)
#define DA732X_LOUT_DIS				(1 << 7)
#define DA732X_LOUT_DAC_EN_SHIFT		4
#define	DA732X_LOUT_MUTE_SHIFT			6
#define DA732X_LIN_OUT_EN_SHIFT			7
#define DA732X_LOUT_VOL_VAL_MAX			DA732X_LOUT_VOL_MASK

/* DA732X_REG_OUT_ZC_EN		(addr=0x2E) */
#define	DA732X_HPL_ZC_EN_SHIFT			0
#define DA732X_HPR_ZC_EN_SHIFT			1
#define DA732X_HPL_ZC_EN			(1 << 0)
#define DA732X_HPL_ZC_DIS			(0 << 0)
#define DA732X_HPR_ZC_EN			(1 << 1)
#define DA732X_HPR_ZC_DIS			(0 << 1)
#define DA732X_LIN2_ZC_EN			(1 << 2)
#define DA732X_LIN2_ZC_DIS			(0 << 2)
#define DA732X_LIN3_ZC_EN			(1 << 3)
#define DA732X_LIN3_ZC_DIS			(0 << 3)
#define DA732X_LIN4_ZC_EN			(1 << 4)
#define DA732X_LIN4_ZC_DIS			(0 << 4)

/* DA732X_REG_HP_LIN1_GNDSEL (addr=0x37) */
#define	DA732X_HP_OUT_GNDSEL			(1 << 0)

/* DA732X_REG_CP_HP2 (addr=0x3a) */
#define	DA732X_HP_CP_PULSESKIP			(1 << 0)
#define	DA732X_HP_CP_REG			(1 << 1)
#define DA732X_HP_CP_EN				(1 << 3)
#define DA732X_HP_CP_DIS			(0 << 3)

/* DA732X_REG_CP_CTRL1 (addr=0x40) */
#define	DA732X_CP_MODE_MASK			(7 << 1)
#define	DA732X_CP_CTRL_STANDBY			(0 << 1)
#define	DA732X_CP_CTRL_CPVDD6			(2 << 1)
#define	DA732X_CP_CTRL_CPVDD5			(3 << 1)
#define	DA732X_CP_CTRL_CPVDD4			(4 << 1)
#define	DA732X_CP_CTRL_CPVDD3			(5 << 1)
#define	DA732X_CP_CTRL_CPVDD2			(6 << 1)
#define	DA732X_CP_CTRL_CPVDD1			(7 << 1)
#define	DA723X_CP_DIS				(0 << 7)
#define	DA732X_CP_EN				(1 << 7)

/* DA732X_REG_CP_CTRL2 (addr=0x41) */
#define	DA732X_CP_BOOST				(1 << 0)
#define	DA732X_CP_MANAGE_MAGNITUDE		(2 << 2)

/* DA732X_REG_CP_CTRL3 (addr=0x42) */
#define	DA732X_CP_1MHZ				(0 << 0)
#define	DA732X_CP_500KHZ			(1 << 0)
#define	DA732X_CP_250KHZ			(2 << 0)
#define	DA732X_CP_125KHZ			(3 << 0)
#define	DA732X_CP_63KHZ				(4 << 0)
#define	DA732X_CP_0KHZ				(5 << 0)

/* DA732X_REG_PLL_CTRL (addr=0x53) */
#define	DA732X_PLL_INDIV_MASK			(3 << 0)
#define	DA732X_PLL_SRM_EN			(1 << 2)
#define	DA732X_PLL_EN				(1 << 7)
#define	DA732X_PLL_BYPASS			(0 << 0)

/* DA732X_REG_CLK_CTRL (addr=0x54) */
#define	DA732X_SR1_MASK				(0xF)
#define	DA732X_SR2_MASK				(0xF0)

/* DA732X_REG_CLK_DSP (addr=0x5A) */
#define	DA732X_DSP_FREQ_MASK			(7 << 0)
#define	DA732X_DSP_FREQ_12MHZ			(0 << 0)
#define	DA732X_DSP_FREQ_24MHZ			(1 << 0)
#define	DA732X_DSP_FREQ_36MHZ			(2 << 0)
#define	DA732X_DSP_FREQ_48MHZ			(3 << 0)
#define	DA732X_DSP_FREQ_60MHZ			(4 << 0)
#define	DA732X_DSP_FREQ_72MHZ			(5 << 0)
#define	DA732X_DSP_FREQ_84MHZ			(6 << 0)
#define	DA732X_DSP_FREQ_96MHZ			(7 << 0)

/* DA732X_REG_CLK_EN1 (addr=0x5B) */
#define	DA732X_DSP_CLK_EN			(1 << 0)
#define	DA732X_SYS3_CLK_EN			(1 << 1)
#define	DA732X_DSP12_CLK_EN			(1 << 2)
#define	DA732X_PC_CLK_EN			(1 << 3)
#define	DA732X_MCLK_SQR_EN			(1 << 7)

/* DA732X_REG_CLK_EN2 (addr=0x5C) */
#define	DA732X_UART_CLK_EN			(1 << 1)
#define	DA732X_CP_CLK_EN			(1 << 2)
#define	DA732X_CP_CLK_DIS			(0 << 2)

/* DA732X_REG_CLK_EN3 (addr=0x5D) */
#define	DA732X_ADCA_BB_CLK_EN			(1 << 0)
#define	DA732X_ADCC_BB_CLK_EN			(1 << 4)

/* DA732X_REG_CLK_EN4 (addr=0x5E) */
#define	DA732X_DACA_BB_CLK_EN			(1 << 0)
#define	DA732X_DACC_BB_CLK_EN			(1 << 4)
#define DA732X_DACA_BB_CLK_SHIFT		0
#define DA732X_DACC_BB_CLK_SHIFT		4

/* DA732X_REG_CLK_EN5 (addr=0x5F) */
#define	DA732X_DACE_BB_CLK_EN			(1 << 0)
#define DA732X_DACE_BB_CLK_SHIFT		0

/* DA732X_REG_AIF_MCLK (addr=0x60) */
#define DA732X_AIFM_FRAME_64			(1 << 2)
#define	DA732X_AIFM_SRC_SEL_AIFA		(1 << 6)
#define	DA732X_CLK_GENERATION_AIF_A		(1 << 4)
#define	DA732X_NO_CLK_GENERATION		0x0

/* DA732X_REG_AIFA1 (addr=0x61) */
#define	DA732X_AIF_WORD_MASK			(0x3 << 0)
#define	DA732X_AIF_WORD_16			(0 << 0)
#define	DA732X_AIF_WORD_20			(1 << 0)
#define	DA732X_AIF_WORD_24			(2 << 0)
#define	DA732X_AIF_WORD_32			(3 << 0)
#define	DA732X_AIF_TDM_MONO_SHIFT		(1 << 6)
#define	DA732X_AIF1_CLK_MASK			(1 << 7)
#define	DA732X_AIF_SLAVE			(0 << 7)
#define DA732X_AIF_CLK_FROM_SRC			(1 << 7)

/* DA732X_REG_AIFA3 (addr=0x63) */
#define	DA732X_AIF_MODE_SHIFT			0
#define	DA732X_AIF_MODE_MASK			0x3
#define	DA732X_AIF_I2S_MODE			(0 << 0)
#define	DA732X_AIF_LEFT_J_MODE			(1 << 0)
#define	DA732X_AIF_RIGHT_J_MODE			(2 << 0)
#define	DA732X_AIF_DSP_MODE			(3 << 0)
#define DA732X_AIF_WCLK_INV			(1 << 4)
#define DA732X_AIF_BCLK_INV			(1 << 5)
#define	DA732X_AIF_EN				(1 << 7)
#define	DA732X_AIF_EN_SHIFT			7

/* DA732X_REG_PC_CTRL (addr=0x6a) */
#define	DA732X_PC_PULSE_AIFA			(0 << 0)
#define	DA732X_PC_PULSE_AIFB			(1 << 0)
#define	DA732X_PC_RESYNC_AUT			(1 << 6)
#define	DA732X_PC_RESYNC_NOT_AUT		(0 << 6)
#define	DA732X_PC_SAME				(1 << 7)

/* DA732X_REG_DATA_ROUTE (addr=0x70) */
#define DA732X_ADC1_TO_AIFA			(0 << 0)
#define DA732X_DSP_TO_AIFA			(1 << 0)
#define DA732X_ADC2_TO_AIFB			(0 << 1)
#define DA732X_DSP_TO_AIFB			(1 << 1)
#define DA732X_AIFA_TO_DAC1L			(0 << 2)
#define DA732X_DSP_TO_DAC1L			(1 << 2)
#define DA732X_AIFA_TO_DAC1R			(0 << 3)
#define DA732X_DSP_TO_DAC1R			(1 << 3)
#define DA732X_AIFB_TO_DAC2L			(0 << 4)
#define DA732X_DSP_TO_DAC2L			(1 << 4)
#define DA732X_AIFB_TO_DAC2R			(0 << 5)
#define DA732X_DSP_TO_DAC2R			(1 << 5)
#define DA732X_AIFB_TO_DAC3			(0 << 6)
#define DA732X_DSP_TO_DAC3			(1 << 6)
#define	DA732X_BYPASS_DSP			(0 << 0)
#define	DA732X_ALL_TO_DSP			(0x7F << 0)

/* DA732X_REG_DSP_CTRL (addr=0x71) */
#define	DA732X_DIGITAL_EN			(1 << 0)
#define	DA732X_DIGITAL_RESET			(0 << 0)
#define	DA732X_DSP_CORE_EN			(1 << 1)
#define	DA732X_DSP_CORE_RESET			(0 << 1)

/* DA732X_REG_SPARE1_OUT (addr=0x7D)*/
#define	DA732X_HP_DRIVER_EN			(1 << 0)
#define	DA732X_HP_GATE_LOW			(1 << 2)
#define DA732X_HP_LOOP_GAIN_CTRL		(1 << 3)

/* DA732X_REG_ID (addr=0x81)*/
#define DA732X_ID_MINOR_MASK			(0xF << 0)
#define DA732X_ID_MAJOR_MASK			(0xF << 4)

/* DA732X_REG_ADC1/2_PD (addr=0x90/0x98) */
#define	DA732X_ADC_RST_MASK			(0x3 << 0)
#define	DA732X_ADC_PD_MASK			(0x3 << 2)
#define	DA732X_ADC_SET_ACT			(0x3 << 0)
#define	DA732X_ADC_SET_RST			(0x0 << 0)
#define	DA732X_ADC_ON				(0x3 << 2)
#define	DA732X_ADC_OFF				(0x0 << 2)

/* DA732X_REG_ADC1/2_SEL (addr=0x94/0x9C) */
#define	DA732X_ADC_VOL_VAL_MASK			0x7
#define	DA732X_ADCL_VOL_SHIFT			0
#define	DA732X_ADCR_VOL_SHIFT			4
#define DA732X_ADCL_EN_SHIFT			2
#define DA732X_ADCR_EN_SHIFT			3
#define	DA732X_ADCL_EN				(1 << 2)
#define	DA732X_ADCR_EN				(1 << 3)
#define	DA732X_ADC_VOL_VAL_MAX			DA732X_ADC_VOL_VAL_MASK

/*
 * DA732X_REG_ADC1/2_HPF (addr=0x93/0x9b)
 * DA732x_REG_DAC1/2/3_HPG	(addr=0xA5/0xB5/0xC5)
 */
#define	DA732X_HPF_MUSIC_EN			(1 << 3)
#define	DA732X_HPF_VOICE_EN			((1 << 3) | (1 << 7))
#define	DA732X_HPF_MASK				((1 << 3) | (1 << 7))
#define DA732X_HPF_DIS				((0 << 3) | (0 << 7))

/* DA732X_REG_DAC1/2/3_VOL */
#define DA732X_DAC_VOL_VAL_MASK			0x7F
#define DA732X_DAC_VOL_SHIFT			0
#define DA732X_DAC_VOL_VAL_MAX			DA732X_DAC_VOL_VAL_MASK

/* DA732X_REG_DAC1/2/3_SEL (addr=0xA3/0xB3/0xC3) */
#define DA732X_DACL_EN_SHIFT			3
#define	DA732X_DACR_EN_SHIFT			7
#define DA732X_DACL_MUTE_SHIFT			2
#define	DA732X_DACR_MUTE_SHIFT			6
#define DA732X_DACL_EN				(1 << 3)
#define	DA732X_DACR_EN				(1 << 7)
#define	DA732X_DACL_SDM				(1 << 0)
#define	DA732X_DACR_SDM				(1 << 4)
#define	DA732X_DACL_MUTE			(1 << 2)
#define	DA732X_DACR_MUTE			(1 << 6)

/* DA732X_REG_DAC_SOFTMUTE (addr=0xA4/0xB4/0xC4) */
#define	DA732X_SOFTMUTE_EN			(1 << 7)
#define	DA732X_GAIN_RAMPED			(1 << 6)
#define	DA732X_16_SAMPLES			(4 << 0)
#define	DA732X_SOFTMUTE_MASK			(1 << 7)
#define	DA732X_SOFTMUTE_SHIFT			7

/*
 * DA732x_REG_ADC1/2_EQ12	(addr=0x95/0x9D)
 * DA732x_REG_ADC1/2_EQ34	(addr=0x96/0x9E)
 * DA732x_REG_ADC1/2_EQ5	(addr=0x97/0x9F)
 * DA732x_REG_DAC1/2/3_EQ12	(addr=0xA5/0xB5/0xC5)
 * DA732x_REG_DAC1/2/3_EQ34	(addr=0xA6/0xB6/0xC6)
 * DA732x_REG_DAC1/2/3_EQ5	(addr=0xA7/0xB7/0xB7)
 */
#define	DA732X_EQ_VOL_VAL_MASK			0xF
#define	DA732X_EQ_BAND1_SHIFT			0
#define	DA732X_EQ_BAND2_SHIFT			4
#define	DA732X_EQ_BAND3_SHIFT			0
#define	DA732X_EQ_BAND4_SHIFT			4
#define	DA732X_EQ_BAND5_SHIFT			0
#define	DA732X_EQ_OVERALL_SHIFT			4
#define	DA732X_EQ_OVERALL_VOL_VAL_MASK		0x3
#define	DA732X_EQ_DIS				(0 << 7)
#define	DA732X_EQ_EN				(1 << 7)
#define	DA732X_EQ_EN_SHIFT			7
#define	DA732X_EQ_VOL_VAL_MAX			DA732X_EQ_VOL_VAL_MASK
#define	DA732X_EQ_OVERALL_VOL_VAL_MAX		DA732X_EQ_OVERALL_VOL_VAL_MASK

/* DA732X_REG_DMA_CMD (addr=0xD3) */
#define	DA732X_SEL_DSP_DMA_MASK			(3 << 0)
#define	DA732X_SEL_DSP_DMA_DIS			(0 << 0)
#define	DA732X_SEL_DSP_DMA_PMEM			(1 << 0)
#define	DA732X_SEL_DSP_DMA_XMEM			(2 << 0)
#define	DA732X_SEL_DSP_DMA_YMEM			(3 << 0)
#define	DA732X_DSP_RW_MASK			(1 << 4)
#define	DA732X_DSP_DMA_WRITE			(0 << 4)
#define	DA732X_DSP_DMA_READ			(1 << 4)

/* DA732X_REG_DMA_STATUS (addr=0xDA) */
#define	DA732X_DSP_DMA_FREE			(0 << 0)
#define	DA732X_DSP_DMA_BUSY			(1 << 0)

#endif /* __DA732X_REG_H_ */
