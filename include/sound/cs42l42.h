/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * linux/sound/cs42l42.h -- Platform data for CS42L42 ALSA SoC audio driver header
 *
 * Copyright 2016-2022 Cirrus Logic, Inc.
 *
 * Author: James Schulman <james.schulman@cirrus.com>
 * Author: Brian Austin <brian.austin@cirrus.com>
 * Author: Michael White <michael.white@cirrus.com>
 */

#ifndef __CS42L42_H
#define __CS42L42_H

#define CS42L42_PAGE_REGISTER	0x00	/* Page Select Register */
#define CS42L42_WIN_START	0x00
#define CS42L42_WIN_LEN		0x100
#define CS42L42_RANGE_MIN	0x00
#define CS42L42_RANGE_MAX	0x7F

#define CS42L42_PAGE_10		0x1000
#define CS42L42_PAGE_11		0x1100
#define CS42L42_PAGE_12		0x1200
#define CS42L42_PAGE_13		0x1300
#define CS42L42_PAGE_15		0x1500
#define CS42L42_PAGE_19		0x1900
#define CS42L42_PAGE_1B		0x1B00
#define CS42L42_PAGE_1C		0x1C00
#define CS42L42_PAGE_1D		0x1D00
#define CS42L42_PAGE_1F		0x1F00
#define CS42L42_PAGE_20		0x2000
#define CS42L42_PAGE_21		0x2100
#define CS42L42_PAGE_23		0x2300
#define CS42L42_PAGE_24		0x2400
#define CS42L42_PAGE_25		0x2500
#define CS42L42_PAGE_26		0x2600
#define CS42L42_PAGE_28		0x2800
#define CS42L42_PAGE_29		0x2900
#define CS42L42_PAGE_2A		0x2A00
#define CS42L42_PAGE_30		0x3000

#define CS42L42_CHIP_ID		0x42A42
#define CS42L83_CHIP_ID		0x42A83

/* Page 0x10 Global Registers */
#define CS42L42_DEVID_AB		(CS42L42_PAGE_10 + 0x01)
#define CS42L42_DEVID_CD		(CS42L42_PAGE_10 + 0x02)
#define CS42L42_DEVID_E			(CS42L42_PAGE_10 + 0x03)
#define CS42L42_FABID			(CS42L42_PAGE_10 + 0x04)
#define CS42L42_REVID			(CS42L42_PAGE_10 + 0x05)
#define CS42L42_FRZ_CTL			(CS42L42_PAGE_10 + 0x06)

#define CS42L42_SRC_CTL			(CS42L42_PAGE_10 + 0x07)
#define CS42L42_SRC_BYPASS_DAC_SHIFT	1
#define CS42L42_SRC_BYPASS_DAC_MASK	(1 << CS42L42_SRC_BYPASS_DAC_SHIFT)

#define CS42L42_MCLK_STATUS		(CS42L42_PAGE_10 + 0x08)

#define CS42L42_MCLK_CTL		(CS42L42_PAGE_10 + 0x09)
#define CS42L42_INTERNAL_FS_SHIFT	1
#define CS42L42_INTERNAL_FS_MASK	(1 << CS42L42_INTERNAL_FS_SHIFT)

#define CS42L42_SFTRAMP_RATE		(CS42L42_PAGE_10 + 0x0A)
#define CS42L42_SLOW_START_ENABLE	(CS42L42_PAGE_10 + 0x0B)
#define CS42L42_SLOW_START_EN_MASK	GENMASK(6, 4)
#define CS42L42_SLOW_START_EN_SHIFT	4
#define CS42L42_I2C_DEBOUNCE		(CS42L42_PAGE_10 + 0x0E)
#define CS42L42_I2C_STRETCH		(CS42L42_PAGE_10 + 0x0F)
#define CS42L42_I2C_TIMEOUT		(CS42L42_PAGE_10 + 0x10)

/* Page 0x11 Power and Headset Detect Registers */
#define CS42L42_PWR_CTL1		(CS42L42_PAGE_11 + 0x01)
#define CS42L42_ASP_DAO_PDN_SHIFT	7
#define CS42L42_ASP_DAO_PDN_MASK	(1 << CS42L42_ASP_DAO_PDN_SHIFT)
#define CS42L42_ASP_DAI_PDN_SHIFT	6
#define CS42L42_ASP_DAI_PDN_MASK	(1 << CS42L42_ASP_DAI_PDN_SHIFT)
#define CS42L42_MIXER_PDN_SHIFT		5
#define CS42L42_MIXER_PDN_MASK		(1 << CS42L42_MIXER_PDN_SHIFT)
#define CS42L42_EQ_PDN_SHIFT		4
#define CS42L42_EQ_PDN_MASK		(1 << CS42L42_EQ_PDN_SHIFT)
#define CS42L42_HP_PDN_SHIFT		3
#define CS42L42_HP_PDN_MASK		(1 << CS42L42_HP_PDN_SHIFT)
#define CS42L42_ADC_PDN_SHIFT		2
#define CS42L42_ADC_PDN_MASK		(1 << CS42L42_ADC_PDN_SHIFT)
#define CS42L42_PDN_ALL_SHIFT		0
#define CS42L42_PDN_ALL_MASK		(1 << CS42L42_PDN_ALL_SHIFT)

#define CS42L42_PWR_CTL2		(CS42L42_PAGE_11 + 0x02)
#define CS42L42_ADC_SRC_PDNB_SHIFT	0
#define CS42L42_ADC_SRC_PDNB_MASK	(1 << CS42L42_ADC_SRC_PDNB_SHIFT)
#define CS42L42_DAC_SRC_PDNB_SHIFT	1
#define CS42L42_DAC_SRC_PDNB_MASK	(1 << CS42L42_DAC_SRC_PDNB_SHIFT)
#define CS42L42_ASP_DAI1_PDN_SHIFT	2
#define CS42L42_ASP_DAI1_PDN_MASK	(1 << CS42L42_ASP_DAI1_PDN_SHIFT)
#define CS42L42_SRC_PDN_OVERRIDE_SHIFT	3
#define CS42L42_SRC_PDN_OVERRIDE_MASK	(1 << CS42L42_SRC_PDN_OVERRIDE_SHIFT)
#define CS42L42_DISCHARGE_FILT_SHIFT	4
#define CS42L42_DISCHARGE_FILT_MASK	(1 << CS42L42_DISCHARGE_FILT_SHIFT)

#define CS42L42_PWR_CTL3			(CS42L42_PAGE_11 + 0x03)
#define CS42L42_RING_SENSE_PDNB_SHIFT		1
#define CS42L42_RING_SENSE_PDNB_MASK		(1 << CS42L42_RING_SENSE_PDNB_SHIFT)
#define CS42L42_VPMON_PDNB_SHIFT		2
#define CS42L42_VPMON_PDNB_MASK			(1 << CS42L42_VPMON_PDNB_SHIFT)
#define CS42L42_SW_CLK_STP_STAT_SEL_SHIFT	5
#define CS42L42_SW_CLK_STP_STAT_SEL_MASK	(3 << CS42L42_SW_CLK_STP_STAT_SEL_SHIFT)

#define CS42L42_RSENSE_CTL1			(CS42L42_PAGE_11 + 0x04)
#define CS42L42_RS_TRIM_R_SHIFT			0
#define CS42L42_RS_TRIM_R_MASK			(1 << CS42L42_RS_TRIM_R_SHIFT)
#define CS42L42_RS_TRIM_T_SHIFT			1
#define CS42L42_RS_TRIM_T_MASK			(1 << CS42L42_RS_TRIM_T_SHIFT)
#define CS42L42_HPREF_RS_SHIFT			2
#define CS42L42_HPREF_RS_MASK			(1 << CS42L42_HPREF_RS_SHIFT)
#define CS42L42_HSBIAS_FILT_REF_RS_SHIFT	3
#define CS42L42_HSBIAS_FILT_REF_RS_MASK		(1 << CS42L42_HSBIAS_FILT_REF_RS_SHIFT)
#define CS42L42_RING_SENSE_PU_HIZ_SHIFT		6
#define CS42L42_RING_SENSE_PU_HIZ_MASK		(1 << CS42L42_RING_SENSE_PU_HIZ_SHIFT)

#define CS42L42_RSENSE_CTL2		(CS42L42_PAGE_11 + 0x05)
#define CS42L42_TS_RS_GATE_SHIFT	7
#define CS42L42_TS_RS_GATE_MAS		(1 << CS42L42_TS_RS_GATE_SHIFT)

#define CS42L42_OSC_SWITCH		(CS42L42_PAGE_11 + 0x07)
#define CS42L42_SCLK_PRESENT_SHIFT	0
#define CS42L42_SCLK_PRESENT_MASK	(1 << CS42L42_SCLK_PRESENT_SHIFT)

#define CS42L42_OSC_SWITCH_STATUS	(CS42L42_PAGE_11 + 0x09)
#define CS42L42_OSC_SW_SEL_STAT_SHIFT	0
#define CS42L42_OSC_SW_SEL_STAT_MASK	(3 << CS42L42_OSC_SW_SEL_STAT_SHIFT)
#define CS42L42_OSC_PDNB_STAT_SHIFT	2
#define CS42L42_OSC_PDNB_STAT_MASK	(1 << CS42L42_OSC_SW_SEL_STAT_SHIFT)

#define CS42L42_RSENSE_CTL3			(CS42L42_PAGE_11 + 0x12)
#define CS42L42_RS_RISE_DBNCE_TIME_SHIFT	0
#define CS42L42_RS_RISE_DBNCE_TIME_MASK		(7 << CS42L42_RS_RISE_DBNCE_TIME_SHIFT)
#define CS42L42_RS_FALL_DBNCE_TIME_SHIFT	3
#define CS42L42_RS_FALL_DBNCE_TIME_MASK		(7 << CS42L42_RS_FALL_DBNCE_TIME_SHIFT)
#define CS42L42_RS_PU_EN_SHIFT			6
#define CS42L42_RS_PU_EN_MASK			(1 << CS42L42_RS_PU_EN_SHIFT)
#define CS42L42_RS_INV_SHIFT			7
#define CS42L42_RS_INV_MASK			(1 << CS42L42_RS_INV_SHIFT)

#define CS42L42_TSENSE_CTL			(CS42L42_PAGE_11 + 0x13)
#define CS42L42_TS_RISE_DBNCE_TIME_SHIFT	0
#define CS42L42_TS_RISE_DBNCE_TIME_MASK		(7 << CS42L42_TS_RISE_DBNCE_TIME_SHIFT)
#define CS42L42_TS_FALL_DBNCE_TIME_SHIFT	3
#define CS42L42_TS_FALL_DBNCE_TIME_MASK		(7 << CS42L42_TS_FALL_DBNCE_TIME_SHIFT)
#define CS42L42_TS_INV_SHIFT			7
#define CS42L42_TS_INV_MASK			(1 << CS42L42_TS_INV_SHIFT)

#define CS42L42_TSRS_INT_DISABLE	(CS42L42_PAGE_11 + 0x14)
#define CS42L42_D_RS_PLUG_DBNC_SHIFT	0
#define CS42L42_D_RS_PLUG_DBNC_MASK	(1 << CS42L42_D_RS_PLUG_DBNC_SHIFT)
#define CS42L42_D_RS_UNPLUG_DBNC_SHIFT	1
#define CS42L42_D_RS_UNPLUG_DBNC_MASK	(1 << CS42L42_D_RS_UNPLUG_DBNC_SHIFT)
#define CS42L42_D_TS_PLUG_DBNC_SHIFT	2
#define CS42L42_D_TS_PLUG_DBNC_MASK	(1 << CS42L42_D_TS_PLUG_DBNC_SHIFT)
#define CS42L42_D_TS_UNPLUG_DBNC_SHIFT	3
#define CS42L42_D_TS_UNPLUG_DBNC_MASK	(1 << CS42L42_D_TS_UNPLUG_DBNC_SHIFT)

#define CS42L42_TRSENSE_STATUS		(CS42L42_PAGE_11 + 0x15)
#define CS42L42_RS_PLUG_DBNC_SHIFT	0
#define CS42L42_RS_PLUG_DBNC_MASK	(1 << CS42L42_RS_PLUG_DBNC_SHIFT)
#define CS42L42_RS_UNPLUG_DBNC_SHIFT	1
#define CS42L42_RS_UNPLUG_DBNC_MASK	(1 << CS42L42_RS_UNPLUG_DBNC_SHIFT)
#define CS42L42_TS_PLUG_DBNC_SHIFT	2
#define CS42L42_TS_PLUG_DBNC_MASK	(1 << CS42L42_TS_PLUG_DBNC_SHIFT)
#define CS42L42_TS_UNPLUG_DBNC_SHIFT	3
#define CS42L42_TS_UNPLUG_DBNC_MASK	(1 << CS42L42_TS_UNPLUG_DBNC_SHIFT)

#define CS42L42_HSDET_CTL1		(CS42L42_PAGE_11 + 0x1F)
#define CS42L42_HSDET_COMP1_LVL_SHIFT	0
#define CS42L42_HSDET_COMP1_LVL_MASK	(15 << CS42L42_HSDET_COMP1_LVL_SHIFT)
#define CS42L42_HSDET_COMP2_LVL_SHIFT	4
#define CS42L42_HSDET_COMP2_LVL_MASK	(15 << CS42L42_HSDET_COMP2_LVL_SHIFT)

#define CS42L42_HSDET_COMP1_LVL_VAL	12 /* 1.25V Comparator */
#define CS42L42_HSDET_COMP2_LVL_VAL	2  /* 1.75V Comparator */
#define CS42L42_HSDET_COMP1_LVL_DEFAULT	7  /* 1V Comparator */
#define CS42L42_HSDET_COMP2_LVL_DEFAULT	7  /* 2V Comparator */

#define CS42L42_HSDET_CTL2		(CS42L42_PAGE_11 + 0x20)
#define CS42L42_HSDET_AUTO_TIME_SHIFT	0
#define CS42L42_HSDET_AUTO_TIME_MASK	(3 << CS42L42_HSDET_AUTO_TIME_SHIFT)
#define CS42L42_HSBIAS_REF_SHIFT	3
#define CS42L42_HSBIAS_REF_MASK		(1 << CS42L42_HSBIAS_REF_SHIFT)
#define CS42L42_HSDET_SET_SHIFT		4
#define CS42L42_HSDET_SET_MASK		(3 << CS42L42_HSDET_SET_SHIFT)
#define CS42L42_HSDET_CTRL_SHIFT	6
#define CS42L42_HSDET_CTRL_MASK		(3 << CS42L42_HSDET_CTRL_SHIFT)

#define CS42L42_HS_SWITCH_CTL		(CS42L42_PAGE_11 + 0x21)
#define CS42L42_SW_GNDHS_HS4_SHIFT	0
#define CS42L42_SW_GNDHS_HS4_MASK	(1 << CS42L42_SW_GNDHS_HS4_SHIFT)
#define CS42L42_SW_GNDHS_HS3_SHIFT	1
#define CS42L42_SW_GNDHS_HS3_MASK	(1 << CS42L42_SW_GNDHS_HS3_SHIFT)
#define CS42L42_SW_HSB_HS4_SHIFT	2
#define CS42L42_SW_HSB_HS4_MASK		(1 << CS42L42_SW_HSB_HS4_SHIFT)
#define CS42L42_SW_HSB_HS3_SHIFT	3
#define CS42L42_SW_HSB_HS3_MASK		(1 << CS42L42_SW_HSB_HS3_SHIFT)
#define CS42L42_SW_HSB_FILT_HS4_SHIFT	4
#define CS42L42_SW_HSB_FILT_HS4_MASK	(1 << CS42L42_SW_HSB_FILT_HS4_SHIFT)
#define CS42L42_SW_HSB_FILT_HS3_SHIFT	5
#define CS42L42_SW_HSB_FILT_HS3_MASK	(1 << CS42L42_SW_HSB_FILT_HS3_SHIFT)
#define CS42L42_SW_REF_HS4_SHIFT	6
#define CS42L42_SW_REF_HS4_MASK		(1 << CS42L42_SW_REF_HS4_SHIFT)
#define CS42L42_SW_REF_HS3_SHIFT	7
#define CS42L42_SW_REF_HS3_MASK		(1 << CS42L42_SW_REF_HS3_SHIFT)

#define CS42L42_HS_DET_STATUS		(CS42L42_PAGE_11 + 0x24)
#define CS42L42_HSDET_TYPE_SHIFT	0
#define CS42L42_HSDET_TYPE_MASK		(3 << CS42L42_HSDET_TYPE_SHIFT)
#define CS42L42_HSDET_COMP1_OUT_SHIFT	6
#define CS42L42_HSDET_COMP1_OUT_MASK	(1 << CS42L42_HSDET_COMP1_OUT_SHIFT)
#define CS42L42_HSDET_COMP2_OUT_SHIFT	7
#define CS42L42_HSDET_COMP2_OUT_MASK	(1 << CS42L42_HSDET_COMP2_OUT_SHIFT)
#define CS42L42_PLUG_CTIA		0
#define CS42L42_PLUG_OMTP		1
#define CS42L42_PLUG_HEADPHONE		2
#define CS42L42_PLUG_INVALID		3

#define CS42L42_HSDET_SW_COMP1		((0 << CS42L42_SW_GNDHS_HS4_SHIFT) | \
					 (1 << CS42L42_SW_GNDHS_HS3_SHIFT) | \
					 (1 << CS42L42_SW_HSB_HS4_SHIFT) | \
					 (0 << CS42L42_SW_HSB_HS3_SHIFT) | \
					 (0 << CS42L42_SW_HSB_FILT_HS4_SHIFT) | \
					 (1 << CS42L42_SW_HSB_FILT_HS3_SHIFT) | \
					 (0 << CS42L42_SW_REF_HS4_SHIFT) | \
					 (1 << CS42L42_SW_REF_HS3_SHIFT))
#define CS42L42_HSDET_SW_COMP2		((1 << CS42L42_SW_GNDHS_HS4_SHIFT) | \
					 (0 << CS42L42_SW_GNDHS_HS3_SHIFT) | \
					 (0 << CS42L42_SW_HSB_HS4_SHIFT) | \
					 (1 << CS42L42_SW_HSB_HS3_SHIFT) | \
					 (1 << CS42L42_SW_HSB_FILT_HS4_SHIFT) | \
					 (0 << CS42L42_SW_HSB_FILT_HS3_SHIFT) | \
					 (1 << CS42L42_SW_REF_HS4_SHIFT) | \
					 (0 << CS42L42_SW_REF_HS3_SHIFT))
#define CS42L42_HSDET_SW_TYPE1		((0 << CS42L42_SW_GNDHS_HS4_SHIFT) | \
					 (1 << CS42L42_SW_GNDHS_HS3_SHIFT) | \
					 (1 << CS42L42_SW_HSB_HS4_SHIFT) | \
					 (0 << CS42L42_SW_HSB_HS3_SHIFT) | \
					 (0 << CS42L42_SW_HSB_FILT_HS4_SHIFT) | \
					 (1 << CS42L42_SW_HSB_FILT_HS3_SHIFT) | \
					 (0 << CS42L42_SW_REF_HS4_SHIFT) | \
					 (1 << CS42L42_SW_REF_HS3_SHIFT))
#define CS42L42_HSDET_SW_TYPE2		((1 << CS42L42_SW_GNDHS_HS4_SHIFT) | \
					 (0 << CS42L42_SW_GNDHS_HS3_SHIFT) | \
					 (0 << CS42L42_SW_HSB_HS4_SHIFT) | \
					 (1 << CS42L42_SW_HSB_HS3_SHIFT) | \
					 (1 << CS42L42_SW_HSB_FILT_HS4_SHIFT) | \
					 (0 << CS42L42_SW_HSB_FILT_HS3_SHIFT) | \
					 (1 << CS42L42_SW_REF_HS4_SHIFT) | \
					 (0 << CS42L42_SW_REF_HS3_SHIFT))
#define CS42L42_HSDET_SW_TYPE3		((1 << CS42L42_SW_GNDHS_HS4_SHIFT) | \
					 (1 << CS42L42_SW_GNDHS_HS3_SHIFT) | \
					 (0 << CS42L42_SW_HSB_HS4_SHIFT) | \
					 (0 << CS42L42_SW_HSB_HS3_SHIFT) | \
					 (1 << CS42L42_SW_HSB_FILT_HS4_SHIFT) | \
					 (1 << CS42L42_SW_HSB_FILT_HS3_SHIFT) | \
					 (1 << CS42L42_SW_REF_HS4_SHIFT) | \
					 (1 << CS42L42_SW_REF_HS3_SHIFT))
#define CS42L42_HSDET_SW_TYPE4		((0 << CS42L42_SW_GNDHS_HS4_SHIFT) | \
					 (1 << CS42L42_SW_GNDHS_HS3_SHIFT) | \
					 (1 << CS42L42_SW_HSB_HS4_SHIFT) | \
					 (0 << CS42L42_SW_HSB_HS3_SHIFT) | \
					 (0 << CS42L42_SW_HSB_FILT_HS4_SHIFT) | \
					 (1 << CS42L42_SW_HSB_FILT_HS3_SHIFT) | \
					 (0 << CS42L42_SW_REF_HS4_SHIFT) | \
					 (1 << CS42L42_SW_REF_HS3_SHIFT))

#define CS42L42_HSDET_COMP_TYPE1	1
#define CS42L42_HSDET_COMP_TYPE2	2
#define CS42L42_HSDET_COMP_TYPE3	0
#define CS42L42_HSDET_COMP_TYPE4	3

#define CS42L42_HS_CLAMP_DISABLE	(CS42L42_PAGE_11 + 0x29)
#define CS42L42_HS_CLAMP_DISABLE_SHIFT	0
#define CS42L42_HS_CLAMP_DISABLE_MASK	(1 << CS42L42_HS_CLAMP_DISABLE_SHIFT)

/* Page 0x12 Clocking Registers */
#define CS42L42_MCLK_SRC_SEL		(CS42L42_PAGE_12 + 0x01)
#define CS42L42_MCLKDIV_SHIFT		1
#define CS42L42_MCLKDIV_MASK		(1 << CS42L42_MCLKDIV_SHIFT)
#define CS42L42_MCLK_SRC_SEL_SHIFT	0
#define CS42L42_MCLK_SRC_SEL_MASK	(1 << CS42L42_MCLK_SRC_SEL_SHIFT)

#define CS42L42_SPDIF_CLK_CFG		(CS42L42_PAGE_12 + 0x02)
#define CS42L42_FSYNC_PW_LOWER		(CS42L42_PAGE_12 + 0x03)

#define CS42L42_FSYNC_PW_UPPER			(CS42L42_PAGE_12 + 0x04)
#define CS42L42_FSYNC_PULSE_WIDTH_SHIFT		0
#define CS42L42_FSYNC_PULSE_WIDTH_MASK		(0xff << \
					CS42L42_FSYNC_PULSE_WIDTH_SHIFT)

#define CS42L42_FSYNC_P_LOWER		(CS42L42_PAGE_12 + 0x05)

#define CS42L42_FSYNC_P_UPPER		(CS42L42_PAGE_12 + 0x06)
#define CS42L42_FSYNC_PERIOD_SHIFT	0
#define CS42L42_FSYNC_PERIOD_MASK	(0xff << CS42L42_FSYNC_PERIOD_SHIFT)

#define CS42L42_ASP_CLK_CFG		(CS42L42_PAGE_12 + 0x07)
#define CS42L42_ASP_SCLK_EN_SHIFT	5
#define CS42L42_ASP_SCLK_EN_MASK	(1 << CS42L42_ASP_SCLK_EN_SHIFT)
#define CS42L42_ASP_MASTER_MODE		0x01
#define CS42L42_ASP_SLAVE_MODE		0x00
#define CS42L42_ASP_MODE_SHIFT		4
#define CS42L42_ASP_MODE_MASK		(1 << CS42L42_ASP_MODE_SHIFT)
#define CS42L42_ASP_SCPOL_SHIFT		2
#define CS42L42_ASP_SCPOL_MASK		(3 << CS42L42_ASP_SCPOL_SHIFT)
#define CS42L42_ASP_SCPOL_NOR		3
#define CS42L42_ASP_LCPOL_SHIFT		0
#define CS42L42_ASP_LCPOL_MASK		(3 << CS42L42_ASP_LCPOL_SHIFT)
#define CS42L42_ASP_LCPOL_INV		3

#define CS42L42_ASP_FRM_CFG		(CS42L42_PAGE_12 + 0x08)
#define CS42L42_ASP_STP_SHIFT		4
#define CS42L42_ASP_STP_MASK		(1 << CS42L42_ASP_STP_SHIFT)
#define CS42L42_ASP_5050_SHIFT		3
#define CS42L42_ASP_5050_MASK		(1 << CS42L42_ASP_5050_SHIFT)
#define CS42L42_ASP_FSD_SHIFT		0
#define CS42L42_ASP_FSD_MASK		(7 << CS42L42_ASP_FSD_SHIFT)
#define CS42L42_ASP_FSD_0_5		1
#define CS42L42_ASP_FSD_1_0		2
#define CS42L42_ASP_FSD_1_5		3
#define CS42L42_ASP_FSD_2_0		4

#define CS42L42_FS_RATE_EN		(CS42L42_PAGE_12 + 0x09)
#define CS42L42_FS_EN_SHIFT		0
#define CS42L42_FS_EN_MASK		(0xf << CS42L42_FS_EN_SHIFT)
#define CS42L42_FS_EN_IASRC_96K		0x1
#define CS42L42_FS_EN_OASRC_96K		0x2

#define CS42L42_IN_ASRC_CLK		(CS42L42_PAGE_12 + 0x0A)
#define CS42L42_CLK_IASRC_SEL_SHIFT	0
#define CS42L42_CLK_IASRC_SEL_MASK	(1 << CS42L42_CLK_IASRC_SEL_SHIFT)
#define CS42L42_CLK_IASRC_SEL_6		0
#define CS42L42_CLK_IASRC_SEL_12	1

#define CS42L42_OUT_ASRC_CLK		(CS42L42_PAGE_12 + 0x0B)
#define CS42L42_CLK_OASRC_SEL_SHIFT	0
#define CS42L42_CLK_OASRC_SEL_MASK	(1 << CS42L42_CLK_OASRC_SEL_SHIFT)
#define CS42L42_CLK_OASRC_SEL_12	1

#define CS42L42_PLL_DIV_CFG1		(CS42L42_PAGE_12 + 0x0C)
#define CS42L42_SCLK_PREDIV_SHIFT	0
#define CS42L42_SCLK_PREDIV_MASK	(3 << CS42L42_SCLK_PREDIV_SHIFT)

/* Page 0x13 Interrupt Registers */
/* Interrupts */
#define CS42L42_ADC_OVFL_STATUS		(CS42L42_PAGE_13 + 0x01)
#define CS42L42_MIXER_STATUS		(CS42L42_PAGE_13 + 0x02)
#define CS42L42_SRC_STATUS		(CS42L42_PAGE_13 + 0x03)
#define CS42L42_ASP_RX_STATUS		(CS42L42_PAGE_13 + 0x04)
#define CS42L42_ASP_TX_STATUS		(CS42L42_PAGE_13 + 0x05)
#define CS42L42_CODEC_STATUS		(CS42L42_PAGE_13 + 0x08)
#define CS42L42_DET_INT_STATUS1		(CS42L42_PAGE_13 + 0x09)
#define CS42L42_DET_INT_STATUS2		(CS42L42_PAGE_13 + 0x0A)
#define CS42L42_SRCPL_INT_STATUS	(CS42L42_PAGE_13 + 0x0B)
#define CS42L42_VPMON_STATUS		(CS42L42_PAGE_13 + 0x0D)
#define CS42L42_PLL_LOCK_STATUS		(CS42L42_PAGE_13 + 0x0E)
#define CS42L42_TSRS_PLUG_STATUS	(CS42L42_PAGE_13 + 0x0F)
/* Masks */
#define CS42L42_ADC_OVFL_INT_MASK	(CS42L42_PAGE_13 + 0x16)
#define CS42L42_ADC_OVFL_SHIFT		0
#define CS42L42_ADC_OVFL_MASK		(1 << CS42L42_ADC_OVFL_SHIFT)
#define CS42L42_ADC_OVFL_VAL_MASK	CS42L42_ADC_OVFL_MASK

#define CS42L42_MIXER_INT_MASK		(CS42L42_PAGE_13 + 0x17)
#define CS42L42_MIX_CHB_OVFL_SHIFT	0
#define CS42L42_MIX_CHB_OVFL_MASK	(1 << CS42L42_MIX_CHB_OVFL_SHIFT)
#define CS42L42_MIX_CHA_OVFL_SHIFT	1
#define CS42L42_MIX_CHA_OVFL_MASK	(1 << CS42L42_MIX_CHA_OVFL_SHIFT)
#define CS42L42_EQ_OVFL_SHIFT		2
#define CS42L42_EQ_OVFL_MASK		(1 << CS42L42_EQ_OVFL_SHIFT)
#define CS42L42_EQ_BIQUAD_OVFL_SHIFT	3
#define CS42L42_EQ_BIQUAD_OVFL_MASK	(1 << CS42L42_EQ_BIQUAD_OVFL_SHIFT)
#define CS42L42_MIXER_VAL_MASK		(CS42L42_MIX_CHB_OVFL_MASK | \
					CS42L42_MIX_CHA_OVFL_MASK | \
					CS42L42_EQ_OVFL_MASK | \
					CS42L42_EQ_BIQUAD_OVFL_MASK)

#define CS42L42_SRC_INT_MASK		(CS42L42_PAGE_13 + 0x18)
#define CS42L42_SRC_ILK_SHIFT		0
#define CS42L42_SRC_ILK_MASK		(1 << CS42L42_SRC_ILK_SHIFT)
#define CS42L42_SRC_OLK_SHIFT		1
#define CS42L42_SRC_OLK_MASK		(1 << CS42L42_SRC_OLK_SHIFT)
#define CS42L42_SRC_IUNLK_SHIFT		2
#define CS42L42_SRC_IUNLK_MASK		(1 << CS42L42_SRC_IUNLK_SHIFT)
#define CS42L42_SRC_OUNLK_SHIFT		3
#define CS42L42_SRC_OUNLK_MASK		(1 << CS42L42_SRC_OUNLK_SHIFT)
#define CS42L42_SRC_VAL_MASK		(CS42L42_SRC_ILK_MASK | \
					CS42L42_SRC_OLK_MASK | \
					CS42L42_SRC_IUNLK_MASK | \
					CS42L42_SRC_OUNLK_MASK)

#define CS42L42_ASP_RX_INT_MASK		(CS42L42_PAGE_13 + 0x19)
#define CS42L42_ASPRX_NOLRCK_SHIFT	0
#define CS42L42_ASPRX_NOLRCK_MASK	(1 << CS42L42_ASPRX_NOLRCK_SHIFT)
#define CS42L42_ASPRX_EARLY_SHIFT	1
#define CS42L42_ASPRX_EARLY_MASK	(1 << CS42L42_ASPRX_EARLY_SHIFT)
#define CS42L42_ASPRX_LATE_SHIFT	2
#define CS42L42_ASPRX_LATE_MASK		(1 << CS42L42_ASPRX_LATE_SHIFT)
#define CS42L42_ASPRX_ERROR_SHIFT	3
#define CS42L42_ASPRX_ERROR_MASK	(1 << CS42L42_ASPRX_ERROR_SHIFT)
#define CS42L42_ASPRX_OVLD_SHIFT	4
#define CS42L42_ASPRX_OVLD_MASK		(1 << CS42L42_ASPRX_OVLD_SHIFT)
#define CS42L42_ASP_RX_VAL_MASK		(CS42L42_ASPRX_NOLRCK_MASK | \
					CS42L42_ASPRX_EARLY_MASK | \
					CS42L42_ASPRX_LATE_MASK | \
					CS42L42_ASPRX_ERROR_MASK | \
					CS42L42_ASPRX_OVLD_MASK)

#define CS42L42_ASP_TX_INT_MASK		(CS42L42_PAGE_13 + 0x1A)
#define CS42L42_ASPTX_NOLRCK_SHIFT	0
#define CS42L42_ASPTX_NOLRCK_MASK	(1 << CS42L42_ASPTX_NOLRCK_SHIFT)
#define CS42L42_ASPTX_EARLY_SHIFT	1
#define CS42L42_ASPTX_EARLY_MASK	(1 << CS42L42_ASPTX_EARLY_SHIFT)
#define CS42L42_ASPTX_LATE_SHIFT	2
#define CS42L42_ASPTX_LATE_MASK		(1 << CS42L42_ASPTX_LATE_SHIFT)
#define CS42L42_ASPTX_SMERROR_SHIFT	3
#define CS42L42_ASPTX_SMERROR_MASK	(1 << CS42L42_ASPTX_SMERROR_SHIFT)
#define CS42L42_ASP_TX_VAL_MASK		(CS42L42_ASPTX_NOLRCK_MASK | \
					CS42L42_ASPTX_EARLY_MASK | \
					CS42L42_ASPTX_LATE_MASK | \
					CS42L42_ASPTX_SMERROR_MASK)

#define CS42L42_CODEC_INT_MASK		(CS42L42_PAGE_13 + 0x1B)
#define CS42L42_PDN_DONE_SHIFT		0
#define CS42L42_PDN_DONE_MASK		(1 << CS42L42_PDN_DONE_SHIFT)
#define CS42L42_HSDET_AUTO_DONE_SHIFT	1
#define CS42L42_HSDET_AUTO_DONE_MASK	(1 << CS42L42_HSDET_AUTO_DONE_SHIFT)
#define CS42L42_CODEC_VAL_MASK		(CS42L42_PDN_DONE_MASK | \
					CS42L42_HSDET_AUTO_DONE_MASK)

#define CS42L42_SRCPL_INT_MASK		(CS42L42_PAGE_13 + 0x1C)
#define CS42L42_SRCPL_ADC_LK_SHIFT	0
#define CS42L42_SRCPL_ADC_LK_MASK	(1 << CS42L42_SRCPL_ADC_LK_SHIFT)
#define CS42L42_SRCPL_DAC_LK_SHIFT	2
#define CS42L42_SRCPL_DAC_LK_MASK	(1 << CS42L42_SRCPL_DAC_LK_SHIFT)
#define CS42L42_SRCPL_ADC_UNLK_SHIFT	5
#define CS42L42_SRCPL_ADC_UNLK_MASK	(1 << CS42L42_SRCPL_ADC_UNLK_SHIFT)
#define CS42L42_SRCPL_DAC_UNLK_SHIFT	6
#define CS42L42_SRCPL_DAC_UNLK_MASK	(1 << CS42L42_SRCPL_DAC_UNLK_SHIFT)
#define CS42L42_SRCPL_VAL_MASK		(CS42L42_SRCPL_ADC_LK_MASK | \
					CS42L42_SRCPL_DAC_LK_MASK | \
					CS42L42_SRCPL_ADC_UNLK_MASK | \
					CS42L42_SRCPL_DAC_UNLK_MASK)

#define CS42L42_VPMON_INT_MASK		(CS42L42_PAGE_13 + 0x1E)
#define CS42L42_VPMON_SHIFT		0
#define CS42L42_VPMON_MASK		(1 << CS42L42_VPMON_SHIFT)
#define CS42L42_VPMON_VAL_MASK		CS42L42_VPMON_MASK

#define CS42L42_PLL_LOCK_INT_MASK	(CS42L42_PAGE_13 + 0x1F)
#define CS42L42_PLL_LOCK_SHIFT		0
#define CS42L42_PLL_LOCK_MASK		(1 << CS42L42_PLL_LOCK_SHIFT)
#define CS42L42_PLL_LOCK_VAL_MASK	CS42L42_PLL_LOCK_MASK

#define CS42L42_TSRS_PLUG_INT_MASK	(CS42L42_PAGE_13 + 0x20)
#define CS42L42_RS_PLUG_SHIFT		0
#define CS42L42_RS_PLUG_MASK		(1 << CS42L42_RS_PLUG_SHIFT)
#define CS42L42_RS_UNPLUG_SHIFT		1
#define CS42L42_RS_UNPLUG_MASK		(1 << CS42L42_RS_UNPLUG_SHIFT)
#define CS42L42_TS_PLUG_SHIFT		2
#define CS42L42_TS_PLUG_MASK		(1 << CS42L42_TS_PLUG_SHIFT)
#define CS42L42_TS_UNPLUG_SHIFT		3
#define CS42L42_TS_UNPLUG_MASK		(1 << CS42L42_TS_UNPLUG_SHIFT)
#define CS42L42_TSRS_PLUG_VAL_MASK	(CS42L42_RS_PLUG_MASK | \
					CS42L42_RS_UNPLUG_MASK | \
					CS42L42_TS_PLUG_MASK | \
					CS42L42_TS_UNPLUG_MASK)
#define CS42L42_TS_PLUG			3
#define CS42L42_TS_UNPLUG		0
#define CS42L42_TS_TRANS		1

/*
 * NOTE: PLL_START must be 0 while both ADC_PDN=1 and HP_PDN=1.
 * Otherwise it will prevent FILT+ from charging properly.
 */
#define CS42L42_PLL_CTL1		(CS42L42_PAGE_15 + 0x01)
#define CS42L42_PLL_START_SHIFT		0
#define CS42L42_PLL_START_MASK		(1 << CS42L42_PLL_START_SHIFT)

#define CS42L42_PLL_DIV_FRAC0		(CS42L42_PAGE_15 + 0x02)
#define CS42L42_PLL_DIV_FRAC_SHIFT	0
#define CS42L42_PLL_DIV_FRAC_MASK	(0xff << CS42L42_PLL_DIV_FRAC_SHIFT)

#define CS42L42_PLL_DIV_FRAC1		(CS42L42_PAGE_15 + 0x03)
#define CS42L42_PLL_DIV_FRAC2		(CS42L42_PAGE_15 + 0x04)

#define CS42L42_PLL_DIV_INT		(CS42L42_PAGE_15 + 0x05)
#define CS42L42_PLL_DIV_INT_SHIFT	0
#define CS42L42_PLL_DIV_INT_MASK	(0xff << CS42L42_PLL_DIV_INT_SHIFT)

#define CS42L42_PLL_CTL3		(CS42L42_PAGE_15 + 0x08)
#define CS42L42_PLL_DIVOUT_SHIFT	0
#define CS42L42_PLL_DIVOUT_MASK		(0xff << CS42L42_PLL_DIVOUT_SHIFT)

#define CS42L42_PLL_CAL_RATIO		(CS42L42_PAGE_15 + 0x0A)
#define CS42L42_PLL_CAL_RATIO_SHIFT	0
#define CS42L42_PLL_CAL_RATIO_MASK	(0xff << CS42L42_PLL_CAL_RATIO_SHIFT)

#define CS42L42_PLL_CTL4		(CS42L42_PAGE_15 + 0x1B)
#define CS42L42_PLL_MODE_SHIFT		0
#define CS42L42_PLL_MODE_MASK		(3 << CS42L42_PLL_MODE_SHIFT)

/* Page 0x19 HP Load Detect Registers */
#define CS42L42_LOAD_DET_RCSTAT		(CS42L42_PAGE_19 + 0x25)
#define CS42L42_RLA_STAT_SHIFT		0
#define CS42L42_RLA_STAT_MASK		(3 << CS42L42_RLA_STAT_SHIFT)
#define CS42L42_RLA_STAT_15_OHM		0

#define CS42L42_LOAD_DET_DONE		(CS42L42_PAGE_19 + 0x26)
#define CS42L42_HPLOAD_DET_DONE_SHIFT	0
#define CS42L42_HPLOAD_DET_DONE_MASK	(1 << CS42L42_HPLOAD_DET_DONE_SHIFT)

#define CS42L42_LOAD_DET_EN		(CS42L42_PAGE_19 + 0x27)
#define CS42L42_HP_LD_EN_SHIFT		0
#define CS42L42_HP_LD_EN_MASK		(1 << CS42L42_HP_LD_EN_SHIFT)

/* Page 0x1B Headset Interface Registers */
#define CS42L42_HSBIAS_SC_AUTOCTL		(CS42L42_PAGE_1B + 0x70)
#define CS42L42_HSBIAS_SENSE_TRIP_SHIFT		0
#define CS42L42_HSBIAS_SENSE_TRIP_MASK		(7 << CS42L42_HSBIAS_SENSE_TRIP_SHIFT)
#define CS42L42_TIP_SENSE_EN_SHIFT		5
#define CS42L42_TIP_SENSE_EN_MASK		(1 << CS42L42_TIP_SENSE_EN_SHIFT)
#define CS42L42_AUTO_HSBIAS_HIZ_SHIFT		6
#define CS42L42_AUTO_HSBIAS_HIZ_MASK		(1 << CS42L42_AUTO_HSBIAS_HIZ_SHIFT)
#define CS42L42_HSBIAS_SENSE_EN_SHIFT		7
#define CS42L42_HSBIAS_SENSE_EN_MASK		(1 << CS42L42_HSBIAS_SENSE_EN_SHIFT)

#define CS42L42_WAKE_CTL		(CS42L42_PAGE_1B + 0x71)
#define CS42L42_WAKEB_CLEAR_SHIFT	0
#define CS42L42_WAKEB_CLEAR_MASK	(1 << CS42L42_WAKEB_CLEAR_SHIFT)
#define CS42L42_WAKEB_MODE_SHIFT	5
#define CS42L42_WAKEB_MODE_MASK		(1 << CS42L42_WAKEB_MODE_SHIFT)
#define CS42L42_M_HP_WAKE_SHIFT		6
#define CS42L42_M_HP_WAKE_MASK		(1 << CS42L42_M_HP_WAKE_SHIFT)
#define CS42L42_M_MIC_WAKE_SHIFT	7
#define CS42L42_M_MIC_WAKE_MASK		(1 << CS42L42_M_MIC_WAKE_SHIFT)

#define CS42L42_ADC_DISABLE_MUTE		(CS42L42_PAGE_1B + 0x72)
#define CS42L42_ADC_DISABLE_S0_MUTE_SHIFT	7
#define CS42L42_ADC_DISABLE_S0_MUTE_MASK	(1 << CS42L42_ADC_DISABLE_S0_MUTE_SHIFT)

#define CS42L42_TIPSENSE_CTL			(CS42L42_PAGE_1B + 0x73)
#define CS42L42_TIP_SENSE_DEBOUNCE_SHIFT	0
#define CS42L42_TIP_SENSE_DEBOUNCE_MASK		(3 << CS42L42_TIP_SENSE_DEBOUNCE_SHIFT)
#define CS42L42_TIP_SENSE_INV_SHIFT		5
#define CS42L42_TIP_SENSE_INV_MASK		(1 << CS42L42_TIP_SENSE_INV_SHIFT)
#define CS42L42_TIP_SENSE_CTRL_SHIFT		6
#define CS42L42_TIP_SENSE_CTRL_MASK		(3 << CS42L42_TIP_SENSE_CTRL_SHIFT)

/*
 * NOTE: DETECT_MODE must be 0 while both ADC_PDN=1 and HP_PDN=1.
 * Otherwise it will prevent FILT+ from charging properly.
 */
#define CS42L42_MISC_DET_CTL		(CS42L42_PAGE_1B + 0x74)
#define CS42L42_PDN_MIC_LVL_DET_SHIFT	0
#define CS42L42_PDN_MIC_LVL_DET_MASK	(1 << CS42L42_PDN_MIC_LVL_DET_SHIFT)
#define CS42L42_HSBIAS_CTL_SHIFT	1
#define CS42L42_HSBIAS_CTL_MASK		(3 << CS42L42_HSBIAS_CTL_SHIFT)
#define CS42L42_DETECT_MODE_SHIFT	3
#define CS42L42_DETECT_MODE_MASK	(3 << CS42L42_DETECT_MODE_SHIFT)

#define CS42L42_MIC_DET_CTL1		(CS42L42_PAGE_1B + 0x75)
#define CS42L42_HS_DET_LEVEL_SHIFT	0
#define CS42L42_HS_DET_LEVEL_MASK	(0x3F << CS42L42_HS_DET_LEVEL_SHIFT)
#define CS42L42_EVENT_STAT_SEL_SHIFT	6
#define CS42L42_EVENT_STAT_SEL_MASK	(1 << CS42L42_EVENT_STAT_SEL_SHIFT)
#define CS42L42_LATCH_TO_VP_SHIFT	7
#define CS42L42_LATCH_TO_VP_MASK	(1 << CS42L42_LATCH_TO_VP_SHIFT)

#define CS42L42_MIC_DET_CTL2		(CS42L42_PAGE_1B + 0x76)
#define CS42L42_DEBOUNCE_TIME_SHIFT	5
#define CS42L42_DEBOUNCE_TIME_MASK	(0x07 << CS42L42_DEBOUNCE_TIME_SHIFT)

#define CS42L42_DET_STATUS1		(CS42L42_PAGE_1B + 0x77)
#define CS42L42_HSBIAS_HIZ_MODE_SHIFT	6
#define CS42L42_HSBIAS_HIZ_MODE_MASK	(1 << CS42L42_HSBIAS_HIZ_MODE_SHIFT)
#define CS42L42_TIP_SENSE_SHIFT		7
#define CS42L42_TIP_SENSE_MASK		(1 << CS42L42_TIP_SENSE_SHIFT)

#define CS42L42_DET_STATUS2		(CS42L42_PAGE_1B + 0x78)
#define CS42L42_SHORT_TRUE_SHIFT	0
#define CS42L42_SHORT_TRUE_MASK		(1 << CS42L42_SHORT_TRUE_SHIFT)
#define CS42L42_HS_TRUE_SHIFT	1
#define CS42L42_HS_TRUE_MASK		(1 << CS42L42_HS_TRUE_SHIFT)

#define CS42L42_DET_INT1_MASK		(CS42L42_PAGE_1B + 0x79)
#define CS42L42_TIP_SENSE_UNPLUG_SHIFT	5
#define CS42L42_TIP_SENSE_UNPLUG_MASK	(1 << CS42L42_TIP_SENSE_UNPLUG_SHIFT)
#define CS42L42_TIP_SENSE_PLUG_SHIFT	6
#define CS42L42_TIP_SENSE_PLUG_MASK	(1 << CS42L42_TIP_SENSE_PLUG_SHIFT)
#define CS42L42_HSBIAS_SENSE_SHIFT	7
#define CS42L42_HSBIAS_SENSE_MASK	(1 << CS42L42_HSBIAS_SENSE_SHIFT)
#define CS42L42_DET_INT_VAL1_MASK	(CS42L42_TIP_SENSE_UNPLUG_MASK | \
					CS42L42_TIP_SENSE_PLUG_MASK | \
					CS42L42_HSBIAS_SENSE_MASK)

#define CS42L42_DET_INT2_MASK		(CS42L42_PAGE_1B + 0x7A)
#define CS42L42_M_SHORT_DET_SHIFT	0
#define CS42L42_M_SHORT_DET_MASK	(1 << CS42L42_M_SHORT_DET_SHIFT)
#define CS42L42_M_SHORT_RLS_SHIFT	1
#define CS42L42_M_SHORT_RLS_MASK	(1 << CS42L42_M_SHORT_RLS_SHIFT)
#define CS42L42_M_HSBIAS_HIZ_SHIFT	2
#define CS42L42_M_HSBIAS_HIZ_MASK	(1 << CS42L42_M_HSBIAS_HIZ_SHIFT)
#define CS42L42_M_DETECT_FT_SHIFT	6
#define CS42L42_M_DETECT_FT_MASK	(1 << CS42L42_M_DETECT_FT_SHIFT)
#define CS42L42_M_DETECT_TF_SHIFT	7
#define CS42L42_M_DETECT_TF_MASK	(1 << CS42L42_M_DETECT_TF_SHIFT)
#define CS42L42_DET_INT_VAL2_MASK	(CS42L42_M_SHORT_DET_MASK | \
					CS42L42_M_SHORT_RLS_MASK | \
					CS42L42_M_HSBIAS_HIZ_MASK | \
					CS42L42_M_DETECT_FT_MASK | \
					CS42L42_M_DETECT_TF_MASK)

/* Page 0x1C Headset Bias Registers */
#define CS42L42_HS_BIAS_CTL		(CS42L42_PAGE_1C + 0x03)
#define CS42L42_HSBIAS_RAMP_SHIFT	0
#define CS42L42_HSBIAS_RAMP_MASK	(3 << CS42L42_HSBIAS_RAMP_SHIFT)
#define CS42L42_HSBIAS_PD_SHIFT		4
#define CS42L42_HSBIAS_PD_MASK		(1 << CS42L42_HSBIAS_PD_SHIFT)
#define CS42L42_HSBIAS_CAPLESS_SHIFT	7
#define CS42L42_HSBIAS_CAPLESS_MASK	(1 << CS42L42_HSBIAS_CAPLESS_SHIFT)

/* Page 0x1D ADC Registers */
#define CS42L42_ADC_CTL			(CS42L42_PAGE_1D + 0x01)
#define CS42L42_ADC_NOTCH_DIS_SHIFT		5
#define CS42L42_ADC_FORCE_WEAK_VCM_SHIFT	4
#define CS42L42_ADC_INV_SHIFT			2
#define CS42L42_ADC_DIG_BOOST_SHIFT		0

#define CS42L42_ADC_VOLUME		(CS42L42_PAGE_1D + 0x03)
#define CS42L42_ADC_VOL_SHIFT		0

#define CS42L42_ADC_WNF_HPF_CTL		(CS42L42_PAGE_1D + 0x04)
#define CS42L42_ADC_WNF_CF_SHIFT	4
#define CS42L42_ADC_WNF_EN_SHIFT	3
#define CS42L42_ADC_HPF_CF_SHIFT	1
#define CS42L42_ADC_HPF_EN_SHIFT	0

/* Page 0x1F DAC Registers */
#define CS42L42_DAC_CTL1		(CS42L42_PAGE_1F + 0x01)
#define CS42L42_DACB_INV_SHIFT		1
#define CS42L42_DACA_INV_SHIFT		0

#define CS42L42_DAC_CTL2		(CS42L42_PAGE_1F + 0x06)
#define CS42L42_HPOUT_PULLDOWN_SHIFT	4
#define CS42L42_HPOUT_PULLDOWN_MASK	(15 << CS42L42_HPOUT_PULLDOWN_SHIFT)
#define CS42L42_HPOUT_LOAD_SHIFT	3
#define CS42L42_HPOUT_LOAD_MASK		(1 << CS42L42_HPOUT_LOAD_SHIFT)
#define CS42L42_HPOUT_CLAMP_SHIFT	2
#define CS42L42_HPOUT_CLAMP_MASK	(1 << CS42L42_HPOUT_CLAMP_SHIFT)
#define CS42L42_DAC_HPF_EN_SHIFT	1
#define CS42L42_DAC_HPF_EN_MASK		(1 << CS42L42_DAC_HPF_EN_SHIFT)
#define CS42L42_DAC_MON_EN_SHIFT	0
#define CS42L42_DAC_MON_EN_MASK		(1 << CS42L42_DAC_MON_EN_SHIFT)

/* Page 0x20 HP CTL Registers */
#define CS42L42_HP_CTL			(CS42L42_PAGE_20 + 0x01)
#define CS42L42_HP_ANA_BMUTE_SHIFT	3
#define CS42L42_HP_ANA_BMUTE_MASK	(1 << CS42L42_HP_ANA_BMUTE_SHIFT)
#define CS42L42_HP_ANA_AMUTE_SHIFT	2
#define CS42L42_HP_ANA_AMUTE_MASK	(1 << CS42L42_HP_ANA_AMUTE_SHIFT)
#define CS42L42_HP_FULL_SCALE_VOL_SHIFT	1
#define CS42L42_HP_FULL_SCALE_VOL_MASK	(1 << CS42L42_HP_FULL_SCALE_VOL_SHIFT)

/* Page 0x21 Class H Registers */
#define CS42L42_CLASSH_CTL		(CS42L42_PAGE_21 + 0x01)

/* Page 0x23 Mixer Volume Registers */
#define CS42L42_MIXER_CHA_VOL		(CS42L42_PAGE_23 + 0x01)
#define CS42L42_MIXER_ADC_VOL		(CS42L42_PAGE_23 + 0x02)

#define CS42L42_MIXER_CHB_VOL		(CS42L42_PAGE_23 + 0x03)
#define CS42L42_MIXER_CH_VOL_SHIFT	0
#define CS42L42_MIXER_CH_VOL_MASK	(0x3f << CS42L42_MIXER_CH_VOL_SHIFT)

/* Page 0x24 EQ Registers */
#define CS42L42_EQ_COEF_IN0		(CS42L42_PAGE_24 + 0x01)
#define CS42L42_EQ_COEF_IN1		(CS42L42_PAGE_24 + 0x02)
#define CS42L42_EQ_COEF_IN2		(CS42L42_PAGE_24 + 0x03)
#define CS42L42_EQ_COEF_IN3		(CS42L42_PAGE_24 + 0x04)
#define CS42L42_EQ_COEF_RW		(CS42L42_PAGE_24 + 0x06)
#define CS42L42_EQ_COEF_OUT0		(CS42L42_PAGE_24 + 0x07)
#define CS42L42_EQ_COEF_OUT1		(CS42L42_PAGE_24 + 0x08)
#define CS42L42_EQ_COEF_OUT2		(CS42L42_PAGE_24 + 0x09)
#define CS42L42_EQ_COEF_OUT3		(CS42L42_PAGE_24 + 0x0A)
#define CS42L42_EQ_INIT_STAT		(CS42L42_PAGE_24 + 0x0B)
#define CS42L42_EQ_START_FILT		(CS42L42_PAGE_24 + 0x0C)
#define CS42L42_EQ_MUTE_CTL		(CS42L42_PAGE_24 + 0x0E)

/* Page 0x25 Audio Port Registers */
#define CS42L42_SP_RX_CH_SEL		(CS42L42_PAGE_25 + 0x01)
#define CS42L42_SP_RX_CHB_SEL_SHIFT	2
#define CS42L42_SP_RX_CHB_SEL_MASK	(3 << CS42L42_SP_RX_CHB_SEL_SHIFT)

#define CS42L42_SP_RX_ISOC_CTL		(CS42L42_PAGE_25 + 0x02)
#define CS42L42_SP_RX_RSYNC_SHIFT	6
#define CS42L42_SP_RX_RSYNC_MASK	(1 << CS42L42_SP_RX_RSYNC_SHIFT)
#define CS42L42_SP_RX_NSB_POS_SHIFT	3
#define CS42L42_SP_RX_NSB_POS_MASK	(7 << CS42L42_SP_RX_NSB_POS_SHIFT)
#define CS42L42_SP_RX_NFS_NSBB_SHIFT	2
#define CS42L42_SP_RX_NFS_NSBB_MASK	(1 << CS42L42_SP_RX_NFS_NSBB_SHIFT)
#define CS42L42_SP_RX_ISOC_MODE_SHIFT	0
#define CS42L42_SP_RX_ISOC_MODE_MASK	(3 << CS42L42_SP_RX_ISOC_MODE_SHIFT)

#define CS42L42_SP_RX_FS		(CS42L42_PAGE_25 + 0x03)
#define CS42l42_SPDIF_CH_SEL		(CS42L42_PAGE_25 + 0x04)
#define CS42L42_SP_TX_ISOC_CTL		(CS42L42_PAGE_25 + 0x05)
#define CS42L42_SP_TX_FS		(CS42L42_PAGE_25 + 0x06)
#define CS42L42_SPDIF_SW_CTL1		(CS42L42_PAGE_25 + 0x07)

/* Page 0x26 SRC Registers */
#define CS42L42_SRC_SDIN_FS		(CS42L42_PAGE_26 + 0x01)
#define CS42L42_SRC_SDIN_FS_SHIFT	0
#define CS42L42_SRC_SDIN_FS_MASK	(0x1f << CS42L42_SRC_SDIN_FS_SHIFT)

#define CS42L42_SRC_SDOUT_FS		(CS42L42_PAGE_26 + 0x09)

/* Page 0x28 S/PDIF Registers */
#define CS42L42_SPDIF_CTL1		(CS42L42_PAGE_28 + 0x01)
#define CS42L42_SPDIF_CTL2		(CS42L42_PAGE_28 + 0x02)
#define CS42L42_SPDIF_CTL3		(CS42L42_PAGE_28 + 0x03)
#define CS42L42_SPDIF_CTL4		(CS42L42_PAGE_28 + 0x04)

/* Page 0x29 Serial Port TX Registers */
#define CS42L42_ASP_TX_SZ_EN		(CS42L42_PAGE_29 + 0x01)
#define CS42L42_ASP_TX_EN_SHIFT		0
#define CS42L42_ASP_TX_CH_EN		(CS42L42_PAGE_29 + 0x02)
#define CS42L42_ASP_TX0_CH2_SHIFT	1
#define CS42L42_ASP_TX0_CH1_SHIFT	0

#define CS42L42_ASP_TX_CH_AP_RES	(CS42L42_PAGE_29 + 0x03)
#define CS42L42_ASP_TX_CH1_AP_SHIFT	7
#define CS42L42_ASP_TX_CH1_AP_MASK	(1 << CS42L42_ASP_TX_CH1_AP_SHIFT)
#define CS42L42_ASP_TX_CH2_AP_SHIFT	6
#define CS42L42_ASP_TX_CH2_AP_MASK	(1 << CS42L42_ASP_TX_CH2_AP_SHIFT)
#define CS42L42_ASP_TX_CH2_RES_SHIFT	2
#define CS42L42_ASP_TX_CH2_RES_MASK	(3 << CS42L42_ASP_TX_CH2_RES_SHIFT)
#define CS42L42_ASP_TX_CH1_RES_SHIFT	0
#define CS42L42_ASP_TX_CH1_RES_MASK	(3 << CS42L42_ASP_TX_CH1_RES_SHIFT)
#define CS42L42_ASP_TX_CH1_BIT_MSB	(CS42L42_PAGE_29 + 0x04)
#define CS42L42_ASP_TX_CH1_BIT_LSB	(CS42L42_PAGE_29 + 0x05)
#define CS42L42_ASP_TX_HIZ_DLY_CFG	(CS42L42_PAGE_29 + 0x06)
#define CS42L42_ASP_TX_CH2_BIT_MSB	(CS42L42_PAGE_29 + 0x0A)
#define CS42L42_ASP_TX_CH2_BIT_LSB	(CS42L42_PAGE_29 + 0x0B)

/* Page 0x2A Serial Port RX Registers */
#define CS42L42_ASP_RX_DAI0_EN		(CS42L42_PAGE_2A + 0x01)
#define CS42L42_ASP_RX0_CH_EN_SHIFT	2
#define CS42L42_ASP_RX0_CH_EN_MASK	(0xf << CS42L42_ASP_RX0_CH_EN_SHIFT)
#define CS42L42_ASP_RX0_CH1_SHIFT	2
#define CS42L42_ASP_RX0_CH2_SHIFT	3
#define CS42L42_ASP_RX0_CH3_SHIFT	4
#define CS42L42_ASP_RX0_CH4_SHIFT	5

#define CS42L42_ASP_RX_DAI0_CH1_AP_RES	(CS42L42_PAGE_2A + 0x02)
#define CS42L42_ASP_RX_DAI0_CH1_BIT_MSB	(CS42L42_PAGE_2A + 0x03)
#define CS42L42_ASP_RX_DAI0_CH1_BIT_LSB	(CS42L42_PAGE_2A + 0x04)
#define CS42L42_ASP_RX_DAI0_CH2_AP_RES	(CS42L42_PAGE_2A + 0x05)
#define CS42L42_ASP_RX_DAI0_CH2_BIT_MSB	(CS42L42_PAGE_2A + 0x06)
#define CS42L42_ASP_RX_DAI0_CH2_BIT_LSB	(CS42L42_PAGE_2A + 0x07)
#define CS42L42_ASP_RX_DAI0_CH3_AP_RES	(CS42L42_PAGE_2A + 0x08)
#define CS42L42_ASP_RX_DAI0_CH3_BIT_MSB	(CS42L42_PAGE_2A + 0x09)
#define CS42L42_ASP_RX_DAI0_CH3_BIT_LSB	(CS42L42_PAGE_2A + 0x0A)
#define CS42L42_ASP_RX_DAI0_CH4_AP_RES	(CS42L42_PAGE_2A + 0x0B)
#define CS42L42_ASP_RX_DAI0_CH4_BIT_MSB	(CS42L42_PAGE_2A + 0x0C)
#define CS42L42_ASP_RX_DAI0_CH4_BIT_LSB	(CS42L42_PAGE_2A + 0x0D)
#define CS42L42_ASP_RX_DAI1_CH1_AP_RES	(CS42L42_PAGE_2A + 0x0E)
#define CS42L42_ASP_RX_DAI1_CH1_BIT_MSB	(CS42L42_PAGE_2A + 0x0F)
#define CS42L42_ASP_RX_DAI1_CH1_BIT_LSB	(CS42L42_PAGE_2A + 0x10)
#define CS42L42_ASP_RX_DAI1_CH2_AP_RES	(CS42L42_PAGE_2A + 0x11)
#define CS42L42_ASP_RX_DAI1_CH2_BIT_MSB	(CS42L42_PAGE_2A + 0x12)
#define CS42L42_ASP_RX_DAI1_CH2_BIT_LSB	(CS42L42_PAGE_2A + 0x13)

#define CS42L42_ASP_RX_CH_AP_SHIFT	6
#define CS42L42_ASP_RX_CH_AP_MASK	(1 << CS42L42_ASP_RX_CH_AP_SHIFT)
#define CS42L42_ASP_RX_CH_AP_LOW	0
#define CS42L42_ASP_RX_CH_AP_HI		1
#define CS42L42_ASP_RX_CH_RES_SHIFT	0
#define CS42L42_ASP_RX_CH_RES_MASK	(3 << CS42L42_ASP_RX_CH_RES_SHIFT)
#define CS42L42_ASP_RX_CH_RES_32	3
#define CS42L42_ASP_RX_CH_RES_16	1
#define CS42L42_ASP_RX_CH_BIT_ST_SHIFT	0
#define CS42L42_ASP_RX_CH_BIT_ST_MASK	(0xff << CS42L42_ASP_RX_CH_BIT_ST_SHIFT)

/* Page 0x30 ID Registers */
#define CS42L42_SUB_REVID		(CS42L42_PAGE_30 + 0x14)
#define CS42L42_MAX_REGISTER		(CS42L42_PAGE_30 + 0x14)

/* Defines for fracturing values spread across multiple registers */
#define CS42L42_FRAC0_VAL(val)	((val) & 0x0000ff)
#define CS42L42_FRAC1_VAL(val)	(((val) & 0x00ff00) >> 8)
#define CS42L42_FRAC2_VAL(val)	(((val) & 0xff0000) >> 16)

#define CS42L42_NUM_SUPPLIES	5
#define CS42L42_BOOT_TIME_US	3000
#define CS42L42_PLL_DIVOUT_TIME_US	800
#define CS42L42_CLOCK_SWITCH_DELAY_US 150
#define CS42L42_PLL_LOCK_POLL_US	250
#define CS42L42_PLL_LOCK_TIMEOUT_US	1250
#define CS42L42_HP_ADC_EN_TIME_US	20000
#define CS42L42_PDN_DONE_POLL_US	1000
#define CS42L42_PDN_DONE_TIMEOUT_US	200000
#define CS42L42_PDN_DONE_TIME_MS	100
#define CS42L42_FILT_DISCHARGE_TIME_MS	46

#endif /* __CS42L42_H */
