/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * ATC2609A PMIC register definitions
 *
 * Copyright (C) 2019 Manivannan Sadhasivam <manivannan.sadhasivam@linaro.org>
 */

#ifndef __LINUX_MFD_ATC260X_ATC2609A_H
#define __LINUX_MFD_ATC260X_ATC2609A_H

enum atc2609a_irq_def {
	ATC2609A_IRQ_AUDIO = 0,
	ATC2609A_IRQ_OV,
	ATC2609A_IRQ_OC,
	ATC2609A_IRQ_OT,
	ATC2609A_IRQ_UV,
	ATC2609A_IRQ_ALARM,
	ATC2609A_IRQ_ONOFF,
	ATC2609A_IRQ_WKUP,
	ATC2609A_IRQ_IR,
	ATC2609A_IRQ_REMCON,
	ATC2609A_IRQ_POWER_IN,
};

/* PMU Registers */
#define ATC2609A_PMU_SYS_CTL0			0x00
#define ATC2609A_PMU_SYS_CTL1			0x01
#define ATC2609A_PMU_SYS_CTL2			0x02
#define ATC2609A_PMU_SYS_CTL3			0x03
#define ATC2609A_PMU_SYS_CTL4			0x04
#define ATC2609A_PMU_SYS_CTL5			0x05
#define ATC2609A_PMU_SYS_CTL6			0x06
#define ATC2609A_PMU_SYS_CTL7			0x07
#define ATC2609A_PMU_SYS_CTL8			0x08
#define ATC2609A_PMU_SYS_CTL9			0x09
#define ATC2609A_PMU_BAT_CTL0			0x0A
#define ATC2609A_PMU_BAT_CTL1			0x0B
#define ATC2609A_PMU_VBUS_CTL0			0x0C
#define ATC2609A_PMU_VBUS_CTL1			0x0D
#define ATC2609A_PMU_WALL_CTL0			0x0E
#define ATC2609A_PMU_WALL_CTL1			0x0F
#define ATC2609A_PMU_SYS_PENDING		0x10
#define ATC2609A_PMU_APDS_CTL0			0x11
#define ATC2609A_PMU_APDS_CTL1			0x12
#define ATC2609A_PMU_APDS_CTL2			0x13
#define ATC2609A_PMU_CHARGER_CTL		0x14
#define ATC2609A_PMU_BAKCHARGER_CTL		0x15
#define ATC2609A_PMU_SWCHG_CTL0			0x16
#define ATC2609A_PMU_SWCHG_CTL1			0x17
#define ATC2609A_PMU_SWCHG_CTL2			0x18
#define ATC2609A_PMU_SWCHG_CTL3			0x19
#define ATC2609A_PMU_SWCHG_CTL4			0x1A
#define ATC2609A_PMU_DC_OSC			0x1B
#define ATC2609A_PMU_DC0_CTL0			0x1C
#define ATC2609A_PMU_DC0_CTL1			0x1D
#define ATC2609A_PMU_DC0_CTL2			0x1E
#define ATC2609A_PMU_DC0_CTL3			0x1F
#define ATC2609A_PMU_DC0_CTL4			0x20
#define ATC2609A_PMU_DC0_CTL5			0x21
#define ATC2609A_PMU_DC0_CTL6			0x22
#define ATC2609A_PMU_DC1_CTL0			0x23
#define ATC2609A_PMU_DC1_CTL1			0x24
#define ATC2609A_PMU_DC1_CTL2			0x25
#define ATC2609A_PMU_DC1_CTL3			0x26
#define ATC2609A_PMU_DC1_CTL4			0x27
#define ATC2609A_PMU_DC1_CTL5			0x28
#define ATC2609A_PMU_DC1_CTL6			0x29
#define ATC2609A_PMU_DC2_CTL0			0x2A
#define ATC2609A_PMU_DC2_CTL1			0x2B
#define ATC2609A_PMU_DC2_CTL2			0x2C
#define ATC2609A_PMU_DC2_CTL3			0x2D
#define ATC2609A_PMU_DC2_CTL4			0x2E
#define ATC2609A_PMU_DC2_CTL5			0x2F
#define ATC2609A_PMU_DC2_CTL6			0x30
#define ATC2609A_PMU_DC3_CTL0			0x31
#define ATC2609A_PMU_DC3_CTL1			0x32
#define ATC2609A_PMU_DC3_CTL2			0x33
#define ATC2609A_PMU_DC3_CTL3			0x34
#define ATC2609A_PMU_DC3_CTL4			0x35
#define ATC2609A_PMU_DC3_CTL5			0x36
#define ATC2609A_PMU_DC3_CTL6			0x37
#define ATC2609A_PMU_DC_ZR			0x38
#define ATC2609A_PMU_LDO0_CTL0			0x39
#define ATC2609A_PMU_LDO0_CTL1			0x3A
#define ATC2609A_PMU_LDO1_CTL0			0x3B
#define ATC2609A_PMU_LDO1_CTL1			0x3C
#define ATC2609A_PMU_LDO2_CTL0			0x3D
#define ATC2609A_PMU_LDO2_CTL1			0x3E
#define ATC2609A_PMU_LDO3_CTL0			0x3F
#define ATC2609A_PMU_LDO3_CTL1			0x40
#define ATC2609A_PMU_LDO4_CTL0			0x41
#define ATC2609A_PMU_LDO4_CTL1			0x42
#define ATC2609A_PMU_LDO5_CTL0			0x43
#define ATC2609A_PMU_LDO5_CTL1			0x44
#define ATC2609A_PMU_LDO6_CTL0			0x45
#define ATC2609A_PMU_LDO6_CTL1			0x46
#define ATC2609A_PMU_LDO7_CTL0			0x47
#define ATC2609A_PMU_LDO7_CTL1			0x48
#define ATC2609A_PMU_LDO8_CTL0			0x49
#define ATC2609A_PMU_LDO8_CTL1			0x4A
#define ATC2609A_PMU_LDO9_CTL			0x4B
#define ATC2609A_PMU_OV_INT_EN			0x4C
#define ATC2609A_PMU_OV_STATUS			0x4D
#define ATC2609A_PMU_UV_INT_EN			0x4E
#define ATC2609A_PMU_UV_STATUS			0x4F
#define ATC2609A_PMU_OC_INT_EN			0x50
#define ATC2609A_PMU_OC_STATUS			0x51
#define ATC2609A_PMU_OT_CTL			0x52
#define ATC2609A_PMU_CM_CTL0			0x53
#define ATC2609A_PMU_FW_USE0			0x54
#define ATC2609A_PMU_FW_USE1			0x55
#define ATC2609A_PMU_ADC12B_I			0x56
#define ATC2609A_PMU_ADC12B_V			0x57
#define ATC2609A_PMU_ADC12B_DUMMY		0x58
#define ATC2609A_PMU_AUXADC_CTL0		0x59
#define ATC2609A_PMU_AUXADC_CTL1		0x5A
#define ATC2609A_PMU_BATVADC			0x5B
#define ATC2609A_PMU_BATIADC			0x5C
#define ATC2609A_PMU_WALLVADC			0x5D
#define ATC2609A_PMU_WALLIADC			0x5E
#define ATC2609A_PMU_VBUSVADC			0x5F
#define ATC2609A_PMU_VBUSIADC			0x60
#define ATC2609A_PMU_SYSPWRADC			0x61
#define ATC2609A_PMU_REMCONADC			0x62
#define ATC2609A_PMU_SVCCADC			0x63
#define ATC2609A_PMU_CHGIADC			0x64
#define ATC2609A_PMU_IREFADC			0x65
#define ATC2609A_PMU_BAKBATADC			0x66
#define ATC2609A_PMU_ICTEMPADC			0x67
#define ATC2609A_PMU_AUXADC0			0x68
#define ATC2609A_PMU_AUXADC1			0x69
#define ATC2609A_PMU_AUXADC2			0x6A
#define ATC2609A_PMU_AUXADC3			0x6B
#define ATC2609A_PMU_ICTEMPADC_ADJ		0x6C
#define ATC2609A_PMU_BDG_CTL			0x6D
#define ATC2609A_RTC_CTL			0x6E
#define ATC2609A_RTC_MSALM			0x6F
#define ATC2609A_RTC_HALM			0x70
#define ATC2609A_RTC_YMDALM			0x71
#define ATC2609A_RTC_MS				0x72
#define ATC2609A_RTC_H				0x73
#define ATC2609A_RTC_DC				0x74
#define ATC2609A_RTC_YMD			0x75
#define ATC2609A_EFUSE_DAT			0x76
#define ATC2609A_EFUSECRTL1			0x77
#define ATC2609A_EFUSECRTL2			0x78
#define ATC2609A_PMU_DC4_CTL0			0x79
#define ATC2609A_PMU_DC4_CTL1			0x7A
#define ATC2609A_PMU_DC4_CTL2			0x7B
#define ATC2609A_PMU_DC4_CTL3			0x7C
#define ATC2609A_PMU_DC4_CTL4			0x7D
#define ATC2609A_PMU_DC4_CTL5			0x7E
#define ATC2609A_PMU_DC4_CTL6			0x7F
#define ATC2609A_PMU_PWR_STATUS			0x80
#define ATC2609A_PMU_S2_PWR			0x81
#define ATC2609A_CLMT_CTL0			0x82
#define ATC2609A_CLMT_DATA0			0x83
#define ATC2609A_CLMT_DATA1			0x84
#define ATC2609A_CLMT_DATA2			0x85
#define ATC2609A_CLMT_DATA3			0x86
#define ATC2609A_CLMT_ADD0			0x87
#define ATC2609A_CLMT_ADD1			0x88
#define ATC2609A_CLMT_OCV_TABLE			0x89
#define ATC2609A_CLMT_R_TABLE			0x8A
#define ATC2609A_PMU_PWRON_CTL0			0x8D
#define ATC2609A_PMU_PWRON_CTL1			0x8E
#define ATC2609A_PMU_PWRON_CTL2			0x8F
#define ATC2609A_IRC_CTL			0x90
#define ATC2609A_IRC_STAT			0x91
#define ATC2609A_IRC_CC				0x92
#define ATC2609A_IRC_KDC			0x93
#define ATC2609A_IRC_WK				0x94
#define ATC2609A_IRC_RCC			0x95

/* AUDIO_OUT Registers */
#define ATC2609A_AUDIOINOUT_CTL			0xA0
#define ATC2609A_AUDIO_DEBUGOUTCTL		0xA1
#define ATC2609A_DAC_DIGITALCTL			0xA2
#define ATC2609A_DAC_VOLUMECTL0			0xA3
#define ATC2609A_DAC_ANALOG0			0xA4
#define ATC2609A_DAC_ANALOG1			0xA5
#define ATC2609A_DAC_ANALOG2			0xA6
#define ATC2609A_DAC_ANALOG3			0xA7

/* AUDIO_IN Registers */
#define ATC2609A_ADC_DIGITALCTL			0xA8
#define ATC2609A_ADC_HPFCTL			0xA9
#define ATC2609A_ADC_CTL			0xAA
#define ATC2609A_AGC_CTL0			0xAB
#define ATC2609A_AGC_CTL1			0xAC
#define ATC2609A_AGC_CTL2			0xAD
#define ATC2609A_ADC_ANALOG0			0xAE
#define ATC2609A_ADC_ANALOG1			0xAF

/* PCM_IF Registers */
#define ATC2609A_PCM0_CTL			0xB0
#define ATC2609A_PCM1_CTL			0xB1
#define ATC2609A_PCM2_CTL			0xB2
#define ATC2609A_PCMIF_CTL			0xB3

/* CMU_CONTROL Registers */
#define ATC2609A_CMU_DEVRST			0xC1

/* INTS Registers */
#define ATC2609A_INTS_PD			0xC8
#define ATC2609A_INTS_MSK			0xC9

/* MFP Registers */
#define ATC2609A_MFP_CTL			0xD0
#define ATC2609A_PAD_VSEL			0xD1
#define ATC2609A_GPIO_OUTEN			0xD2
#define ATC2609A_GPIO_INEN			0xD3
#define ATC2609A_GPIO_DAT			0xD4
#define ATC2609A_PAD_DRV			0xD5
#define ATC2609A_PAD_EN				0xD6
#define ATC2609A_DEBUG_SEL			0xD7
#define ATC2609A_DEBUG_IE			0xD8
#define ATC2609A_DEBUG_OE			0xD9
#define ATC2609A_CHIP_VER			0xDC

/* PWSI Registers */
#define ATC2609A_PWSI_CTL			0xF0
#define ATC2609A_PWSI_STATUS			0xF1

/* TWSI Registers */
#define ATC2609A_SADDR				0xFF

/* PMU_SYS_CTL0 Register Mask Bits */
#define ATC2609A_PMU_SYS_CTL0_IR_WK_EN			BIT(5)
#define ATC2609A_PMU_SYS_CTL0_RESET_WK_EN		BIT(6)
#define ATC2609A_PMU_SYS_CTL0_HDSW_WK_EN		BIT(7)
#define ATC2609A_PMU_SYS_CTL0_ALARM_WK_EN		BIT(8)
#define ATC2609A_PMU_SYS_CTL0_REM_CON_WK_EN		BIT(9)
#define ATC2609A_PMU_SYS_CTL0_RESTART_EN		BIT(10)
#define ATC2609A_PMU_SYS_CTL0_WKIRQ_WK_EN		BIT(11)
#define ATC2609A_PMU_SYS_CTL0_ONOFF_SHORT_WK_EN		BIT(12)
#define ATC2609A_PMU_SYS_CTL0_ONOFF_LONG_WK_EN		BIT(13)
#define ATC2609A_PMU_SYS_CTL0_WALL_WK_EN		BIT(14)
#define ATC2609A_PMU_SYS_CTL0_USB_WK_EN			BIT(15)
#define ATC2609A_PMU_SYS_CTL0_WK_ALL			(GENMASK(15, 5) & (~BIT(10)))

/* PMU_SYS_CTL1 Register Mask Bits */
#define ATC2609A_PMU_SYS_CTL1_EN_S1			BIT(0)
#define ATC2609A_PMU_SYS_CTL1_LB_S4_EN			BIT(2)
#define ATC2609A_PMU_SYS_CTL1_LB_S4			GENMASK(4, 3)
#define ATC2609A_PMU_SYS_CTL1_LB_S4_3_1V		BIT(4)
#define ATC2609A_PMU_SYS_CTL1_IR_WK_FLAG		BIT(5)
#define ATC2609A_PMU_SYS_CTL1_RESET_WK_FLAG		BIT(6)
#define ATC2609A_PMU_SYS_CTL1_HDSW_WK_FLAG		BIT(7)
#define ATC2609A_PMU_SYS_CTL1_ALARM_WK_FLAG		BIT(8)
#define ATC2609A_PMU_SYS_CTL1_REM_CON_WK_FLAG		BIT(9)
#define ATC2609A_PMU_SYS_CTL1_RESTART_WK_FLAG		BIT(10)
#define ATC2609A_PMU_SYS_CTL1_WKIRQ_WK_FLAG		BIT(11)
#define ATC2609A_PMU_SYS_CTL1_ONOFF_SHORT_WK_FLAG	BIT(12)
#define ATC2609A_PMU_SYS_CTL1_ONOFF_LONG_WK_FLAG	BIT(13)
#define ATC2609A_PMU_SYS_CTL1_WALL_WK_FLAG		BIT(14)
#define ATC2609A_PMU_SYS_CTL1_USB_WK_FLAG		BIT(15)

/* PMU_SYS_CTL2 Register Mask Bits */
#define ATC2609A_PMU_SYS_CTL2_PMU_A_EN			BIT(0)
#define ATC2609A_PMU_SYS_CTL2_ONOFF_PRESS_INT_EN	BIT(1)
#define ATC2609A_PMU_SYS_CTL2_ONOFF_PRESS_PD		BIT(2)
#define ATC2609A_PMU_SYS_CTL2_S2TIMER			GENMASK(5, 3)
#define ATC2609A_PMU_SYS_CTL2_S2_TIMER_EN		BIT(6)
#define ATC2609A_PMU_SYS_CTL2_ONOFF_RESET_TIME_SEL	GENMASK(8, 7)
#define ATC2609A_PMU_SYS_CTL2_ONOFF_RESET_EN		BIT(9)
#define ATC2609A_PMU_SYS_CTL2_ONOFF_PRESS_TIME		GENMASK(11, 10)
#define ATC2609A_PMU_SYS_CTL2_ONOFF_LSP_INT_EN		BIT(12)
#define ATC2609A_PMU_SYS_CTL2_ONOFF_LONG_PRESS		BIT(13)
#define ATC2609A_PMU_SYS_CTL2_ONOFF_SHORT_PRESS		BIT(14)
#define ATC2609A_PMU_SYS_CTL2_ONOFF_PRESS		BIT(15)

/* PMU_SYS_CTL3 Register Mask Bits */
#define ATC2609A_PMU_SYS_CTL3_S2S3TOS1_TIMER		GENMASK(8, 7)
#define ATC2609A_PMU_SYS_CTL3_S2S3TOS1_TIMER_EN		BIT(9)
#define ATC2609A_PMU_SYS_CTL3_S3_TIMER			GENMASK(12, 10)
#define ATC2609A_PMU_SYS_CTL3_S3_TIMER_EN		BIT(13)
#define ATC2609A_PMU_SYS_CTL3_EN_S3			BIT(14)
#define ATC2609A_PMU_SYS_CTL3_EN_S2			BIT(15)

/* PMU_SYS_CTL5 Register Mask Bits */
#define ATC2609A_PMU_SYS_CTL5_WALLWKDTEN		BIT(7)
#define ATC2609A_PMU_SYS_CTL5_VBUSWKDTEN		BIT(8)
#define ATC2609A_PMU_SYS_CTL5_REMCON_DECT_EN		BIT(9)
#define ATC2609A_PMU_SYS_CTL5_ONOFF_8S_SEL		BIT(10)

/* INTS_MSK Register Mask Bits */
#define ATC2609A_INTS_MSK_AUDIO				BIT(0)
#define ATC2609A_INTS_MSK_OV				BIT(1)
#define ATC2609A_INTS_MSK_OC				BIT(2)
#define ATC2609A_INTS_MSK_OT				BIT(3)
#define ATC2609A_INTS_MSK_UV				BIT(4)
#define ATC2609A_INTS_MSK_ALARM				BIT(5)
#define ATC2609A_INTS_MSK_ONOFF				BIT(6)
#define ATC2609A_INTS_MSK_WKUP				BIT(7)
#define ATC2609A_INTS_MSK_IR				BIT(8)
#define ATC2609A_INTS_MSK_REMCON			BIT(9)
#define ATC2609A_INTS_MSK_POWERIN			BIT(10)

/* CMU_DEVRST Register Mask Bits */
#define ATC2609A_CMU_DEVRST_AUDIO			BIT(0)
#define ATC2609A_CMU_DEVRST_MFP				BIT(1)
#define ATC2609A_CMU_DEVRST_INTS			BIT(2)

/* PAD_EN Register Mask Bits */
#define ATC2609A_PAD_EN_EXTIRQ				BIT(0)

#endif /* __LINUX_MFD_ATC260X_ATC2609A_H */
