/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * max77686-private.h - Voltage regulator driver for the Maxim 77686/802
 *
 *  Copyright (C) 2012 Samsung Electrnoics
 *  Chiwoong Byun <woong.byun@samsung.com>
 */

#ifndef __LINUX_MFD_MAX77686_PRIV_H
#define __LINUX_MFD_MAX77686_PRIV_H

#include <linux/i2c.h>
#include <linux/regmap.h>
#include <linux/module.h>

#define MAX77686_REG_INVALID		(0xff)

/* MAX77686 PMIC registers */
enum max77686_pmic_reg {
	MAX77686_REG_DEVICE_ID		= 0x00,
	MAX77686_REG_INTSRC		= 0x01,
	MAX77686_REG_INT1		= 0x02,
	MAX77686_REG_INT2		= 0x03,

	MAX77686_REG_INT1MSK		= 0x04,
	MAX77686_REG_INT2MSK		= 0x05,

	MAX77686_REG_STATUS1		= 0x06,
	MAX77686_REG_STATUS2		= 0x07,

	MAX77686_REG_PWRON		= 0x08,
	MAX77686_REG_ONOFF_DELAY	= 0x09,
	MAX77686_REG_MRSTB		= 0x0A,
	/* Reserved: 0x0B-0x0F */

	MAX77686_REG_BUCK1CTRL		= 0x10,
	MAX77686_REG_BUCK1OUT		= 0x11,
	MAX77686_REG_BUCK2CTRL1		= 0x12,
	MAX77686_REG_BUCK234FREQ	= 0x13,
	MAX77686_REG_BUCK2DVS1		= 0x14,
	MAX77686_REG_BUCK2DVS2		= 0x15,
	MAX77686_REG_BUCK2DVS3		= 0x16,
	MAX77686_REG_BUCK2DVS4		= 0x17,
	MAX77686_REG_BUCK2DVS5		= 0x18,
	MAX77686_REG_BUCK2DVS6		= 0x19,
	MAX77686_REG_BUCK2DVS7		= 0x1A,
	MAX77686_REG_BUCK2DVS8		= 0x1B,
	MAX77686_REG_BUCK3CTRL1		= 0x1C,
	/* Reserved: 0x1D */
	MAX77686_REG_BUCK3DVS1		= 0x1E,
	MAX77686_REG_BUCK3DVS2		= 0x1F,
	MAX77686_REG_BUCK3DVS3		= 0x20,
	MAX77686_REG_BUCK3DVS4		= 0x21,
	MAX77686_REG_BUCK3DVS5		= 0x22,
	MAX77686_REG_BUCK3DVS6		= 0x23,
	MAX77686_REG_BUCK3DVS7		= 0x24,
	MAX77686_REG_BUCK3DVS8		= 0x25,
	MAX77686_REG_BUCK4CTRL1		= 0x26,
	/* Reserved: 0x27 */
	MAX77686_REG_BUCK4DVS1		= 0x28,
	MAX77686_REG_BUCK4DVS2		= 0x29,
	MAX77686_REG_BUCK4DVS3		= 0x2A,
	MAX77686_REG_BUCK4DVS4		= 0x2B,
	MAX77686_REG_BUCK4DVS5		= 0x2C,
	MAX77686_REG_BUCK4DVS6		= 0x2D,
	MAX77686_REG_BUCK4DVS7		= 0x2E,
	MAX77686_REG_BUCK4DVS8		= 0x2F,
	MAX77686_REG_BUCK5CTRL		= 0x30,
	MAX77686_REG_BUCK5OUT		= 0x31,
	MAX77686_REG_BUCK6CTRL		= 0x32,
	MAX77686_REG_BUCK6OUT		= 0x33,
	MAX77686_REG_BUCK7CTRL		= 0x34,
	MAX77686_REG_BUCK7OUT		= 0x35,
	MAX77686_REG_BUCK8CTRL		= 0x36,
	MAX77686_REG_BUCK8OUT		= 0x37,
	MAX77686_REG_BUCK9CTRL		= 0x38,
	MAX77686_REG_BUCK9OUT		= 0x39,
	/* Reserved: 0x3A-0x3F */

	MAX77686_REG_LDO1CTRL1		= 0x40,
	MAX77686_REG_LDO2CTRL1		= 0x41,
	MAX77686_REG_LDO3CTRL1		= 0x42,
	MAX77686_REG_LDO4CTRL1		= 0x43,
	MAX77686_REG_LDO5CTRL1		= 0x44,
	MAX77686_REG_LDO6CTRL1		= 0x45,
	MAX77686_REG_LDO7CTRL1		= 0x46,
	MAX77686_REG_LDO8CTRL1		= 0x47,
	MAX77686_REG_LDO9CTRL1		= 0x48,
	MAX77686_REG_LDO10CTRL1		= 0x49,
	MAX77686_REG_LDO11CTRL1		= 0x4A,
	MAX77686_REG_LDO12CTRL1		= 0x4B,
	MAX77686_REG_LDO13CTRL1		= 0x4C,
	MAX77686_REG_LDO14CTRL1		= 0x4D,
	MAX77686_REG_LDO15CTRL1		= 0x4E,
	MAX77686_REG_LDO16CTRL1		= 0x4F,
	MAX77686_REG_LDO17CTRL1		= 0x50,
	MAX77686_REG_LDO18CTRL1		= 0x51,
	MAX77686_REG_LDO19CTRL1		= 0x52,
	MAX77686_REG_LDO20CTRL1		= 0x53,
	MAX77686_REG_LDO21CTRL1		= 0x54,
	MAX77686_REG_LDO22CTRL1		= 0x55,
	MAX77686_REG_LDO23CTRL1		= 0x56,
	MAX77686_REG_LDO24CTRL1		= 0x57,
	MAX77686_REG_LDO25CTRL1		= 0x58,
	MAX77686_REG_LDO26CTRL1		= 0x59,
	/* Reserved: 0x5A-0x5F */
	MAX77686_REG_LDO1CTRL2		= 0x60,
	MAX77686_REG_LDO2CTRL2		= 0x61,
	MAX77686_REG_LDO3CTRL2		= 0x62,
	MAX77686_REG_LDO4CTRL2		= 0x63,
	MAX77686_REG_LDO5CTRL2		= 0x64,
	MAX77686_REG_LDO6CTRL2		= 0x65,
	MAX77686_REG_LDO7CTRL2		= 0x66,
	MAX77686_REG_LDO8CTRL2		= 0x67,
	MAX77686_REG_LDO9CTRL2		= 0x68,
	MAX77686_REG_LDO10CTRL2		= 0x69,
	MAX77686_REG_LDO11CTRL2		= 0x6A,
	MAX77686_REG_LDO12CTRL2		= 0x6B,
	MAX77686_REG_LDO13CTRL2		= 0x6C,
	MAX77686_REG_LDO14CTRL2		= 0x6D,
	MAX77686_REG_LDO15CTRL2		= 0x6E,
	MAX77686_REG_LDO16CTRL2		= 0x6F,
	MAX77686_REG_LDO17CTRL2		= 0x70,
	MAX77686_REG_LDO18CTRL2		= 0x71,
	MAX77686_REG_LDO19CTRL2		= 0x72,
	MAX77686_REG_LDO20CTRL2		= 0x73,
	MAX77686_REG_LDO21CTRL2		= 0x74,
	MAX77686_REG_LDO22CTRL2		= 0x75,
	MAX77686_REG_LDO23CTRL2		= 0x76,
	MAX77686_REG_LDO24CTRL2		= 0x77,
	MAX77686_REG_LDO25CTRL2		= 0x78,
	MAX77686_REG_LDO26CTRL2		= 0x79,
	/* Reserved: 0x7A-0x7D */

	MAX77686_REG_BBAT_CHG		= 0x7E,
	MAX77686_REG_32KHZ			= 0x7F,

	MAX77686_REG_PMIC_END		= 0x80,
};

enum max77686_rtc_reg {
	MAX77686_RTC_INT			= 0x00,
	MAX77686_RTC_INTM			= 0x01,
	MAX77686_RTC_CONTROLM		= 0x02,
	MAX77686_RTC_CONTROL		= 0x03,
	MAX77686_RTC_UPDATE0		= 0x04,
	/* Reserved: 0x5 */
	MAX77686_WTSR_SMPL_CNTL		= 0x06,
	MAX77686_RTC_SEC			= 0x07,
	MAX77686_RTC_MIN			= 0x08,
	MAX77686_RTC_HOUR			= 0x09,
	MAX77686_RTC_WEEKDAY		= 0x0A,
	MAX77686_RTC_MONTH			= 0x0B,
	MAX77686_RTC_YEAR			= 0x0C,
	MAX77686_RTC_DATE			= 0x0D,
	MAX77686_ALARM1_SEC			= 0x0E,
	MAX77686_ALARM1_MIN			= 0x0F,
	MAX77686_ALARM1_HOUR		= 0x10,
	MAX77686_ALARM1_WEEKDAY		= 0x11,
	MAX77686_ALARM1_MONTH		= 0x12,
	MAX77686_ALARM1_YEAR		= 0x13,
	MAX77686_ALARM1_DATE		= 0x14,
	MAX77686_ALARM2_SEC			= 0x15,
	MAX77686_ALARM2_MIN			= 0x16,
	MAX77686_ALARM2_HOUR		= 0x17,
	MAX77686_ALARM2_WEEKDAY		= 0x18,
	MAX77686_ALARM2_MONTH		= 0x19,
	MAX77686_ALARM2_YEAR		= 0x1A,
	MAX77686_ALARM2_DATE		= 0x1B,
};

/* MAX77802 PMIC registers */
enum max77802_pmic_reg {
	MAX77802_REG_DEVICE_ID		= 0x00,
	MAX77802_REG_INTSRC		= 0x01,
	MAX77802_REG_INT1		= 0x02,
	MAX77802_REG_INT2		= 0x03,

	MAX77802_REG_INT1MSK		= 0x04,
	MAX77802_REG_INT2MSK		= 0x05,

	MAX77802_REG_STATUS1		= 0x06,
	MAX77802_REG_STATUS2		= 0x07,

	MAX77802_REG_PWRON		= 0x08,
	/* Reserved: 0x09 */
	MAX77802_REG_MRSTB		= 0x0A,
	MAX77802_REG_EPWRHOLD		= 0x0B,
	/* Reserved: 0x0C-0x0D */
	MAX77802_REG_BOOSTCTRL		= 0x0E,
	MAX77802_REG_BOOSTOUT		= 0x0F,

	MAX77802_REG_BUCK1CTRL		= 0x10,
	MAX77802_REG_BUCK1DVS1		= 0x11,
	MAX77802_REG_BUCK1DVS2		= 0x12,
	MAX77802_REG_BUCK1DVS3		= 0x13,
	MAX77802_REG_BUCK1DVS4		= 0x14,
	MAX77802_REG_BUCK1DVS5		= 0x15,
	MAX77802_REG_BUCK1DVS6		= 0x16,
	MAX77802_REG_BUCK1DVS7		= 0x17,
	MAX77802_REG_BUCK1DVS8		= 0x18,
	/* Reserved: 0x19 */
	MAX77802_REG_BUCK2CTRL1		= 0x1A,
	MAX77802_REG_BUCK2CTRL2		= 0x1B,
	MAX77802_REG_BUCK2PHTRAN	= 0x1C,
	MAX77802_REG_BUCK2DVS1		= 0x1D,
	MAX77802_REG_BUCK2DVS2		= 0x1E,
	MAX77802_REG_BUCK2DVS3		= 0x1F,
	MAX77802_REG_BUCK2DVS4		= 0x20,
	MAX77802_REG_BUCK2DVS5		= 0x21,
	MAX77802_REG_BUCK2DVS6		= 0x22,
	MAX77802_REG_BUCK2DVS7		= 0x23,
	MAX77802_REG_BUCK2DVS8		= 0x24,
	/* Reserved: 0x25-0x26 */
	MAX77802_REG_BUCK3CTRL1		= 0x27,
	MAX77802_REG_BUCK3DVS1		= 0x28,
	MAX77802_REG_BUCK3DVS2		= 0x29,
	MAX77802_REG_BUCK3DVS3		= 0x2A,
	MAX77802_REG_BUCK3DVS4		= 0x2B,
	MAX77802_REG_BUCK3DVS5		= 0x2C,
	MAX77802_REG_BUCK3DVS6		= 0x2D,
	MAX77802_REG_BUCK3DVS7		= 0x2E,
	MAX77802_REG_BUCK3DVS8		= 0x2F,
	/* Reserved: 0x30-0x36 */
	MAX77802_REG_BUCK4CTRL1		= 0x37,
	MAX77802_REG_BUCK4DVS1		= 0x38,
	MAX77802_REG_BUCK4DVS2		= 0x39,
	MAX77802_REG_BUCK4DVS3		= 0x3A,
	MAX77802_REG_BUCK4DVS4		= 0x3B,
	MAX77802_REG_BUCK4DVS5		= 0x3C,
	MAX77802_REG_BUCK4DVS6		= 0x3D,
	MAX77802_REG_BUCK4DVS7		= 0x3E,
	MAX77802_REG_BUCK4DVS8		= 0x3F,
	/* Reserved: 0x40 */
	MAX77802_REG_BUCK5CTRL		= 0x41,
	MAX77802_REG_BUCK5OUT		= 0x42,
	/* Reserved: 0x43 */
	MAX77802_REG_BUCK6CTRL		= 0x44,
	MAX77802_REG_BUCK6DVS1		= 0x45,
	MAX77802_REG_BUCK6DVS2		= 0x46,
	MAX77802_REG_BUCK6DVS3		= 0x47,
	MAX77802_REG_BUCK6DVS4		= 0x48,
	MAX77802_REG_BUCK6DVS5		= 0x49,
	MAX77802_REG_BUCK6DVS6		= 0x4A,
	MAX77802_REG_BUCK6DVS7		= 0x4B,
	MAX77802_REG_BUCK6DVS8		= 0x4C,
	/* Reserved: 0x4D */
	MAX77802_REG_BUCK7CTRL		= 0x4E,
	MAX77802_REG_BUCK7OUT		= 0x4F,
	/* Reserved: 0x50 */
	MAX77802_REG_BUCK8CTRL		= 0x51,
	MAX77802_REG_BUCK8OUT		= 0x52,
	/* Reserved: 0x53 */
	MAX77802_REG_BUCK9CTRL		= 0x54,
	MAX77802_REG_BUCK9OUT		= 0x55,
	/* Reserved: 0x56 */
	MAX77802_REG_BUCK10CTRL		= 0x57,
	MAX77802_REG_BUCK10OUT		= 0x58,

	/* Reserved: 0x59-0x5F */

	MAX77802_REG_LDO1CTRL1		= 0x60,
	MAX77802_REG_LDO2CTRL1		= 0x61,
	MAX77802_REG_LDO3CTRL1		= 0x62,
	MAX77802_REG_LDO4CTRL1		= 0x63,
	MAX77802_REG_LDO5CTRL1		= 0x64,
	MAX77802_REG_LDO6CTRL1		= 0x65,
	MAX77802_REG_LDO7CTRL1		= 0x66,
	MAX77802_REG_LDO8CTRL1		= 0x67,
	MAX77802_REG_LDO9CTRL1		= 0x68,
	MAX77802_REG_LDO10CTRL1		= 0x69,
	MAX77802_REG_LDO11CTRL1		= 0x6A,
	MAX77802_REG_LDO12CTRL1		= 0x6B,
	MAX77802_REG_LDO13CTRL1		= 0x6C,
	MAX77802_REG_LDO14CTRL1		= 0x6D,
	MAX77802_REG_LDO15CTRL1		= 0x6E,
	/* Reserved: 0x6F */
	MAX77802_REG_LDO17CTRL1		= 0x70,
	MAX77802_REG_LDO18CTRL1		= 0x71,
	MAX77802_REG_LDO19CTRL1		= 0x72,
	MAX77802_REG_LDO20CTRL1		= 0x73,
	MAX77802_REG_LDO21CTRL1		= 0x74,
	MAX77802_REG_LDO22CTRL1		= 0x75,
	MAX77802_REG_LDO23CTRL1		= 0x76,
	MAX77802_REG_LDO24CTRL1		= 0x77,
	MAX77802_REG_LDO25CTRL1		= 0x78,
	MAX77802_REG_LDO26CTRL1		= 0x79,
	MAX77802_REG_LDO27CTRL1		= 0x7A,
	MAX77802_REG_LDO28CTRL1		= 0x7B,
	MAX77802_REG_LDO29CTRL1		= 0x7C,
	MAX77802_REG_LDO30CTRL1		= 0x7D,
	/* Reserved: 0x7E */
	MAX77802_REG_LDO32CTRL1		= 0x7F,
	MAX77802_REG_LDO33CTRL1		= 0x80,
	MAX77802_REG_LDO34CTRL1		= 0x81,
	MAX77802_REG_LDO35CTRL1		= 0x82,
	/* Reserved: 0x83-0x8F */
	MAX77802_REG_LDO1CTRL2		= 0x90,
	MAX77802_REG_LDO2CTRL2		= 0x91,
	MAX77802_REG_LDO3CTRL2		= 0x92,
	MAX77802_REG_LDO4CTRL2		= 0x93,
	MAX77802_REG_LDO5CTRL2		= 0x94,
	MAX77802_REG_LDO6CTRL2		= 0x95,
	MAX77802_REG_LDO7CTRL2		= 0x96,
	MAX77802_REG_LDO8CTRL2		= 0x97,
	MAX77802_REG_LDO9CTRL2		= 0x98,
	MAX77802_REG_LDO10CTRL2		= 0x99,
	MAX77802_REG_LDO11CTRL2		= 0x9A,
	MAX77802_REG_LDO12CTRL2		= 0x9B,
	MAX77802_REG_LDO13CTRL2		= 0x9C,
	MAX77802_REG_LDO14CTRL2		= 0x9D,
	MAX77802_REG_LDO15CTRL2		= 0x9E,
	/* Reserved: 0x9F */
	MAX77802_REG_LDO17CTRL2		= 0xA0,
	MAX77802_REG_LDO18CTRL2		= 0xA1,
	MAX77802_REG_LDO19CTRL2		= 0xA2,
	MAX77802_REG_LDO20CTRL2		= 0xA3,
	MAX77802_REG_LDO21CTRL2		= 0xA4,
	MAX77802_REG_LDO22CTRL2		= 0xA5,
	MAX77802_REG_LDO23CTRL2		= 0xA6,
	MAX77802_REG_LDO24CTRL2		= 0xA7,
	MAX77802_REG_LDO25CTRL2		= 0xA8,
	MAX77802_REG_LDO26CTRL2		= 0xA9,
	MAX77802_REG_LDO27CTRL2		= 0xAA,
	MAX77802_REG_LDO28CTRL2		= 0xAB,
	MAX77802_REG_LDO29CTRL2		= 0xAC,
	MAX77802_REG_LDO30CTRL2		= 0xAD,
	/* Reserved: 0xAE */
	MAX77802_REG_LDO32CTRL2		= 0xAF,
	MAX77802_REG_LDO33CTRL2		= 0xB0,
	MAX77802_REG_LDO34CTRL2		= 0xB1,
	MAX77802_REG_LDO35CTRL2		= 0xB2,
	/* Reserved: 0xB3 */

	MAX77802_REG_BBAT_CHG		= 0xB4,
	MAX77802_REG_32KHZ		= 0xB5,

	MAX77802_REG_PMIC_END		= 0xB6,
};

enum max77802_rtc_reg {
	MAX77802_RTC_INT		= 0xC0,
	MAX77802_RTC_INTM		= 0xC1,
	MAX77802_RTC_CONTROLM		= 0xC2,
	MAX77802_RTC_CONTROL		= 0xC3,
	MAX77802_RTC_UPDATE0		= 0xC4,
	MAX77802_RTC_UPDATE1		= 0xC5,
	MAX77802_WTSR_SMPL_CNTL		= 0xC6,
	MAX77802_RTC_SEC		= 0xC7,
	MAX77802_RTC_MIN		= 0xC8,
	MAX77802_RTC_HOUR		= 0xC9,
	MAX77802_RTC_WEEKDAY		= 0xCA,
	MAX77802_RTC_MONTH		= 0xCB,
	MAX77802_RTC_YEAR		= 0xCC,
	MAX77802_RTC_DATE		= 0xCD,
	MAX77802_RTC_AE1		= 0xCE,
	MAX77802_ALARM1_SEC		= 0xCF,
	MAX77802_ALARM1_MIN		= 0xD0,
	MAX77802_ALARM1_HOUR		= 0xD1,
	MAX77802_ALARM1_WEEKDAY		= 0xD2,
	MAX77802_ALARM1_MONTH		= 0xD3,
	MAX77802_ALARM1_YEAR		= 0xD4,
	MAX77802_ALARM1_DATE		= 0xD5,
	MAX77802_RTC_AE2		= 0xD6,
	MAX77802_ALARM2_SEC		= 0xD7,
	MAX77802_ALARM2_MIN		= 0xD8,
	MAX77802_ALARM2_HOUR		= 0xD9,
	MAX77802_ALARM2_WEEKDAY		= 0xDA,
	MAX77802_ALARM2_MONTH		= 0xDB,
	MAX77802_ALARM2_YEAR		= 0xDC,
	MAX77802_ALARM2_DATE		= 0xDD,

	MAX77802_RTC_END		= 0xDF,
};

enum max77686_irq_source {
	PMIC_INT1 = 0,
	PMIC_INT2,
	RTC_INT,

	MAX77686_IRQ_GROUP_NR,
};

enum max77686_irq {
	MAX77686_PMICIRQ_PWRONF,
	MAX77686_PMICIRQ_PWRONR,
	MAX77686_PMICIRQ_JIGONBF,
	MAX77686_PMICIRQ_JIGONBR,
	MAX77686_PMICIRQ_ACOKBF,
	MAX77686_PMICIRQ_ACOKBR,
	MAX77686_PMICIRQ_ONKEY1S,
	MAX77686_PMICIRQ_MRSTB,

	MAX77686_PMICIRQ_140C,
	MAX77686_PMICIRQ_120C,

	MAX77686_RTCIRQ_RTC60S = 0,
	MAX77686_RTCIRQ_RTCA1,
	MAX77686_RTCIRQ_RTCA2,
	MAX77686_RTCIRQ_SMPL,
	MAX77686_RTCIRQ_RTC1S,
	MAX77686_RTCIRQ_WTSR,
};

#define MAX77686_INT1_PWRONF_MSK	BIT(0)
#define MAX77686_INT1_PWRONR_MSK	BIT(1)
#define MAX77686_INT1_JIGONBF_MSK	BIT(2)
#define MAX77686_INT1_JIGONBR_MSK	BIT(3)
#define MAX77686_INT1_ACOKBF_MSK	BIT(4)
#define MAX77686_INT1_ACOKBR_MSK	BIT(5)
#define MAX77686_INT1_ONKEY1S_MSK	BIT(6)
#define MAX77686_INT1_MRSTB_MSK		BIT(7)

#define MAX77686_INT2_140C_MSK		BIT(0)
#define MAX77686_INT2_120C_MSK		BIT(1)

#define MAX77686_RTCINT_RTC60S_MSK	BIT(0)
#define MAX77686_RTCINT_RTCA1_MSK	BIT(1)
#define MAX77686_RTCINT_RTCA2_MSK	BIT(2)
#define MAX77686_RTCINT_SMPL_MSK	BIT(3)
#define MAX77686_RTCINT_RTC1S_MSK	BIT(4)
#define MAX77686_RTCINT_WTSR_MSK	BIT(5)

struct max77686_dev {
	struct device *dev;
	struct i2c_client *i2c; /* 0xcc / PMIC, Battery Control, and FLASH */

	unsigned long type;

	struct regmap *regmap;		/* regmap for mfd */
	struct regmap_irq_chip_data *irq_data;

	int irq;
	struct mutex irqlock;
	int irq_masks_cur[MAX77686_IRQ_GROUP_NR];
	int irq_masks_cache[MAX77686_IRQ_GROUP_NR];
};

enum max77686_types {
	TYPE_MAX77686,
	TYPE_MAX77802,
};

extern int max77686_irq_init(struct max77686_dev *max77686);
extern void max77686_irq_exit(struct max77686_dev *max77686);
extern int max77686_irq_resume(struct max77686_dev *max77686);

#endif /*  __LINUX_MFD_MAX77686_PRIV_H */
