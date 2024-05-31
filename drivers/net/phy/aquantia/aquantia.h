/* SPDX-License-Identifier: GPL-2.0 */
/* HWMON driver for Aquantia PHY
 *
 * Author: Nikita Yushchenko <nikita.yoush@cogentembedded.com>
 * Author: Andrew Lunn <andrew@lunn.ch>
 * Author: Heiner Kallweit <hkallweit1@gmail.com>
 */

#include <linux/device.h>
#include <linux/phy.h>

/* Vendor specific 1, MDIO_MMD_VEND1 */
#define VEND1_GLOBAL_SC				0x0
#define VEND1_GLOBAL_SC_SOFT_RESET		BIT(15)
#define VEND1_GLOBAL_SC_LOW_POWER		BIT(11)

#define VEND1_GLOBAL_FW_ID			0x0020
#define VEND1_GLOBAL_FW_ID_MAJOR		GENMASK(15, 8)
#define VEND1_GLOBAL_FW_ID_MINOR		GENMASK(7, 0)

#define VEND1_GLOBAL_MAILBOX_INTERFACE1			0x0200
#define VEND1_GLOBAL_MAILBOX_INTERFACE1_EXECUTE		BIT(15)
#define VEND1_GLOBAL_MAILBOX_INTERFACE1_WRITE		BIT(14)
#define VEND1_GLOBAL_MAILBOX_INTERFACE1_CRC_RESET	BIT(12)
#define VEND1_GLOBAL_MAILBOX_INTERFACE1_BUSY		BIT(8)

#define VEND1_GLOBAL_MAILBOX_INTERFACE2			0x0201
#define VEND1_GLOBAL_MAILBOX_INTERFACE3			0x0202
#define VEND1_GLOBAL_MAILBOX_INTERFACE3_MSW_ADDR_MASK	GENMASK(15, 0)
#define VEND1_GLOBAL_MAILBOX_INTERFACE3_MSW_ADDR(x)	FIELD_PREP(VEND1_GLOBAL_MAILBOX_INTERFACE3_MSW_ADDR_MASK, (u16)((x) >> 16))
#define VEND1_GLOBAL_MAILBOX_INTERFACE4			0x0203
#define VEND1_GLOBAL_MAILBOX_INTERFACE4_LSW_ADDR_MASK	GENMASK(15, 2)
#define VEND1_GLOBAL_MAILBOX_INTERFACE4_LSW_ADDR(x)	FIELD_PREP(VEND1_GLOBAL_MAILBOX_INTERFACE4_LSW_ADDR_MASK, (u16)(x))

#define VEND1_GLOBAL_MAILBOX_INTERFACE5			0x0204
#define VEND1_GLOBAL_MAILBOX_INTERFACE5_MSW_DATA_MASK	GENMASK(15, 0)
#define VEND1_GLOBAL_MAILBOX_INTERFACE5_MSW_DATA(x)	FIELD_PREP(VEND1_GLOBAL_MAILBOX_INTERFACE5_MSW_DATA_MASK, (u16)((x) >> 16))
#define VEND1_GLOBAL_MAILBOX_INTERFACE6			0x0205
#define VEND1_GLOBAL_MAILBOX_INTERFACE6_LSW_DATA_MASK	GENMASK(15, 0)
#define VEND1_GLOBAL_MAILBOX_INTERFACE6_LSW_DATA(x)	FIELD_PREP(VEND1_GLOBAL_MAILBOX_INTERFACE6_LSW_DATA_MASK, (u16)(x))

/* The following registers all have similar layouts; first the registers... */
#define VEND1_GLOBAL_CFG_10M			0x0310
#define VEND1_GLOBAL_CFG_100M			0x031b
#define VEND1_GLOBAL_CFG_1G			0x031c
#define VEND1_GLOBAL_CFG_2_5G			0x031d
#define VEND1_GLOBAL_CFG_5G			0x031e
#define VEND1_GLOBAL_CFG_10G			0x031f
/* ...and now the fields */
#define VEND1_GLOBAL_CFG_SERDES_MODE		GENMASK(2, 0)
#define VEND1_GLOBAL_CFG_SERDES_MODE_XFI	0
#define VEND1_GLOBAL_CFG_SERDES_MODE_SGMII	3
#define VEND1_GLOBAL_CFG_SERDES_MODE_OCSGMII	4
#define VEND1_GLOBAL_CFG_SERDES_MODE_XFI5G	6
#define VEND1_GLOBAL_CFG_RATE_ADAPT		GENMASK(8, 7)
#define VEND1_GLOBAL_CFG_RATE_ADAPT_NONE	0
#define VEND1_GLOBAL_CFG_RATE_ADAPT_USX		1
#define VEND1_GLOBAL_CFG_RATE_ADAPT_PAUSE	2

/* Vendor specific 1, MDIO_MMD_VEND2 */
#define VEND1_GLOBAL_CONTROL2			0xc001
#define VEND1_GLOBAL_CONTROL2_UP_RUN_STALL_RST	BIT(15)
#define VEND1_GLOBAL_CONTROL2_UP_RUN_STALL_OVD	BIT(6)
#define VEND1_GLOBAL_CONTROL2_UP_RUN_STALL	BIT(0)

#define VEND1_THERMAL_PROV_HIGH_TEMP_FAIL	0xc421
#define VEND1_THERMAL_PROV_LOW_TEMP_FAIL	0xc422
#define VEND1_THERMAL_PROV_HIGH_TEMP_WARN	0xc423
#define VEND1_THERMAL_PROV_LOW_TEMP_WARN	0xc424
#define VEND1_THERMAL_STAT1			0xc820
#define VEND1_THERMAL_STAT2			0xc821
#define VEND1_THERMAL_STAT2_VALID		BIT(0)
#define VEND1_GENERAL_STAT1			0xc830
#define VEND1_GENERAL_STAT1_HIGH_TEMP_FAIL	BIT(14)
#define VEND1_GENERAL_STAT1_LOW_TEMP_FAIL	BIT(13)
#define VEND1_GENERAL_STAT1_HIGH_TEMP_WARN	BIT(12)
#define VEND1_GENERAL_STAT1_LOW_TEMP_WARN	BIT(11)

#define VEND1_GLOBAL_GEN_STAT2			0xc831
#define VEND1_GLOBAL_GEN_STAT2_OP_IN_PROG	BIT(15)

#define VEND1_GLOBAL_RSVD_STAT1			0xc885
#define VEND1_GLOBAL_RSVD_STAT1_FW_BUILD_ID	GENMASK(7, 4)
#define VEND1_GLOBAL_RSVD_STAT1_PROV_ID		GENMASK(3, 0)

#define VEND1_GLOBAL_RSVD_STAT9			0xc88d
#define VEND1_GLOBAL_RSVD_STAT9_MODE		GENMASK(7, 0)
#define VEND1_GLOBAL_RSVD_STAT9_1000BT2		0x23

#define VEND1_GLOBAL_INT_STD_STATUS		0xfc00
#define VEND1_GLOBAL_INT_VEND_STATUS		0xfc01

#define VEND1_GLOBAL_INT_STD_MASK		0xff00
#define VEND1_GLOBAL_INT_STD_MASK_PMA1		BIT(15)
#define VEND1_GLOBAL_INT_STD_MASK_PMA2		BIT(14)
#define VEND1_GLOBAL_INT_STD_MASK_PCS1		BIT(13)
#define VEND1_GLOBAL_INT_STD_MASK_PCS2		BIT(12)
#define VEND1_GLOBAL_INT_STD_MASK_PCS3		BIT(11)
#define VEND1_GLOBAL_INT_STD_MASK_PHY_XS1	BIT(10)
#define VEND1_GLOBAL_INT_STD_MASK_PHY_XS2	BIT(9)
#define VEND1_GLOBAL_INT_STD_MASK_AN1		BIT(8)
#define VEND1_GLOBAL_INT_STD_MASK_AN2		BIT(7)
#define VEND1_GLOBAL_INT_STD_MASK_GBE		BIT(6)
#define VEND1_GLOBAL_INT_STD_MASK_ALL		BIT(0)

#define VEND1_GLOBAL_INT_VEND_MASK		0xff01
#define VEND1_GLOBAL_INT_VEND_MASK_PMA		BIT(15)
#define VEND1_GLOBAL_INT_VEND_MASK_PCS		BIT(14)
#define VEND1_GLOBAL_INT_VEND_MASK_PHY_XS	BIT(13)
#define VEND1_GLOBAL_INT_VEND_MASK_AN		BIT(12)
#define VEND1_GLOBAL_INT_VEND_MASK_GBE		BIT(11)
#define VEND1_GLOBAL_INT_VEND_MASK_GLOBAL1	BIT(2)
#define VEND1_GLOBAL_INT_VEND_MASK_GLOBAL2	BIT(1)
#define VEND1_GLOBAL_INT_VEND_MASK_GLOBAL3	BIT(0)

#if IS_REACHABLE(CONFIG_HWMON)
int aqr_hwmon_probe(struct phy_device *phydev);
#else
static inline int aqr_hwmon_probe(struct phy_device *phydev) { return 0; }
#endif

int aqr_firmware_load(struct phy_device *phydev);
