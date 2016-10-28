/* Copyright Altera Corporation (C) 2016. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Tien Hock Loh <thloh@altera.com>
 */

#include <linux/mfd/syscon.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_net.h>
#include <linux/phy.h>
#include <linux/regmap.h>
#include <linux/reset.h>
#include <linux/stmmac.h>

#include "stmmac.h"
#include "stmmac_platform.h"
#include "altr_tse_pcs.h"

#define SYSMGR_EMACGRP_CTRL_PHYSEL_ENUM_GMII_MII	0
#define SYSMGR_EMACGRP_CTRL_PHYSEL_ENUM_RGMII		BIT(1)
#define SYSMGR_EMACGRP_CTRL_PHYSEL_ENUM_RMII		BIT(2)
#define SYSMGR_EMACGRP_CTRL_PHYSEL_WIDTH		2
#define SYSMGR_EMACGRP_CTRL_PHYSEL_MASK			GENMASK(1, 0)

#define TSE_PCS_CONTROL_AN_EN_MASK			BIT(12)
#define TSE_PCS_CONTROL_REG				0x00
#define TSE_PCS_CONTROL_RESTART_AN_MASK			BIT(9)
#define TSE_PCS_IF_MODE_REG				0x28
#define TSE_PCS_LINK_TIMER_0_REG			0x24
#define TSE_PCS_LINK_TIMER_1_REG			0x26
#define TSE_PCS_SIZE					0x40
#define TSE_PCS_STATUS_AN_COMPLETED_MASK		BIT(5)
#define TSE_PCS_STATUS_LINK_MASK			0x0004
#define TSE_PCS_STATUS_REG				0x02
#define TSE_PCS_SGMII_SPEED_1000			BIT(3)
#define TSE_PCS_SGMII_SPEED_100				BIT(2)
#define TSE_PCS_SGMII_SPEED_10				0x0
#define TSE_PCS_SW_RST_MASK				0x8000
#define TSE_PCS_PARTNER_ABILITY_REG			0x0A
#define TSE_PCS_PARTNER_DUPLEX_FULL			0x1000
#define TSE_PCS_PARTNER_DUPLEX_HALF			0x0000
#define TSE_PCS_PARTNER_DUPLEX_MASK			0x1000
#define TSE_PCS_PARTNER_SPEED_MASK			GENMASK(11, 10)
#define TSE_PCS_PARTNER_SPEED_1000			BIT(11)
#define TSE_PCS_PARTNER_SPEED_100			BIT(10)
#define TSE_PCS_PARTNER_SPEED_10			0x0000
#define TSE_PCS_PARTNER_SPEED_1000			BIT(11)
#define TSE_PCS_PARTNER_SPEED_100			BIT(10)
#define TSE_PCS_PARTNER_SPEED_10			0x0000
#define TSE_PCS_SGMII_SPEED_MASK			GENMASK(3, 2)
#define TSE_PCS_SGMII_LINK_TIMER_0			0x0D40
#define TSE_PCS_SGMII_LINK_TIMER_1			0x0003
#define TSE_PCS_SW_RESET_TIMEOUT			100
#define TSE_PCS_USE_SGMII_AN_MASK			BIT(2)
#define TSE_PCS_USE_SGMII_ENA				BIT(1)

#define SGMII_ADAPTER_CTRL_REG				0x00
#define SGMII_ADAPTER_DISABLE				0x0001
#define SGMII_ADAPTER_ENABLE				0x0000

#define AUTONEGO_LINK_TIMER				20

static int tse_pcs_reset(void __iomem *base, struct tse_pcs *pcs)
{
	int counter = 0;
	u16 val;

	val = readw(base + TSE_PCS_CONTROL_REG);
	val |= TSE_PCS_SW_RST_MASK;
	writew(val, base + TSE_PCS_CONTROL_REG);

	while (counter < TSE_PCS_SW_RESET_TIMEOUT) {
		val = readw(base + TSE_PCS_CONTROL_REG);
		val &= TSE_PCS_SW_RST_MASK;
		if (val == 0)
			break;
		counter++;
		udelay(1);
	}
	if (counter >= TSE_PCS_SW_RESET_TIMEOUT) {
		dev_err(pcs->dev, "PCS could not get out of sw reset\n");
		return -ETIMEDOUT;
	}

	return 0;
}

int tse_pcs_init(void __iomem *base, struct tse_pcs *pcs)
{
	int ret = 0;

	writew(TSE_PCS_USE_SGMII_ENA, base + TSE_PCS_IF_MODE_REG);

	writew(TSE_PCS_SGMII_LINK_TIMER_0, base + TSE_PCS_LINK_TIMER_0_REG);
	writew(TSE_PCS_SGMII_LINK_TIMER_1, base + TSE_PCS_LINK_TIMER_1_REG);

	ret = tse_pcs_reset(base, pcs);
	if (ret == 0)
		writew(SGMII_ADAPTER_ENABLE,
		       pcs->sgmii_adapter_base + SGMII_ADAPTER_CTRL_REG);

	return ret;
}

static void pcs_link_timer_callback(unsigned long data)
{
	u16 val = 0;
	struct tse_pcs *pcs = (struct tse_pcs *)data;
	void __iomem *tse_pcs_base = pcs->tse_pcs_base;
	void __iomem *sgmii_adapter_base = pcs->sgmii_adapter_base;

	val = readw(tse_pcs_base + TSE_PCS_STATUS_REG);
	val &= TSE_PCS_STATUS_LINK_MASK;

	if (val != 0) {
		dev_dbg(pcs->dev, "Adapter: Link is established\n");
		writew(SGMII_ADAPTER_ENABLE,
		       sgmii_adapter_base + SGMII_ADAPTER_CTRL_REG);
	} else {
		mod_timer(&pcs->aneg_link_timer, jiffies +
			  msecs_to_jiffies(AUTONEGO_LINK_TIMER));
	}
}

static void auto_nego_timer_callback(unsigned long data)
{
	u16 val = 0;
	u16 speed = 0;
	u16 duplex = 0;
	struct tse_pcs *pcs = (struct tse_pcs *)data;
	void __iomem *tse_pcs_base = pcs->tse_pcs_base;
	void __iomem *sgmii_adapter_base = pcs->sgmii_adapter_base;

	val = readw(tse_pcs_base + TSE_PCS_STATUS_REG);
	val &= TSE_PCS_STATUS_AN_COMPLETED_MASK;

	if (val != 0) {
		dev_dbg(pcs->dev, "Adapter: Auto Negotiation is completed\n");
		val = readw(tse_pcs_base + TSE_PCS_PARTNER_ABILITY_REG);
		speed = val & TSE_PCS_PARTNER_SPEED_MASK;
		duplex = val & TSE_PCS_PARTNER_DUPLEX_MASK;

		if (speed == TSE_PCS_PARTNER_SPEED_10 &&
		    duplex == TSE_PCS_PARTNER_DUPLEX_FULL)
			dev_dbg(pcs->dev,
				"Adapter: Link Partner is Up - 10/Full\n");
		else if (speed == TSE_PCS_PARTNER_SPEED_100 &&
			 duplex == TSE_PCS_PARTNER_DUPLEX_FULL)
			dev_dbg(pcs->dev,
				"Adapter: Link Partner is Up - 100/Full\n");
		else if (speed == TSE_PCS_PARTNER_SPEED_1000 &&
			 duplex == TSE_PCS_PARTNER_DUPLEX_FULL)
			dev_dbg(pcs->dev,
				"Adapter: Link Partner is Up - 1000/Full\n");
		else if (speed == TSE_PCS_PARTNER_SPEED_10 &&
			 duplex == TSE_PCS_PARTNER_DUPLEX_HALF)
			dev_err(pcs->dev,
				"Adapter does not support Half Duplex\n");
		else if (speed == TSE_PCS_PARTNER_SPEED_100 &&
			 duplex == TSE_PCS_PARTNER_DUPLEX_HALF)
			dev_err(pcs->dev,
				"Adapter does not support Half Duplex\n");
		else if (speed == TSE_PCS_PARTNER_SPEED_1000 &&
			 duplex == TSE_PCS_PARTNER_DUPLEX_HALF)
			dev_err(pcs->dev,
				"Adapter does not support Half Duplex\n");
		else
			dev_err(pcs->dev,
				"Adapter: Invalid Partner Speed and Duplex\n");

		if (duplex == TSE_PCS_PARTNER_DUPLEX_FULL &&
		    (speed == TSE_PCS_PARTNER_SPEED_10 ||
		     speed == TSE_PCS_PARTNER_SPEED_100 ||
		     speed == TSE_PCS_PARTNER_SPEED_1000))
			writew(SGMII_ADAPTER_ENABLE,
			       sgmii_adapter_base + SGMII_ADAPTER_CTRL_REG);
	} else {
		val = readw(tse_pcs_base + TSE_PCS_CONTROL_REG);
		val |= TSE_PCS_CONTROL_RESTART_AN_MASK;
		writew(val, tse_pcs_base + TSE_PCS_CONTROL_REG);

		tse_pcs_reset(tse_pcs_base, pcs);
		mod_timer(&pcs->aneg_link_timer, jiffies +
			  msecs_to_jiffies(AUTONEGO_LINK_TIMER));
	}
}

static void aneg_link_timer_callback(unsigned long data)
{
	struct tse_pcs *pcs = (struct tse_pcs *)data;

	if (pcs->autoneg == AUTONEG_ENABLE)
		auto_nego_timer_callback(data);
	else if (pcs->autoneg == AUTONEG_DISABLE)
		pcs_link_timer_callback(data);
}

void tse_pcs_fix_mac_speed(struct tse_pcs *pcs, struct phy_device *phy_dev,
			   unsigned int speed)
{
	void __iomem *tse_pcs_base = pcs->tse_pcs_base;
	void __iomem *sgmii_adapter_base = pcs->sgmii_adapter_base;
	u32 val;

	writew(SGMII_ADAPTER_ENABLE,
	       sgmii_adapter_base + SGMII_ADAPTER_CTRL_REG);

	pcs->autoneg = phy_dev->autoneg;

	if (phy_dev->autoneg == AUTONEG_ENABLE) {
		val = readw(tse_pcs_base + TSE_PCS_CONTROL_REG);
		val |= TSE_PCS_CONTROL_AN_EN_MASK;
		writew(val, tse_pcs_base + TSE_PCS_CONTROL_REG);

		val = readw(tse_pcs_base + TSE_PCS_IF_MODE_REG);
		val |= TSE_PCS_USE_SGMII_AN_MASK;
		writew(val, tse_pcs_base + TSE_PCS_IF_MODE_REG);

		val = readw(tse_pcs_base + TSE_PCS_CONTROL_REG);
		val |= TSE_PCS_CONTROL_RESTART_AN_MASK;

		tse_pcs_reset(tse_pcs_base, pcs);

		setup_timer(&pcs->aneg_link_timer,
			    aneg_link_timer_callback, (unsigned long)pcs);
		mod_timer(&pcs->aneg_link_timer, jiffies +
			  msecs_to_jiffies(AUTONEGO_LINK_TIMER));
	} else if (phy_dev->autoneg == AUTONEG_DISABLE) {
		val = readw(tse_pcs_base + TSE_PCS_CONTROL_REG);
		val &= ~TSE_PCS_CONTROL_AN_EN_MASK;
		writew(val, tse_pcs_base + TSE_PCS_CONTROL_REG);

		val = readw(tse_pcs_base + TSE_PCS_IF_MODE_REG);
		val &= ~TSE_PCS_USE_SGMII_AN_MASK;
		writew(val, tse_pcs_base + TSE_PCS_IF_MODE_REG);

		val = readw(tse_pcs_base + TSE_PCS_IF_MODE_REG);
		val &= ~TSE_PCS_SGMII_SPEED_MASK;

		switch (speed) {
		case 1000:
			val |= TSE_PCS_SGMII_SPEED_1000;
			break;
		case 100:
			val |= TSE_PCS_SGMII_SPEED_100;
			break;
		case 10:
			val |= TSE_PCS_SGMII_SPEED_10;
			break;
		default:
			return;
		}
		writew(val, tse_pcs_base + TSE_PCS_IF_MODE_REG);

		tse_pcs_reset(tse_pcs_base, pcs);

		setup_timer(&pcs->aneg_link_timer,
			    aneg_link_timer_callback, (unsigned long)pcs);
		mod_timer(&pcs->aneg_link_timer, jiffies +
			  msecs_to_jiffies(AUTONEGO_LINK_TIMER));
	}
}
