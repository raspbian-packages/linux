/* SPDX-License-Identifier: GPL-2.0 */
/* Microchip LAN937X switch register definitions
 * Copyright (C) 2019-2021 Microchip Technology Inc.
 */
#ifndef __LAN937X_REG_H
#define __LAN937X_REG_H

#define PORT_CTRL_ADDR(port, addr)	((addr) | (((port) + 1)  << 12))

/* 0 - Operation */
#define REG_GLOBAL_CTRL_0		0x0007

#define SW_PHY_REG_BLOCK		BIT(7)
#define SW_FAST_MODE			BIT(3)
#define SW_FAST_MODE_OVERRIDE		BIT(2)

#define REG_SW_INT_STATUS__4		0x0010
#define REG_SW_INT_MASK__4		0x0014

#define LUE_INT				BIT(31)
#define TRIG_TS_INT			BIT(30)
#define APB_TIMEOUT_INT			BIT(29)
#define OVER_TEMP_INT			BIT(28)
#define HSR_INT				BIT(27)
#define PIO_INT				BIT(26)
#define POR_READY_INT			BIT(25)

#define SWITCH_INT_MASK			\
	(LUE_INT | TRIG_TS_INT | APB_TIMEOUT_INT | OVER_TEMP_INT | HSR_INT | \
	 PIO_INT | POR_READY_INT)

#define REG_SW_PORT_INT_STATUS__4	0x0018
#define REG_SW_PORT_INT_MASK__4		0x001C

/* 1 - Global */
#define REG_SW_GLOBAL_OUTPUT_CTRL__1	0x0103
#define SW_CLK125_ENB			BIT(1)
#define SW_CLK25_ENB			BIT(0)

/* 3 - Operation Control */
#define REG_SW_OPERATION		0x0300

#define SW_DOUBLE_TAG			BIT(7)
#define SW_OVER_TEMP_ENABLE		BIT(2)
#define SW_RESET			BIT(1)

#define REG_SW_LUE_CTRL_0		0x0310

#define SW_VLAN_ENABLE			BIT(7)
#define SW_DROP_INVALID_VID		BIT(6)
#define SW_AGE_CNT_M			0x7
#define SW_AGE_CNT_S			3
#define SW_RESV_MCAST_ENABLE		BIT(2)

#define REG_SW_LUE_CTRL_1		0x0311

#define UNICAST_LEARN_DISABLE		BIT(7)
#define SW_FLUSH_STP_TABLE		BIT(5)
#define SW_FLUSH_MSTP_TABLE		BIT(4)
#define SW_SRC_ADDR_FILTER		BIT(3)
#define SW_AGING_ENABLE			BIT(2)
#define SW_FAST_AGING			BIT(1)
#define SW_LINK_AUTO_AGING		BIT(0)

#define REG_SW_AGE_PERIOD__1		0x0313
#define SW_AGE_PERIOD_7_0_M		GENMASK(7, 0)

#define REG_SW_AGE_PERIOD__2		0x0320
#define SW_AGE_PERIOD_19_8_M		GENMASK(19, 8)

#define REG_SW_MAC_CTRL_0		0x0330
#define SW_NEW_BACKOFF			BIT(7)
#define SW_PAUSE_UNH_MODE		BIT(1)
#define SW_AGGR_BACKOFF			BIT(0)

#define REG_SW_MAC_CTRL_1		0x0331
#define SW_SHORT_IFG			BIT(7)
#define MULTICAST_STORM_DISABLE		BIT(6)
#define SW_BACK_PRESSURE		BIT(5)
#define FAIR_FLOW_CTRL			BIT(4)
#define NO_EXC_COLLISION_DROP		BIT(3)
#define SW_LEGAL_PACKET_DISABLE		BIT(1)
#define SW_PASS_SHORT_FRAME		BIT(0)

#define REG_SW_MAC_CTRL_6		0x0336
#define SW_MIB_COUNTER_FLUSH		BIT(7)
#define SW_MIB_COUNTER_FREEZE		BIT(6)

/* 4 - LUE */
#define REG_SW_ALU_STAT_CTRL__4		0x041C

#define REG_SW_ALU_VAL_B		0x0424
#define ALU_V_OVERRIDE			BIT(31)
#define ALU_V_USE_FID			BIT(30)
#define ALU_V_PORT_MAP			0xFF

/* 7 - VPhy */
#define REG_VPHY_IND_ADDR__2		0x075C
#define REG_VPHY_IND_DATA__2		0x0760

#define REG_VPHY_IND_CTRL__2		0x0768

#define VPHY_IND_WRITE			BIT(1)
#define VPHY_IND_BUSY			BIT(0)

#define REG_VPHY_SPECIAL_CTRL__2	0x077C
#define VPHY_SMI_INDIRECT_ENABLE	BIT(15)
#define VPHY_SW_LOOPBACK		BIT(14)
#define VPHY_MDIO_INTERNAL_ENABLE	BIT(13)
#define VPHY_SPI_INDIRECT_ENABLE	BIT(12)
#define VPHY_PORT_MODE_M		0x3
#define VPHY_PORT_MODE_S		8
#define VPHY_MODE_RGMII			0
#define VPHY_MODE_MII_PHY		1
#define VPHY_MODE_SGMII			2
#define VPHY_MODE_RMII_PHY		3
#define VPHY_SW_COLLISION_TEST		BIT(7)
#define VPHY_SPEED_DUPLEX_STAT_M	0x7
#define VPHY_SPEED_DUPLEX_STAT_S	2
#define VPHY_SPEED_1000			BIT(4)
#define VPHY_SPEED_100			BIT(3)
#define VPHY_FULL_DUPLEX		BIT(2)

/* Port Registers */

/* 0 - Operation */
#define REG_PORT_INT_STATUS		0x001B
#define REG_PORT_INT_MASK		0x001F

#define PORT_TAS_INT			BIT(5)
#define PORT_QCI_INT			BIT(4)
#define PORT_SGMII_INT			BIT(3)
#define PORT_PTP_INT			BIT(2)
#define PORT_PHY_INT			BIT(1)
#define PORT_ACL_INT			BIT(0)

#define PORT_SRC_PHY_INT		1

#define REG_PORT_CTRL_0			0x0020

#define PORT_MAC_LOOPBACK		BIT(7)
#define PORT_MAC_REMOTE_LOOPBACK	BIT(6)
#define PORT_K2L_INSERT_ENABLE		BIT(5)
#define PORT_K2L_DEBUG_ENABLE		BIT(4)
#define PORT_TAIL_TAG_ENABLE		BIT(2)
#define PORT_QUEUE_SPLIT_ENABLE		0x3

/* 1 - Phy */
#define REG_PORT_T1_PHY_CTRL_BASE	0x0100

/* 3 - xMII */
#define PORT_SGMII_SEL			BIT(7)
#define PORT_GRXC_ENABLE		BIT(0)

#define PORT_MII_SEL_EDGE		BIT(5)

#define REG_PORT_XMII_CTRL_4		0x0304
#define REG_PORT_XMII_CTRL_5		0x0306

#define PORT_DLL_RESET			BIT(15)
#define PORT_TUNE_ADJ			GENMASK(13, 7)

/* 4 - MAC */
#define REG_PORT_MAC_CTRL_0		0x0400
#define PORT_CHECK_LENGTH		BIT(2)
#define PORT_BROADCAST_STORM		BIT(1)
#define PORT_JUMBO_PACKET		BIT(0)

#define REG_PORT_MAC_CTRL_1		0x0401
#define PORT_BACK_PRESSURE		BIT(3)
#define PORT_PASS_ALL			BIT(0)

#define PORT_MAX_FR_SIZE		0x404
#define FR_MIN_SIZE		1522

/* 8 - Classification and Policing */
#define REG_PORT_MRI_PRIO_CTRL		0x0801
#define PORT_HIGHEST_PRIO		BIT(7)
#define PORT_OR_PRIO			BIT(6)
#define PORT_MAC_PRIO_ENABLE		BIT(4)
#define PORT_VLAN_PRIO_ENABLE		BIT(3)
#define PORT_802_1P_PRIO_ENABLE		BIT(2)
#define PORT_DIFFSERV_PRIO_ENABLE	BIT(1)
#define PORT_ACL_PRIO_ENABLE		BIT(0)

#define P_PRIO_CTRL			REG_PORT_MRI_PRIO_CTRL

/* 9 - Shaping */
#define REG_PORT_MTI_CREDIT_INCREMENT	0x091C

/* The port number as per the datasheet */
#define RGMII_2_PORT_NUM		5
#define RGMII_1_PORT_NUM		6

#define LAN937X_RGMII_2_PORT		(RGMII_2_PORT_NUM - 1)
#define LAN937X_RGMII_1_PORT		(RGMII_1_PORT_NUM - 1)

#define RGMII_1_TX_DELAY_2NS		2
#define RGMII_2_TX_DELAY_2NS		0
#define RGMII_1_RX_DELAY_2NS		0x1B
#define RGMII_2_RX_DELAY_2NS		0x14

#define LAN937X_TAG_LEN			2

#endif
