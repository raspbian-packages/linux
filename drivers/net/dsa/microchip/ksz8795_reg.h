/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Microchip KSZ8795 register definitions
 *
 * Copyright (c) 2017 Microchip Technology Inc.
 *	Tristram Ha <Tristram.Ha@microchip.com>
 */

#ifndef __KSZ8795_REG_H
#define __KSZ8795_REG_H

#define KS_PORT_M			0x1F

#define KS_PRIO_M			0x3
#define KS_PRIO_S			2

#define REG_CHIP_ID0			0x00

#define FAMILY_ID			0x87

#define REG_CHIP_ID1			0x01

#define SW_CHIP_ID_M			0xF0
#define SW_CHIP_ID_S			4
#define SW_REVISION_M			0x0E
#define SW_REVISION_S			1
#define SW_START			0x01

#define CHIP_ID_94			0x60
#define CHIP_ID_95			0x90

#define REG_SW_CTRL_0			0x02

#define SW_NEW_BACKOFF			BIT(7)
#define SW_GLOBAL_RESET			BIT(6)
#define SW_FLUSH_DYN_MAC_TABLE		BIT(5)
#define SW_FLUSH_STA_MAC_TABLE		BIT(4)
#define SW_LINK_AUTO_AGING		BIT(0)

#define REG_SW_CTRL_1			0x03

#define SW_HUGE_PACKET			BIT(6)
#define SW_TX_FLOW_CTRL_DISABLE		BIT(5)
#define SW_RX_FLOW_CTRL_DISABLE		BIT(4)
#define SW_CHECK_LENGTH			BIT(3)
#define SW_AGING_ENABLE			BIT(2)
#define SW_FAST_AGING			BIT(1)
#define SW_AGGR_BACKOFF			BIT(0)

#define REG_SW_CTRL_2			0x04

#define UNICAST_VLAN_BOUNDARY		BIT(7)
#define MULTICAST_STORM_DISABLE		BIT(6)
#define SW_BACK_PRESSURE		BIT(5)
#define FAIR_FLOW_CTRL			BIT(4)
#define NO_EXC_COLLISION_DROP		BIT(3)
#define SW_LEGAL_PACKET_DISABLE		BIT(1)

#define REG_SW_CTRL_3			0x05
 #define WEIGHTED_FAIR_QUEUE_ENABLE	BIT(3)

#define SW_VLAN_ENABLE			BIT(7)
#define SW_IGMP_SNOOP			BIT(6)
#define SW_MIRROR_RX_TX			BIT(0)

#define REG_SW_CTRL_4			0x06

#define SW_HALF_DUPLEX_FLOW_CTRL	BIT(7)
#define SW_HALF_DUPLEX			BIT(6)
#define SW_FLOW_CTRL			BIT(5)
#define SW_10_MBIT			BIT(4)
#define SW_REPLACE_VID			BIT(3)
#define BROADCAST_STORM_RATE_HI		0x07

#define REG_SW_CTRL_5			0x07

#define BROADCAST_STORM_RATE_LO		0xFF
#define BROADCAST_STORM_RATE		0x07FF

#define REG_SW_CTRL_6			0x08

#define SW_MIB_COUNTER_FLUSH		BIT(7)
#define SW_MIB_COUNTER_FREEZE		BIT(6)
#define SW_MIB_COUNTER_CTRL_ENABLE	KS_PORT_M

#define REG_SW_CTRL_9			0x0B

#define SPI_CLK_125_MHZ			0x80
#define SPI_CLK_62_5_MHZ		0x40
#define SPI_CLK_31_25_MHZ		0x00

#define SW_LED_MODE_M			0x3
#define SW_LED_MODE_S			4
#define SW_LED_LINK_ACT_SPEED		0
#define SW_LED_LINK_ACT			1
#define SW_LED_LINK_ACT_DUPLEX		2
#define SW_LED_LINK_DUPLEX		3

#define REG_SW_CTRL_10			0x0C

#define SW_TAIL_TAG_ENABLE		BIT(1)
#define SW_PASS_PAUSE			BIT(0)

#define REG_SW_CTRL_11			0x0D

#define REG_POWER_MANAGEMENT_1		0x0E

#define SW_PLL_POWER_DOWN		BIT(5)
#define SW_POWER_MANAGEMENT_MODE_M	0x3
#define SW_POWER_MANAGEMENT_MODE_S	3
#define SW_POWER_NORMAL			0
#define SW_ENERGY_DETECTION		1
#define SW_SOFTWARE_POWER_DOWN		2

#define REG_POWER_MANAGEMENT_2		0x0F

#define REG_PORT_1_CTRL_0		0x10
#define REG_PORT_2_CTRL_0		0x20
#define REG_PORT_3_CTRL_0		0x30
#define REG_PORT_4_CTRL_0		0x40
#define REG_PORT_5_CTRL_0		0x50

#define PORT_BROADCAST_STORM		BIT(7)
#define PORT_DIFFSERV_ENABLE		BIT(6)
#define PORT_802_1P_ENABLE		BIT(5)
#define PORT_BASED_PRIO_S		3
#define PORT_BASED_PRIO_M		KS_PRIO_M
#define PORT_BASED_PRIO_0		0
#define PORT_BASED_PRIO_1		1
#define PORT_BASED_PRIO_2		2
#define PORT_BASED_PRIO_3		3
#define PORT_INSERT_TAG			BIT(2)
#define PORT_REMOVE_TAG			BIT(1)
#define PORT_QUEUE_SPLIT_L		BIT(0)

#define REG_PORT_1_CTRL_1		0x11
#define REG_PORT_2_CTRL_1		0x21
#define REG_PORT_3_CTRL_1		0x31
#define REG_PORT_4_CTRL_1		0x41
#define REG_PORT_5_CTRL_1		0x51

#define PORT_MIRROR_SNIFFER		BIT(7)
#define PORT_MIRROR_RX			BIT(6)
#define PORT_MIRROR_TX			BIT(5)
#define PORT_VLAN_MEMBERSHIP		KS_PORT_M

#define REG_PORT_1_CTRL_2		0x12
#define REG_PORT_2_CTRL_2		0x22
#define REG_PORT_3_CTRL_2		0x32
#define REG_PORT_4_CTRL_2		0x42
#define REG_PORT_5_CTRL_2		0x52

#define PORT_802_1P_REMAPPING		BIT(7)
#define PORT_INGRESS_FILTER		BIT(6)
#define PORT_DISCARD_NON_VID		BIT(5)
#define PORT_FORCE_FLOW_CTRL		BIT(4)
#define PORT_BACK_PRESSURE		BIT(3)
#define PORT_TX_ENABLE			BIT(2)
#define PORT_RX_ENABLE			BIT(1)
#define PORT_LEARN_DISABLE		BIT(0)

#define REG_PORT_1_CTRL_3		0x13
#define REG_PORT_2_CTRL_3		0x23
#define REG_PORT_3_CTRL_3		0x33
#define REG_PORT_4_CTRL_3		0x43
#define REG_PORT_5_CTRL_3		0x53
#define REG_PORT_1_CTRL_4		0x14
#define REG_PORT_2_CTRL_4		0x24
#define REG_PORT_3_CTRL_4		0x34
#define REG_PORT_4_CTRL_4		0x44
#define REG_PORT_5_CTRL_4		0x54

#define PORT_DEFAULT_VID		0x0001

#define REG_PORT_1_CTRL_5		0x15
#define REG_PORT_2_CTRL_5		0x25
#define REG_PORT_3_CTRL_5		0x35
#define REG_PORT_4_CTRL_5		0x45
#define REG_PORT_5_CTRL_5		0x55

#define PORT_ACL_ENABLE			BIT(2)
#define PORT_AUTHEN_MODE		0x3
#define PORT_AUTHEN_PASS		0
#define PORT_AUTHEN_BLOCK		1
#define PORT_AUTHEN_TRAP		2

#define REG_PORT_5_CTRL_6		0x56

#define PORT_MII_INTERNAL_CLOCK		BIT(7)
#define PORT_GMII_1GPS_MODE		BIT(6)
#define PORT_RGMII_ID_IN_ENABLE		BIT(4)
#define PORT_RGMII_ID_OUT_ENABLE	BIT(3)
#define PORT_GMII_MAC_MODE		BIT(2)
#define PORT_INTERFACE_TYPE		0x3
#define PORT_INTERFACE_MII		0
#define PORT_INTERFACE_RMII		1
#define PORT_INTERFACE_GMII		2
#define PORT_INTERFACE_RGMII		3

#define REG_PORT_1_CTRL_7		0x17
#define REG_PORT_2_CTRL_7		0x27
#define REG_PORT_3_CTRL_7		0x37
#define REG_PORT_4_CTRL_7		0x47

#define PORT_AUTO_NEG_ASYM_PAUSE	BIT(5)
#define PORT_AUTO_NEG_SYM_PAUSE		BIT(4)
#define PORT_AUTO_NEG_100BTX_FD		BIT(3)
#define PORT_AUTO_NEG_100BTX		BIT(2)
#define PORT_AUTO_NEG_10BT_FD		BIT(1)
#define PORT_AUTO_NEG_10BT		BIT(0)

#define REG_PORT_1_STATUS_0		0x18
#define REG_PORT_2_STATUS_0		0x28
#define REG_PORT_3_STATUS_0		0x38
#define REG_PORT_4_STATUS_0		0x48

/* For KSZ8765. */
#define PORT_FIBER_MODE			BIT(7)

#define PORT_REMOTE_ASYM_PAUSE		BIT(5)
#define PORT_REMOTE_SYM_PAUSE		BIT(4)
#define PORT_REMOTE_100BTX_FD		BIT(3)
#define PORT_REMOTE_100BTX		BIT(2)
#define PORT_REMOTE_10BT_FD		BIT(1)
#define PORT_REMOTE_10BT		BIT(0)

#define REG_PORT_1_STATUS_1		0x19
#define REG_PORT_2_STATUS_1		0x29
#define REG_PORT_3_STATUS_1		0x39
#define REG_PORT_4_STATUS_1		0x49

#define PORT_HP_MDIX			BIT(7)
#define PORT_REVERSED_POLARITY		BIT(5)
#define PORT_TX_FLOW_CTRL		BIT(4)
#define PORT_RX_FLOW_CTRL		BIT(3)
#define PORT_STAT_SPEED_100MBIT		BIT(2)
#define PORT_STAT_FULL_DUPLEX		BIT(1)

#define PORT_REMOTE_FAULT		BIT(0)

#define REG_PORT_1_LINK_MD_CTRL		0x1A
#define REG_PORT_2_LINK_MD_CTRL		0x2A
#define REG_PORT_3_LINK_MD_CTRL		0x3A
#define REG_PORT_4_LINK_MD_CTRL		0x4A

#define PORT_CABLE_10M_SHORT		BIT(7)
#define PORT_CABLE_DIAG_RESULT_M	0x3
#define PORT_CABLE_DIAG_RESULT_S	5
#define PORT_CABLE_STAT_NORMAL		0
#define PORT_CABLE_STAT_OPEN		1
#define PORT_CABLE_STAT_SHORT		2
#define PORT_CABLE_STAT_FAILED		3
#define PORT_START_CABLE_DIAG		BIT(4)
#define PORT_FORCE_LINK			BIT(3)
#define PORT_POWER_SAVING		BIT(2)
#define PORT_PHY_REMOTE_LOOPBACK	BIT(1)
#define PORT_CABLE_FAULT_COUNTER_H	0x01

#define REG_PORT_1_LINK_MD_RESULT	0x1B
#define REG_PORT_2_LINK_MD_RESULT	0x2B
#define REG_PORT_3_LINK_MD_RESULT	0x3B
#define REG_PORT_4_LINK_MD_RESULT	0x4B

#define PORT_CABLE_FAULT_COUNTER_L	0xFF
#define PORT_CABLE_FAULT_COUNTER	0x1FF

#define REG_PORT_1_CTRL_9		0x1C
#define REG_PORT_2_CTRL_9		0x2C
#define REG_PORT_3_CTRL_9		0x3C
#define REG_PORT_4_CTRL_9		0x4C

#define PORT_AUTO_NEG_DISABLE		BIT(7)
#define PORT_FORCE_100_MBIT		BIT(6)
#define PORT_FORCE_FULL_DUPLEX		BIT(5)

#define REG_PORT_1_CTRL_10		0x1D
#define REG_PORT_2_CTRL_10		0x2D
#define REG_PORT_3_CTRL_10		0x3D
#define REG_PORT_4_CTRL_10		0x4D

#define PORT_LED_OFF			BIT(7)
#define PORT_TX_DISABLE			BIT(6)
#define PORT_AUTO_NEG_RESTART		BIT(5)
#define PORT_POWER_DOWN			BIT(3)
#define PORT_AUTO_MDIX_DISABLE		BIT(2)
#define PORT_FORCE_MDIX			BIT(1)
#define PORT_MAC_LOOPBACK		BIT(0)

#define REG_PORT_1_STATUS_2		0x1E
#define REG_PORT_2_STATUS_2		0x2E
#define REG_PORT_3_STATUS_2		0x3E
#define REG_PORT_4_STATUS_2		0x4E

#define PORT_MDIX_STATUS		BIT(7)
#define PORT_AUTO_NEG_COMPLETE		BIT(6)
#define PORT_STAT_LINK_GOOD		BIT(5)

#define REG_PORT_1_STATUS_3		0x1F
#define REG_PORT_2_STATUS_3		0x2F
#define REG_PORT_3_STATUS_3		0x3F
#define REG_PORT_4_STATUS_3		0x4F

#define PORT_PHY_LOOPBACK		BIT(7)
#define PORT_PHY_ISOLATE		BIT(5)
#define PORT_PHY_SOFT_RESET		BIT(4)
#define PORT_PHY_FORCE_LINK		BIT(3)
#define PORT_PHY_MODE_M			0x7
#define PHY_MODE_IN_AUTO_NEG		1
#define PHY_MODE_10BT_HALF		2
#define PHY_MODE_100BT_HALF		3
#define PHY_MODE_10BT_FULL		5
#define PHY_MODE_100BT_FULL		6
#define PHY_MODE_ISOLDATE		7

#define REG_PORT_CTRL_0			0x00
#define REG_PORT_CTRL_1			0x01
#define REG_PORT_CTRL_2			0x02
#define REG_PORT_CTRL_VID		0x03

#define REG_PORT_CTRL_5			0x05

#define REG_PORT_CTRL_7			0x07
#define REG_PORT_STATUS_0		0x08
#define REG_PORT_STATUS_1		0x09
#define REG_PORT_LINK_MD_CTRL		0x0A
#define REG_PORT_LINK_MD_RESULT		0x0B
#define REG_PORT_CTRL_9			0x0C
#define REG_PORT_CTRL_10		0x0D
#define REG_PORT_STATUS_2		0x0E
#define REG_PORT_STATUS_3		0x0F

#define REG_PORT_CTRL_12		0xA0
#define REG_PORT_CTRL_13		0xA1
#define REG_PORT_RATE_CTRL_3		0xA2
#define REG_PORT_RATE_CTRL_2		0xA3
#define REG_PORT_RATE_CTRL_1		0xA4
#define REG_PORT_RATE_CTRL_0		0xA5
#define REG_PORT_RATE_LIMIT		0xA6
#define REG_PORT_IN_RATE_0		0xA7
#define REG_PORT_IN_RATE_1		0xA8
#define REG_PORT_IN_RATE_2		0xA9
#define REG_PORT_IN_RATE_3		0xAA
#define REG_PORT_OUT_RATE_0		0xAB
#define REG_PORT_OUT_RATE_1		0xAC
#define REG_PORT_OUT_RATE_2		0xAD
#define REG_PORT_OUT_RATE_3		0xAE

#define PORT_CTRL_ADDR(port, addr)		\
	((addr) + REG_PORT_1_CTRL_0 + (port) *	\
		(REG_PORT_2_CTRL_0 - REG_PORT_1_CTRL_0))

#define REG_SW_MAC_ADDR_0		0x68
#define REG_SW_MAC_ADDR_1		0x69
#define REG_SW_MAC_ADDR_2		0x6A
#define REG_SW_MAC_ADDR_3		0x6B
#define REG_SW_MAC_ADDR_4		0x6C
#define REG_SW_MAC_ADDR_5		0x6D

#define REG_IND_CTRL_0			0x6E

#define TABLE_EXT_SELECT_S		5
#define TABLE_EEE_V			1
#define TABLE_ACL_V			2
#define TABLE_PME_V			4
#define TABLE_LINK_MD_V			5
#define TABLE_EEE			(TABLE_EEE_V << TABLE_EXT_SELECT_S)
#define TABLE_ACL			(TABLE_ACL_V << TABLE_EXT_SELECT_S)
#define TABLE_PME			(TABLE_PME_V << TABLE_EXT_SELECT_S)
#define TABLE_LINK_MD			(TABLE_LINK_MD << TABLE_EXT_SELECT_S)
#define TABLE_READ			BIT(4)
#define TABLE_SELECT_S			2
#define TABLE_STATIC_MAC_V		0
#define TABLE_VLAN_V			1
#define TABLE_DYNAMIC_MAC_V		2
#define TABLE_MIB_V			3
#define TABLE_STATIC_MAC		(TABLE_STATIC_MAC_V << TABLE_SELECT_S)
#define TABLE_VLAN			(TABLE_VLAN_V << TABLE_SELECT_S)
#define TABLE_DYNAMIC_MAC		(TABLE_DYNAMIC_MAC_V << TABLE_SELECT_S)
#define TABLE_MIB			(TABLE_MIB_V << TABLE_SELECT_S)

#define REG_IND_CTRL_1			0x6F

#define TABLE_ENTRY_MASK		0x03FF
#define TABLE_EXT_ENTRY_MASK		0x0FFF

#define REG_IND_DATA_8			0x70
#define REG_IND_DATA_7			0x71
#define REG_IND_DATA_6			0x72
#define REG_IND_DATA_5			0x73
#define REG_IND_DATA_4			0x74
#define REG_IND_DATA_3			0x75
#define REG_IND_DATA_2			0x76
#define REG_IND_DATA_1			0x77
#define REG_IND_DATA_0			0x78

#define REG_IND_DATA_PME_EEE_ACL	0xA0

#define REG_IND_DATA_CHECK		REG_IND_DATA_6
#define REG_IND_MIB_CHECK		REG_IND_DATA_4
#define REG_IND_DATA_HI			REG_IND_DATA_7
#define REG_IND_DATA_LO			REG_IND_DATA_3

#define REG_INT_STATUS			0x7C
#define REG_INT_ENABLE			0x7D

#define INT_PME				BIT(4)

#define REG_ACL_INT_STATUS		0x7E
#define REG_ACL_INT_ENABLE		0x7F

#define INT_PORT_5			BIT(4)
#define INT_PORT_4			BIT(3)
#define INT_PORT_3			BIT(2)
#define INT_PORT_2			BIT(1)
#define INT_PORT_1			BIT(0)

#define INT_PORT_ALL			\
	(INT_PORT_5 | INT_PORT_4 | INT_PORT_3 | INT_PORT_2 | INT_PORT_1)

#define REG_SW_CTRL_12			0x80
#define REG_SW_CTRL_13			0x81

#define SWITCH_802_1P_MASK		3
#define SWITCH_802_1P_BASE		3
#define SWITCH_802_1P_SHIFT		2

#define SW_802_1P_MAP_M			KS_PRIO_M
#define SW_802_1P_MAP_S			KS_PRIO_S

#define REG_SWITCH_CTRL_14		0x82

#define SW_PRIO_MAPPING_M		KS_PRIO_M
#define SW_PRIO_MAPPING_S		6
#define SW_PRIO_MAP_3_HI		0
#define SW_PRIO_MAP_2_HI		2
#define SW_PRIO_MAP_0_LO		3

#define REG_SW_CTRL_15			0x83
#define REG_SW_CTRL_16			0x84
#define REG_SW_CTRL_17			0x85
#define REG_SW_CTRL_18			0x86

#define SW_SELF_ADDR_FILTER_ENABLE	BIT(6)

#define REG_SW_UNK_UCAST_CTRL		0x83
#define REG_SW_UNK_MCAST_CTRL		0x84
#define REG_SW_UNK_VID_CTRL		0x85
#define REG_SW_UNK_IP_MCAST_CTRL	0x86

#define SW_UNK_FWD_ENABLE		BIT(5)
#define SW_UNK_FWD_MAP			KS_PORT_M

#define REG_SW_CTRL_19			0x87

#define SW_IN_RATE_LIMIT_PERIOD_M	0x3
#define SW_IN_RATE_LIMIT_PERIOD_S	4
#define SW_IN_RATE_LIMIT_16_MS		0
#define SW_IN_RATE_LIMIT_64_MS		1
#define SW_IN_RATE_LIMIT_256_MS		2
#define SW_OUT_RATE_LIMIT_QUEUE_BASED	BIT(3)
#define SW_INS_TAG_ENABLE		BIT(2)

#define REG_TOS_PRIO_CTRL_0		0x90
#define REG_TOS_PRIO_CTRL_1		0x91
#define REG_TOS_PRIO_CTRL_2		0x92
#define REG_TOS_PRIO_CTRL_3		0x93
#define REG_TOS_PRIO_CTRL_4		0x94
#define REG_TOS_PRIO_CTRL_5		0x95
#define REG_TOS_PRIO_CTRL_6		0x96
#define REG_TOS_PRIO_CTRL_7		0x97
#define REG_TOS_PRIO_CTRL_8		0x98
#define REG_TOS_PRIO_CTRL_9		0x99
#define REG_TOS_PRIO_CTRL_10		0x9A
#define REG_TOS_PRIO_CTRL_11		0x9B
#define REG_TOS_PRIO_CTRL_12		0x9C
#define REG_TOS_PRIO_CTRL_13		0x9D
#define REG_TOS_PRIO_CTRL_14		0x9E
#define REG_TOS_PRIO_CTRL_15		0x9F

#define TOS_PRIO_M			KS_PRIO_M
#define TOS_PRIO_S			KS_PRIO_S

#define REG_SW_CTRL_20			0xA3

#define SW_GMII_DRIVE_STRENGTH_S	4
#define SW_DRIVE_STRENGTH_M		0x7
#define SW_DRIVE_STRENGTH_2MA		0
#define SW_DRIVE_STRENGTH_4MA		1
#define SW_DRIVE_STRENGTH_8MA		2
#define SW_DRIVE_STRENGTH_12MA		3
#define SW_DRIVE_STRENGTH_16MA		4
#define SW_DRIVE_STRENGTH_20MA		5
#define SW_DRIVE_STRENGTH_24MA		6
#define SW_DRIVE_STRENGTH_28MA		7
#define SW_MII_DRIVE_STRENGTH_S		0

#define REG_SW_CTRL_21			0xA4

#define SW_IPV6_MLD_OPTION		BIT(3)
#define SW_IPV6_MLD_SNOOP		BIT(2)

#define REG_PORT_1_CTRL_12		0xB0
#define REG_PORT_2_CTRL_12		0xC0
#define REG_PORT_3_CTRL_12		0xD0
#define REG_PORT_4_CTRL_12		0xE0
#define REG_PORT_5_CTRL_12		0xF0

#define PORT_PASS_ALL			BIT(6)
#define PORT_INS_TAG_FOR_PORT_5_S	3
#define PORT_INS_TAG_FOR_PORT_5		BIT(3)
#define PORT_INS_TAG_FOR_PORT_4		BIT(2)
#define PORT_INS_TAG_FOR_PORT_3		BIT(1)
#define PORT_INS_TAG_FOR_PORT_2		BIT(0)

#define REG_PORT_1_CTRL_13		0xB1
#define REG_PORT_2_CTRL_13		0xC1
#define REG_PORT_3_CTRL_13		0xD1
#define REG_PORT_4_CTRL_13		0xE1
#define REG_PORT_5_CTRL_13		0xF1

#define PORT_QUEUE_SPLIT_H		BIT(1)
#define PORT_QUEUE_SPLIT_1		0
#define PORT_QUEUE_SPLIT_2		1
#define PORT_QUEUE_SPLIT_4		2
#define PORT_DROP_TAG			BIT(0)

#define REG_PORT_1_CTRL_14		0xB2
#define REG_PORT_2_CTRL_14		0xC2
#define REG_PORT_3_CTRL_14		0xD2
#define REG_PORT_4_CTRL_14		0xE2
#define REG_PORT_5_CTRL_14		0xF2
#define REG_PORT_1_CTRL_15		0xB3
#define REG_PORT_2_CTRL_15		0xC3
#define REG_PORT_3_CTRL_15		0xD3
#define REG_PORT_4_CTRL_15		0xE3
#define REG_PORT_5_CTRL_15		0xF3
#define REG_PORT_1_CTRL_16		0xB4
#define REG_PORT_2_CTRL_16		0xC4
#define REG_PORT_3_CTRL_16		0xD4
#define REG_PORT_4_CTRL_16		0xE4
#define REG_PORT_5_CTRL_16		0xF4
#define REG_PORT_1_CTRL_17		0xB5
#define REG_PORT_2_CTRL_17		0xC5
#define REG_PORT_3_CTRL_17		0xD5
#define REG_PORT_4_CTRL_17		0xE5
#define REG_PORT_5_CTRL_17		0xF5

#define REG_PORT_1_RATE_CTRL_3		0xB2
#define REG_PORT_1_RATE_CTRL_2		0xB3
#define REG_PORT_1_RATE_CTRL_1		0xB4
#define REG_PORT_1_RATE_CTRL_0		0xB5
#define REG_PORT_2_RATE_CTRL_3		0xC2
#define REG_PORT_2_RATE_CTRL_2		0xC3
#define REG_PORT_2_RATE_CTRL_1		0xC4
#define REG_PORT_2_RATE_CTRL_0		0xC5
#define REG_PORT_3_RATE_CTRL_3		0xD2
#define REG_PORT_3_RATE_CTRL_2		0xD3
#define REG_PORT_3_RATE_CTRL_1		0xD4
#define REG_PORT_3_RATE_CTRL_0		0xD5
#define REG_PORT_4_RATE_CTRL_3		0xE2
#define REG_PORT_4_RATE_CTRL_2		0xE3
#define REG_PORT_4_RATE_CTRL_1		0xE4
#define REG_PORT_4_RATE_CTRL_0		0xE5
#define REG_PORT_5_RATE_CTRL_3		0xF2
#define REG_PORT_5_RATE_CTRL_2		0xF3
#define REG_PORT_5_RATE_CTRL_1		0xF4
#define REG_PORT_5_RATE_CTRL_0		0xF5

#define RATE_CTRL_ENABLE		BIT(7)
#define RATE_RATIO_M			(BIT(7) - 1)

#define PORT_OUT_RATE_ENABLE		BIT(7)

#define REG_PORT_1_RATE_LIMIT		0xB6
#define REG_PORT_2_RATE_LIMIT		0xC6
#define REG_PORT_3_RATE_LIMIT		0xD6
#define REG_PORT_4_RATE_LIMIT		0xE6
#define REG_PORT_5_RATE_LIMIT		0xF6

#define PORT_IN_PORT_BASED_S		6
#define PORT_RATE_PACKET_BASED_S	5
#define PORT_IN_FLOW_CTRL_S		4
#define PORT_IN_LIMIT_MODE_M		0x3
#define PORT_IN_LIMIT_MODE_S		2
#define PORT_COUNT_IFG_S		1
#define PORT_COUNT_PREAMBLE_S		0
#define PORT_IN_PORT_BASED		BIT(PORT_IN_PORT_BASED_S)
#define PORT_RATE_PACKET_BASED		BIT(PORT_RATE_PACKET_BASED_S)
#define PORT_IN_FLOW_CTRL		BIT(PORT_IN_FLOW_CTRL_S)
#define PORT_IN_ALL			0
#define PORT_IN_UNICAST			1
#define PORT_IN_MULTICAST		2
#define PORT_IN_BROADCAST		3
#define PORT_COUNT_IFG			BIT(PORT_COUNT_IFG_S)
#define PORT_COUNT_PREAMBLE		BIT(PORT_COUNT_PREAMBLE_S)

#define REG_PORT_1_IN_RATE_0		0xB7
#define REG_PORT_2_IN_RATE_0		0xC7
#define REG_PORT_3_IN_RATE_0		0xD7
#define REG_PORT_4_IN_RATE_0		0xE7
#define REG_PORT_5_IN_RATE_0		0xF7
#define REG_PORT_1_IN_RATE_1		0xB8
#define REG_PORT_2_IN_RATE_1		0xC8
#define REG_PORT_3_IN_RATE_1		0xD8
#define REG_PORT_4_IN_RATE_1		0xE8
#define REG_PORT_5_IN_RATE_1		0xF8
#define REG_PORT_1_IN_RATE_2		0xB9
#define REG_PORT_2_IN_RATE_2		0xC9
#define REG_PORT_3_IN_RATE_2		0xD9
#define REG_PORT_4_IN_RATE_2		0xE9
#define REG_PORT_5_IN_RATE_2		0xF9
#define REG_PORT_1_IN_RATE_3		0xBA
#define REG_PORT_2_IN_RATE_3		0xCA
#define REG_PORT_3_IN_RATE_3		0xDA
#define REG_PORT_4_IN_RATE_3		0xEA
#define REG_PORT_5_IN_RATE_3		0xFA

#define PORT_IN_RATE_ENABLE		BIT(7)
#define PORT_RATE_LIMIT_M		(BIT(7) - 1)

#define REG_PORT_1_OUT_RATE_0		0xBB
#define REG_PORT_2_OUT_RATE_0		0xCB
#define REG_PORT_3_OUT_RATE_0		0xDB
#define REG_PORT_4_OUT_RATE_0		0xEB
#define REG_PORT_5_OUT_RATE_0		0xFB
#define REG_PORT_1_OUT_RATE_1		0xBC
#define REG_PORT_2_OUT_RATE_1		0xCC
#define REG_PORT_3_OUT_RATE_1		0xDC
#define REG_PORT_4_OUT_RATE_1		0xEC
#define REG_PORT_5_OUT_RATE_1		0xFC
#define REG_PORT_1_OUT_RATE_2		0xBD
#define REG_PORT_2_OUT_RATE_2		0xCD
#define REG_PORT_3_OUT_RATE_2		0xDD
#define REG_PORT_4_OUT_RATE_2		0xED
#define REG_PORT_5_OUT_RATE_2		0xFD
#define REG_PORT_1_OUT_RATE_3		0xBE
#define REG_PORT_2_OUT_RATE_3		0xCE
#define REG_PORT_3_OUT_RATE_3		0xDE
#define REG_PORT_4_OUT_RATE_3		0xEE
#define REG_PORT_5_OUT_RATE_3		0xFE

/* PME */

#define SW_PME_OUTPUT_ENABLE		BIT(1)
#define SW_PME_ACTIVE_HIGH		BIT(0)

#define PORT_MAGIC_PACKET_DETECT	BIT(2)
#define PORT_LINK_UP_DETECT		BIT(1)
#define PORT_ENERGY_DETECT		BIT(0)

/* ACL */

#define ACL_FIRST_RULE_M		0xF

#define ACL_MODE_M			0x3
#define ACL_MODE_S			4
#define ACL_MODE_DISABLE		0
#define ACL_MODE_LAYER_2		1
#define ACL_MODE_LAYER_3		2
#define ACL_MODE_LAYER_4		3
#define ACL_ENABLE_M			0x3
#define ACL_ENABLE_S			2
#define ACL_ENABLE_2_COUNT		0
#define ACL_ENABLE_2_TYPE		1
#define ACL_ENABLE_2_MAC		2
#define ACL_ENABLE_2_BOTH		3
#define ACL_ENABLE_3_IP			1
#define ACL_ENABLE_3_SRC_DST_COMP	2
#define ACL_ENABLE_4_PROTOCOL		0
#define ACL_ENABLE_4_TCP_PORT_COMP	1
#define ACL_ENABLE_4_UDP_PORT_COMP	2
#define ACL_ENABLE_4_TCP_SEQN_COMP	3
#define ACL_SRC				BIT(1)
#define ACL_EQUAL			BIT(0)

#define ACL_MAX_PORT			0xFFFF

#define ACL_MIN_PORT			0xFFFF
#define ACL_IP_ADDR			0xFFFFFFFF
#define ACL_TCP_SEQNUM			0xFFFFFFFF

#define ACL_RESERVED			0xF8
#define ACL_PORT_MODE_M			0x3
#define ACL_PORT_MODE_S			1
#define ACL_PORT_MODE_DISABLE		0
#define ACL_PORT_MODE_EITHER		1
#define ACL_PORT_MODE_IN_RANGE		2
#define ACL_PORT_MODE_OUT_OF_RANGE	3

#define ACL_TCP_FLAG_ENABLE		BIT(0)

#define ACL_TCP_FLAG_M			0xFF

#define ACL_TCP_FLAG			0xFF
#define ACL_ETH_TYPE			0xFFFF
#define ACL_IP_M			0xFFFFFFFF

#define ACL_PRIO_MODE_M			0x3
#define ACL_PRIO_MODE_S			6
#define ACL_PRIO_MODE_DISABLE		0
#define ACL_PRIO_MODE_HIGHER		1
#define ACL_PRIO_MODE_LOWER		2
#define ACL_PRIO_MODE_REPLACE		3
#define ACL_PRIO_M			0x7
#define ACL_PRIO_S			3
#define ACL_VLAN_PRIO_REPLACE		BIT(2)
#define ACL_VLAN_PRIO_M			0x7
#define ACL_VLAN_PRIO_HI_M		0x3

#define ACL_VLAN_PRIO_LO_M		0x8
#define ACL_VLAN_PRIO_S			7
#define ACL_MAP_MODE_M			0x3
#define ACL_MAP_MODE_S			5
#define ACL_MAP_MODE_DISABLE		0
#define ACL_MAP_MODE_OR			1
#define ACL_MAP_MODE_AND		2
#define ACL_MAP_MODE_REPLACE		3
#define ACL_MAP_PORT_M			0x1F

#define ACL_CNT_M			(BIT(11) - 1)
#define ACL_CNT_S			5
#define ACL_MSEC_UNIT			BIT(4)
#define ACL_INTR_MODE			BIT(3)

#define REG_PORT_ACL_BYTE_EN_MSB	0x10

#define ACL_BYTE_EN_MSB_M		0x3F

#define REG_PORT_ACL_BYTE_EN_LSB	0x11

#define ACL_ACTION_START		0xA
#define ACL_ACTION_LEN			2
#define ACL_INTR_CNT_START		0xB
#define ACL_RULESET_START		0xC
#define ACL_RULESET_LEN			2
#define ACL_TABLE_LEN			14

#define ACL_ACTION_ENABLE		0x000C
#define ACL_MATCH_ENABLE		0x1FF0
#define ACL_RULESET_ENABLE		0x2003
#define ACL_BYTE_ENABLE			((ACL_BYTE_EN_MSB_M << 8) | 0xFF)
#define ACL_MODE_ENABLE			(0x10 << 8)

#define REG_PORT_ACL_CTRL_0		0x12

#define PORT_ACL_WRITE_DONE		BIT(6)
#define PORT_ACL_READ_DONE		BIT(5)
#define PORT_ACL_WRITE			BIT(4)
#define PORT_ACL_INDEX_M		0xF

#define REG_PORT_ACL_CTRL_1		0x13

#define PORT_ACL_FORCE_DLR_MISS		BIT(0)

#ifndef PHY_REG_CTRL
#define PHY_REG_CTRL			0

#define PHY_RESET			BIT(15)
#define PHY_LOOPBACK			BIT(14)
#define PHY_SPEED_100MBIT		BIT(13)
#define PHY_AUTO_NEG_ENABLE		BIT(12)
#define PHY_POWER_DOWN			BIT(11)
#define PHY_MII_DISABLE			BIT(10)
#define PHY_AUTO_NEG_RESTART		BIT(9)
#define PHY_FULL_DUPLEX			BIT(8)
#define PHY_COLLISION_TEST_NOT		BIT(7)
#define PHY_HP_MDIX			BIT(5)
#define PHY_FORCE_MDIX			BIT(4)
#define PHY_AUTO_MDIX_DISABLE		BIT(3)
#define PHY_REMOTE_FAULT_DISABLE	BIT(2)
#define PHY_TRANSMIT_DISABLE		BIT(1)
#define PHY_LED_DISABLE			BIT(0)

#define PHY_REG_STATUS			1

#define PHY_100BT4_CAPABLE		BIT(15)
#define PHY_100BTX_FD_CAPABLE		BIT(14)
#define PHY_100BTX_CAPABLE		BIT(13)
#define PHY_10BT_FD_CAPABLE		BIT(12)
#define PHY_10BT_CAPABLE		BIT(11)
#define PHY_MII_SUPPRESS_CAPABLE_NOT	BIT(6)
#define PHY_AUTO_NEG_ACKNOWLEDGE	BIT(5)
#define PHY_REMOTE_FAULT		BIT(4)
#define PHY_AUTO_NEG_CAPABLE		BIT(3)
#define PHY_LINK_STATUS			BIT(2)
#define PHY_JABBER_DETECT_NOT		BIT(1)
#define PHY_EXTENDED_CAPABILITY		BIT(0)

#define PHY_REG_ID_1			2
#define PHY_REG_ID_2			3

#define PHY_REG_AUTO_NEGOTIATION	4

#define PHY_AUTO_NEG_NEXT_PAGE_NOT	BIT(15)
#define PHY_AUTO_NEG_REMOTE_FAULT_NOT	BIT(13)
#define PHY_AUTO_NEG_SYM_PAUSE		BIT(10)
#define PHY_AUTO_NEG_100BT4		BIT(9)
#define PHY_AUTO_NEG_100BTX_FD		BIT(8)
#define PHY_AUTO_NEG_100BTX		BIT(7)
#define PHY_AUTO_NEG_10BT_FD		BIT(6)
#define PHY_AUTO_NEG_10BT		BIT(5)
#define PHY_AUTO_NEG_SELECTOR		0x001F
#define PHY_AUTO_NEG_802_3		0x0001

#define PHY_REG_REMOTE_CAPABILITY	5

#define PHY_REMOTE_NEXT_PAGE_NOT	BIT(15)
#define PHY_REMOTE_ACKNOWLEDGE_NOT	BIT(14)
#define PHY_REMOTE_REMOTE_FAULT_NOT	BIT(13)
#define PHY_REMOTE_SYM_PAUSE		BIT(10)
#define PHY_REMOTE_100BTX_FD		BIT(8)
#define PHY_REMOTE_100BTX		BIT(7)
#define PHY_REMOTE_10BT_FD		BIT(6)
#define PHY_REMOTE_10BT			BIT(5)
#endif

#define KSZ8795_ID_HI			0x0022
#define KSZ8795_ID_LO			0x1550

#define KSZ8795_SW_ID			0x8795

#define PHY_REG_LINK_MD			0x1D

#define PHY_START_CABLE_DIAG		BIT(15)
#define PHY_CABLE_DIAG_RESULT		0x6000
#define PHY_CABLE_STAT_NORMAL		0x0000
#define PHY_CABLE_STAT_OPEN		0x2000
#define PHY_CABLE_STAT_SHORT		0x4000
#define PHY_CABLE_STAT_FAILED		0x6000
#define PHY_CABLE_10M_SHORT		BIT(12)
#define PHY_CABLE_FAULT_COUNTER		0x01FF

#define PHY_REG_PHY_CTRL		0x1F

#define PHY_MODE_M			0x7
#define PHY_MODE_S			8
#define PHY_STAT_REVERSED_POLARITY	BIT(5)
#define PHY_STAT_MDIX			BIT(4)
#define PHY_FORCE_LINK			BIT(3)
#define PHY_POWER_SAVING_ENABLE		BIT(2)
#define PHY_REMOTE_LOOPBACK		BIT(1)

/* Chip resource */

#define PRIO_QUEUES			4

#define KS_PRIO_IN_REG			4

#define TOTAL_PORT_NUM			5

/* Host port can only be last of them. */
#define SWITCH_PORT_NUM			(TOTAL_PORT_NUM - 1)

#define KSZ8795_COUNTER_NUM		0x20
#define TOTAL_KSZ8795_COUNTER_NUM	(KSZ8795_COUNTER_NUM + 4)

#define SWITCH_COUNTER_NUM		KSZ8795_COUNTER_NUM
#define TOTAL_SWITCH_COUNTER_NUM	TOTAL_KSZ8795_COUNTER_NUM

/* Common names used by other drivers */

#define P_BCAST_STORM_CTRL		REG_PORT_CTRL_0
#define P_PRIO_CTRL			REG_PORT_CTRL_0
#define P_TAG_CTRL			REG_PORT_CTRL_0
#define P_MIRROR_CTRL			REG_PORT_CTRL_1
#define P_802_1P_CTRL			REG_PORT_CTRL_2
#define P_STP_CTRL			REG_PORT_CTRL_2
#define P_LOCAL_CTRL			REG_PORT_CTRL_7
#define P_REMOTE_STATUS			REG_PORT_STATUS_0
#define P_FORCE_CTRL			REG_PORT_CTRL_9
#define P_NEG_RESTART_CTRL		REG_PORT_CTRL_10
#define P_SPEED_STATUS			REG_PORT_STATUS_1
#define P_LINK_STATUS			REG_PORT_STATUS_2
#define P_PASS_ALL_CTRL			REG_PORT_CTRL_12
#define P_INS_SRC_PVID_CTRL		REG_PORT_CTRL_12
#define P_DROP_TAG_CTRL			REG_PORT_CTRL_13
#define P_RATE_LIMIT_CTRL		REG_PORT_RATE_LIMIT

#define S_UNKNOWN_DA_CTRL		REG_SWITCH_CTRL_12
#define S_FORWARD_INVALID_VID_CTRL	REG_FORWARD_INVALID_VID

#define S_FLUSH_TABLE_CTRL		REG_SW_CTRL_0
#define S_LINK_AGING_CTRL		REG_SW_CTRL_0
#define S_HUGE_PACKET_CTRL		REG_SW_CTRL_1
#define S_MIRROR_CTRL			REG_SW_CTRL_3
#define S_REPLACE_VID_CTRL		REG_SW_CTRL_4
#define S_PASS_PAUSE_CTRL		REG_SW_CTRL_10
#define S_TAIL_TAG_CTRL			REG_SW_CTRL_10
#define S_802_1P_PRIO_CTRL		REG_SW_CTRL_12
#define S_TOS_PRIO_CTRL			REG_TOS_PRIO_CTRL_0
#define S_IPV6_MLD_CTRL			REG_SW_CTRL_21

#define IND_ACC_TABLE(table)		((table) << 8)

/* Driver set switch broadcast storm protection at 10% rate. */
#define BROADCAST_STORM_PROT_RATE	10

/* 148,800 frames * 67 ms / 100 */
#define BROADCAST_STORM_VALUE		9969

/**
 * STATIC_MAC_TABLE_ADDR		00-0000FFFF-FFFFFFFF
 * STATIC_MAC_TABLE_FWD_PORTS		00-001F0000-00000000
 * STATIC_MAC_TABLE_VALID		00-00200000-00000000
 * STATIC_MAC_TABLE_OVERRIDE		00-00400000-00000000
 * STATIC_MAC_TABLE_USE_FID		00-00800000-00000000
 * STATIC_MAC_TABLE_FID			00-7F000000-00000000
 */

#define STATIC_MAC_TABLE_ADDR		0x0000FFFF
#define STATIC_MAC_TABLE_FWD_PORTS	0x001F0000
#define STATIC_MAC_TABLE_VALID		0x00200000
#define STATIC_MAC_TABLE_OVERRIDE	0x00400000
#define STATIC_MAC_TABLE_USE_FID	0x00800000
#define STATIC_MAC_TABLE_FID		0x7F000000

#define STATIC_MAC_FWD_PORTS_S		16
#define STATIC_MAC_FID_S		24

/**
 * VLAN_TABLE_FID			00-007F007F-007F007F
 * VLAN_TABLE_MEMBERSHIP		00-0F800F80-0F800F80
 * VLAN_TABLE_VALID			00-10001000-10001000
 */

#define VLAN_TABLE_FID			0x007F
#define VLAN_TABLE_MEMBERSHIP		0x0F80
#define VLAN_TABLE_VALID		0x1000

#define VLAN_TABLE_MEMBERSHIP_S		7
#define VLAN_TABLE_S			16

/**
 * DYNAMIC_MAC_TABLE_ADDR		00-0000FFFF-FFFFFFFF
 * DYNAMIC_MAC_TABLE_FID		00-007F0000-00000000
 * DYNAMIC_MAC_TABLE_NOT_READY		00-00800000-00000000
 * DYNAMIC_MAC_TABLE_SRC_PORT		00-07000000-00000000
 * DYNAMIC_MAC_TABLE_TIMESTAMP		00-18000000-00000000
 * DYNAMIC_MAC_TABLE_ENTRIES		7F-E0000000-00000000
 * DYNAMIC_MAC_TABLE_MAC_EMPTY		80-00000000-00000000
 */

#define DYNAMIC_MAC_TABLE_ADDR		0x0000FFFF
#define DYNAMIC_MAC_TABLE_FID		0x007F0000
#define DYNAMIC_MAC_TABLE_SRC_PORT	0x07000000
#define DYNAMIC_MAC_TABLE_TIMESTAMP	0x18000000
#define DYNAMIC_MAC_TABLE_ENTRIES	0xE0000000

#define DYNAMIC_MAC_TABLE_NOT_READY	0x80

#define DYNAMIC_MAC_TABLE_ENTRIES_H	0x7F
#define DYNAMIC_MAC_TABLE_MAC_EMPTY	0x80

#define DYNAMIC_MAC_FID_S		16
#define DYNAMIC_MAC_SRC_PORT_S		24
#define DYNAMIC_MAC_TIMESTAMP_S		27
#define DYNAMIC_MAC_ENTRIES_S		29
#define DYNAMIC_MAC_ENTRIES_H_S		3

/**
 * MIB_COUNTER_VALUE			00-00000000-3FFFFFFF
 * MIB_TOTAL_BYTES			00-0000000F-FFFFFFFF
 * MIB_PACKET_DROPPED			00-00000000-0000FFFF
 * MIB_COUNTER_VALID			00-00000020-00000000
 * MIB_COUNTER_OVERFLOW			00-00000040-00000000
 */

#define MIB_COUNTER_OVERFLOW		BIT(6)
#define MIB_COUNTER_VALID		BIT(5)

#define MIB_COUNTER_VALUE		0x3FFFFFFF

#define KS_MIB_TOTAL_RX_0		0x100
#define KS_MIB_TOTAL_TX_0		0x101
#define KS_MIB_PACKET_DROPPED_RX_0	0x102
#define KS_MIB_PACKET_DROPPED_TX_0	0x103
#define KS_MIB_TOTAL_RX_1		0x104
#define KS_MIB_TOTAL_TX_1		0x105
#define KS_MIB_PACKET_DROPPED_TX_1	0x106
#define KS_MIB_PACKET_DROPPED_RX_1	0x107
#define KS_MIB_TOTAL_RX_2		0x108
#define KS_MIB_TOTAL_TX_2		0x109
#define KS_MIB_PACKET_DROPPED_TX_2	0x10A
#define KS_MIB_PACKET_DROPPED_RX_2	0x10B
#define KS_MIB_TOTAL_RX_3		0x10C
#define KS_MIB_TOTAL_TX_3		0x10D
#define KS_MIB_PACKET_DROPPED_TX_3	0x10E
#define KS_MIB_PACKET_DROPPED_RX_3	0x10F
#define KS_MIB_TOTAL_RX_4		0x110
#define KS_MIB_TOTAL_TX_4		0x111
#define KS_MIB_PACKET_DROPPED_TX_4	0x112
#define KS_MIB_PACKET_DROPPED_RX_4	0x113

#define MIB_PACKET_DROPPED		0x0000FFFF

#define MIB_TOTAL_BYTES_H		0x0000000F

#define TAIL_TAG_OVERRIDE		BIT(6)
#define TAIL_TAG_LOOKUP			BIT(7)

#define VLAN_TABLE_ENTRIES		(4096 / 4)
#define FID_ENTRIES			128

#endif
