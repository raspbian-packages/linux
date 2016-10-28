/*
 * Header File to describe the DMA descriptors and related definitions specific
 * for DesignWare databook 4.xx.
 *
 * Copyright (C) 2015  STMicroelectronics Ltd
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * Author: Alexandre Torgue <alexandre.torgue@st.com>
 */

#ifndef __DWMAC4_DESCS_H__
#define __DWMAC4_DESCS_H__

#include <linux/bitops.h>

/* Normal transmit descriptor defines (without split feature) */

/* TDES2 (read format) */
#define TDES2_BUFFER1_SIZE_MASK		GENMASK(13, 0)
#define TDES2_VLAN_TAG_MASK		GENMASK(15, 14)
#define TDES2_BUFFER2_SIZE_MASK		GENMASK(29, 16)
#define TDES2_BUFFER2_SIZE_MASK_SHIFT	16
#define TDES2_TIMESTAMP_ENABLE		BIT(30)
#define TDES2_INTERRUPT_ON_COMPLETION	BIT(31)

/* TDES3 (read format) */
#define TDES3_PACKET_SIZE_MASK		GENMASK(14, 0)
#define TDES3_CHECKSUM_INSERTION_MASK	GENMASK(17, 16)
#define TDES3_CHECKSUM_INSERTION_SHIFT	16
#define TDES3_TCP_PKT_PAYLOAD_MASK	GENMASK(17, 0)
#define TDES3_TCP_SEGMENTATION_ENABLE	BIT(18)
#define TDES3_HDR_LEN_SHIFT		19
#define TDES3_SLOT_NUMBER_MASK		GENMASK(22, 19)
#define TDES3_SA_INSERT_CTRL_MASK	GENMASK(25, 23)
#define TDES3_CRC_PAD_CTRL_MASK		GENMASK(27, 26)

/* TDES3 (write back format) */
#define TDES3_IP_HDR_ERROR		BIT(0)
#define TDES3_DEFERRED			BIT(1)
#define TDES3_UNDERFLOW_ERROR		BIT(2)
#define TDES3_EXCESSIVE_DEFERRAL	BIT(3)
#define TDES3_COLLISION_COUNT_MASK	GENMASK(7, 4)
#define TDES3_COLLISION_COUNT_SHIFT	4
#define TDES3_EXCESSIVE_COLLISION	BIT(8)
#define TDES3_LATE_COLLISION		BIT(9)
#define TDES3_NO_CARRIER		BIT(10)
#define TDES3_LOSS_CARRIER		BIT(11)
#define TDES3_PAYLOAD_ERROR		BIT(12)
#define TDES3_PACKET_FLUSHED		BIT(13)
#define TDES3_JABBER_TIMEOUT		BIT(14)
#define TDES3_ERROR_SUMMARY		BIT(15)
#define TDES3_TIMESTAMP_STATUS		BIT(17)
#define TDES3_TIMESTAMP_STATUS_SHIFT	17

/* TDES3 context */
#define TDES3_CTXT_TCMSSV		BIT(26)

/* TDES3 Common */
#define TDES3_LAST_DESCRIPTOR		BIT(28)
#define TDES3_LAST_DESCRIPTOR_SHIFT	28
#define TDES3_FIRST_DESCRIPTOR		BIT(29)
#define TDES3_CONTEXT_TYPE		BIT(30)

/* TDS3 use for both format (read and write back) */
#define TDES3_OWN			BIT(31)
#define TDES3_OWN_SHIFT			31

/* Normal receive descriptor defines (without split feature) */

/* RDES0 (write back format) */
#define RDES0_VLAN_TAG_MASK		GENMASK(15, 0)

/* RDES1 (write back format) */
#define RDES1_IP_PAYLOAD_TYPE_MASK	GENMASK(2, 0)
#define RDES1_IP_HDR_ERROR		BIT(3)
#define RDES1_IPV4_HEADER		BIT(4)
#define RDES1_IPV6_HEADER		BIT(5)
#define RDES1_IP_CSUM_BYPASSED		BIT(6)
#define RDES1_IP_CSUM_ERROR		BIT(7)
#define RDES1_PTP_MSG_TYPE_MASK		GENMASK(11, 8)
#define RDES1_PTP_PACKET_TYPE		BIT(12)
#define RDES1_PTP_VER			BIT(13)
#define RDES1_TIMESTAMP_AVAILABLE	BIT(14)
#define RDES1_TIMESTAMP_AVAILABLE_SHIFT	14
#define RDES1_TIMESTAMP_DROPPED		BIT(15)
#define RDES1_IP_TYPE1_CSUM_MASK	GENMASK(31, 16)

/* RDES2 (write back format) */
#define RDES2_L3_L4_HEADER_SIZE_MASK	GENMASK(9, 0)
#define RDES2_VLAN_FILTER_STATUS	BIT(15)
#define RDES2_SA_FILTER_FAIL		BIT(16)
#define RDES2_DA_FILTER_FAIL		BIT(17)
#define RDES2_HASH_FILTER_STATUS	BIT(18)
#define RDES2_MAC_ADDR_MATCH_MASK	GENMASK(26, 19)
#define RDES2_HASH_VALUE_MATCH_MASK	GENMASK(26, 19)
#define RDES2_L3_FILTER_MATCH		BIT(27)
#define RDES2_L4_FILTER_MATCH		BIT(28)
#define RDES2_L3_L4_FILT_NB_MATCH_MASK	GENMASK(27, 26)
#define RDES2_L3_L4_FILT_NB_MATCH_SHIFT	26

/* RDES3 (write back format) */
#define RDES3_PACKET_SIZE_MASK		GENMASK(14, 0)
#define RDES3_ERROR_SUMMARY		BIT(15)
#define RDES3_PACKET_LEN_TYPE_MASK	GENMASK(18, 16)
#define RDES3_DRIBBLE_ERROR		BIT(19)
#define RDES3_RECEIVE_ERROR		BIT(20)
#define RDES3_OVERFLOW_ERROR		BIT(21)
#define RDES3_RECEIVE_WATCHDOG		BIT(22)
#define RDES3_GIANT_PACKET		BIT(23)
#define RDES3_CRC_ERROR			BIT(24)
#define RDES3_RDES0_VALID		BIT(25)
#define RDES3_RDES1_VALID		BIT(26)
#define RDES3_RDES2_VALID		BIT(27)
#define RDES3_LAST_DESCRIPTOR		BIT(28)
#define RDES3_FIRST_DESCRIPTOR		BIT(29)
#define RDES3_CONTEXT_DESCRIPTOR	BIT(30)

/* RDES3 (read format) */
#define RDES3_BUFFER1_VALID_ADDR	BIT(24)
#define RDES3_BUFFER2_VALID_ADDR	BIT(25)
#define RDES3_INT_ON_COMPLETION_EN	BIT(30)

/* TDS3 use for both format (read and write back) */
#define RDES3_OWN			BIT(31)

#endif /* __DWMAC4_DESCS_H__ */
