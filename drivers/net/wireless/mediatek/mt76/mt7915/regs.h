/* SPDX-License-Identifier: ISC */
/* Copyright (C) 2020 MediaTek Inc. */

#ifndef __MT7915_REGS_H
#define __MT7915_REGS_H

/* MCU WFDMA1 */
#define MT_MCU_WFDMA1_BASE		0x3000
#define MT_MCU_WFDMA1(ofs)		(MT_MCU_WFDMA1_BASE + (ofs))

#define MT_MCU_INT_EVENT		MT_MCU_WFDMA1(0x108)
#define MT_MCU_INT_EVENT_DMA_STOPPED	BIT(0)
#define MT_MCU_INT_EVENT_DMA_INIT	BIT(1)
#define MT_MCU_INT_EVENT_SER_TRIGGER	BIT(2)
#define MT_MCU_INT_EVENT_RESET_DONE	BIT(3)

#define MT_PLE_BASE			0x8000
#define MT_PLE(ofs)			(MT_PLE_BASE + (ofs))

#define MT_PLE_FL_Q0_CTRL		MT_PLE(0x1b0)
#define MT_PLE_FL_Q1_CTRL		MT_PLE(0x1b4)
#define MT_PLE_FL_Q2_CTRL		MT_PLE(0x1b8)
#define MT_PLE_FL_Q3_CTRL		MT_PLE(0x1bc)

#define MT_PLE_AC_QEMPTY(ac, n)		MT_PLE(0x300 + 0x10 * (ac) + \
					       ((n) << 2))
#define MT_PLE_AMSDU_PACK_MSDU_CNT(n)	MT_PLE(0x10e0 + ((n) << 2))

#define MT_MDP_BASE			0xf000
#define MT_MDP(ofs)			(MT_MDP_BASE + (ofs))

#define MT_MDP_DCR0			MT_MDP(0x000)
#define MT_MDP_DCR0_DAMSDU_EN		BIT(15)

#define MT_MDP_DCR1			MT_MDP(0x004)
#define MT_MDP_DCR1_MAX_RX_LEN		GENMASK(15, 3)

#define MT_MDP_BNRCFR0(_band)		MT_MDP(0x070 + ((_band) << 8))
#define MT_MDP_RCFR0_MCU_RX_MGMT	GENMASK(5, 4)
#define MT_MDP_RCFR0_MCU_RX_CTL_NON_BAR	GENMASK(7, 6)
#define MT_MDP_RCFR0_MCU_RX_CTL_BAR	GENMASK(9, 8)

#define MT_MDP_BNRCFR1(_band)		MT_MDP(0x074 + ((_band) << 8))
#define MT_MDP_RCFR1_MCU_RX_BYPASS	GENMASK(23, 22)
#define MT_MDP_RCFR1_RX_DROPPED_UCAST	GENMASK(28, 27)
#define MT_MDP_RCFR1_RX_DROPPED_MCAST	GENMASK(30, 29)
#define MT_MDP_TO_HIF			0
#define MT_MDP_TO_WM			1

/* TMAC: band 0(0x21000), band 1(0xa1000) */
#define MT_WF_TMAC_BASE(_band)		((_band) ? 0xa1000 : 0x21000)
#define MT_WF_TMAC(_band, ofs)		(MT_WF_TMAC_BASE(_band) + (ofs))

#define MT_TMAC_CDTR(_band)		MT_WF_TMAC(_band, 0x090)
#define MT_TMAC_ODTR(_band)		MT_WF_TMAC(_band, 0x094)
#define MT_TIMEOUT_VAL_PLCP		GENMASK(15, 0)
#define MT_TIMEOUT_VAL_CCA		GENMASK(31, 16)

#define MT_TMAC_ICR0(_band)		MT_WF_TMAC(_band, 0x0a4)
#define MT_IFS_EIFS			GENMASK(8, 0)
#define MT_IFS_RIFS			GENMASK(14, 10)
#define MT_IFS_SIFS			GENMASK(22, 16)
#define MT_IFS_SLOT			GENMASK(30, 24)

#define MT_TMAC_CTCR0(_band)			MT_WF_TMAC(_band, 0x0f4)
#define MT_TMAC_CTCR0_INS_DDLMT_REFTIME		GENMASK(5, 0)
#define MT_TMAC_CTCR0_INS_DDLMT_EN		BIT(17)
#define MT_TMAC_CTCR0_INS_DDLMT_VHT_SMPDU_EN	BIT(18)

/* DMA Band 0 */
#define MT_WF_DMA_BASE			0x21e00
#define MT_WF_DMA(ofs)			(MT_WF_DMA_BASE + (ofs))

#define MT_DMA_DCR0			MT_WF_DMA(0x000)
#define MT_DMA_DCR0_MAX_RX_LEN		GENMASK(15, 3)
#define MT_DMA_DCR0_RXD_G5_EN		BIT(23)

/* ETBF: band 0(0x24000), band 1(0xa4000) */
#define MT_WF_ETBF_BASE(_band)		((_band) ? 0xa4000 : 0x24000)
#define MT_WF_ETBF(_band, ofs)		(MT_WF_ETBF_BASE(_band) + (ofs))

#define MT_ETBF_TX_NDP_BFRP(_band)	MT_WF_ETBF(_band, 0x040)
#define MT_ETBF_TX_FB_CPL		GENMASK(31, 16)
#define MT_ETBF_TX_FB_TRI		GENMASK(15, 0)

#define MT_ETBF_TX_APP_CNT(_band)	MT_WF_ETBF(_band, 0x0f0)
#define MT_ETBF_TX_IBF_CNT		GENMASK(31, 16)
#define MT_ETBF_TX_EBF_CNT		GENMASK(15, 0)

#define MT_ETBF_RX_FB_CNT(_band)	MT_WF_ETBF(_band, 0x0f8)
#define MT_ETBF_RX_FB_ALL		GENMASK(31, 24)
#define MT_ETBF_RX_FB_HE		GENMASK(23, 16)
#define MT_ETBF_RX_FB_VHT		GENMASK(15, 8)
#define MT_ETBF_RX_FB_HT		GENMASK(7, 0)

/* LPON: band 0(0x24200), band 1(0xa4200) */
#define MT_WF_LPON_BASE(_band)		((_band) ? 0xa4200 : 0x24200)
#define MT_WF_LPON(_band, ofs)		(MT_WF_LPON_BASE(_band) + (ofs))

#define MT_LPON_UTTR0(_band)		MT_WF_LPON(_band, 0x080)
#define MT_LPON_UTTR1(_band)		MT_WF_LPON(_band, 0x084)

#define MT_LPON_TCR(_band, n)		MT_WF_LPON(_band, 0x0a8 + (n) * 4)
#define MT_LPON_TCR_SW_MODE		GENMASK(1, 0)
#define MT_LPON_TCR_SW_WRITE		BIT(0)

/* MIB: band 0(0x24800), band 1(0xa4800) */
#define MT_WF_MIB_BASE(_band)		((_band) ? 0xa4800 : 0x24800)
#define MT_WF_MIB(_band, ofs)		(MT_WF_MIB_BASE(_band) + (ofs))

#define MT_MIB_SDR3(_band)		MT_WF_MIB(_band, 0x014)
#define MT_MIB_SDR3_FCS_ERR_MASK	GENMASK(15, 0)

#define MT_MIB_SDR9(_band)		MT_WF_MIB(_band, 0x02c)
#define MT_MIB_SDR9_BUSY_MASK		GENMASK(23, 0)

#define MT_MIB_SDR16(_band)		MT_WF_MIB(_band, 0x048)
#define MT_MIB_SDR16_BUSY_MASK		GENMASK(23, 0)

#define MT_MIB_SDR36(_band)		MT_WF_MIB(_band, 0x098)
#define MT_MIB_SDR36_TXTIME_MASK	GENMASK(23, 0)
#define MT_MIB_SDR37(_band)		MT_WF_MIB(_band, 0x09c)
#define MT_MIB_SDR37_RXTIME_MASK	GENMASK(23, 0)

#define MT_MIB_DR11(_band)		MT_WF_MIB(_band, 0x0cc)

#define MT_MIB_MB_SDR0(_band, n)	MT_WF_MIB(_band, 0x100 + ((n) << 4))
#define MT_MIB_RTS_RETRIES_COUNT_MASK	GENMASK(31, 16)
#define MT_MIB_RTS_COUNT_MASK		GENMASK(15, 0)

#define MT_MIB_MB_SDR1(_band, n)	MT_WF_MIB(_band, 0x104 + ((n) << 4))
#define MT_MIB_BA_MISS_COUNT_MASK	GENMASK(15, 0)
#define MT_MIB_ACK_FAIL_COUNT_MASK	GENMASK(31, 16)

#define MT_MIB_MB_SDR2(_band, n)	MT_WF_MIB(_band, 0x108 + ((n) << 4))
#define MT_MIB_FRAME_RETRIES_COUNT_MASK	GENMASK(15, 0)

#define MT_TX_AGG_CNT(_band, n)		MT_WF_MIB(_band, 0x0a8 + ((n) << 2))
#define MT_TX_AGG_CNT2(_band, n)	MT_WF_MIB(_band, 0x164 + ((n) << 2))
#define MT_MIB_ARNG(_band, n)		MT_WF_MIB(_band, 0x4b8 + ((n) << 2))
#define MT_MIB_ARNCR_RANGE(val, n)	(((val) >> ((n) << 3)) & GENMASK(7, 0))

#define MT_WTBLON_TOP_BASE		0x34000
#define MT_WTBLON_TOP(ofs)		(MT_WTBLON_TOP_BASE + (ofs))
#define MT_WTBLON_TOP_WDUCR		MT_WTBLON_TOP(0x0)
#define MT_WTBLON_TOP_WDUCR_GROUP	GENMASK(2, 0)

#define MT_WTBL_UPDATE			MT_WTBLON_TOP(0x030)
#define MT_WTBL_UPDATE_WLAN_IDX		GENMASK(9, 0)
#define MT_WTBL_UPDATE_ADM_COUNT_CLEAR	BIT(12)
#define MT_WTBL_UPDATE_BUSY		BIT(31)

#define MT_WTBL_BASE			0x38000
#define MT_WTBL_LMAC_ID			GENMASK(14, 8)
#define MT_WTBL_LMAC_DW			GENMASK(7, 2)
#define MT_WTBL_LMAC_OFFS(_id, _dw)	(MT_WTBL_BASE | \
					FIELD_PREP(MT_WTBL_LMAC_ID, _id) | \
					FIELD_PREP(MT_WTBL_LMAC_DW, _dw))

/* AGG: band 0(0x20800), band 1(0xa0800) */
#define MT_WF_AGG_BASE(_band)		((_band) ? 0xa0800 : 0x20800)
#define MT_WF_AGG(_band, ofs)		(MT_WF_AGG_BASE(_band) + (ofs))

#define MT_AGG_ACR0(_band)		MT_WF_AGG(_band, 0x084)
#define MT_AGG_ACR_CFEND_RATE		GENMASK(13, 0)
#define MT_AGG_ACR_BAR_RATE		GENMASK(29, 16)

/* ARB: band 0(0x20c00), band 1(0xa0c00) */
#define MT_WF_ARB_BASE(_band)		((_band) ? 0xa0c00 : 0x20c00)
#define MT_WF_ARB(_band, ofs)		(MT_WF_ARB_BASE(_band) + (ofs))

#define MT_ARB_SCR(_band)		MT_WF_ARB(_band, 0x080)
#define MT_ARB_SCR_TX_DISABLE		BIT(8)
#define MT_ARB_SCR_RX_DISABLE		BIT(9)

/* RMAC: band 0(0x21400), band 1(0xa1400) */
#define MT_WF_RMAC_BASE(_band)		((_band) ? 0xa1400 : 0x21400)
#define MT_WF_RMAC(_band, ofs)		(MT_WF_RMAC_BASE(_band) + (ofs))

#define MT_WF_RFCR(_band)		MT_WF_RMAC(_band, 0x000)
#define MT_WF_RFCR_DROP_STBC_MULTI	BIT(0)
#define MT_WF_RFCR_DROP_FCSFAIL		BIT(1)
#define MT_WF_RFCR_DROP_VERSION		BIT(3)
#define MT_WF_RFCR_DROP_PROBEREQ	BIT(4)
#define MT_WF_RFCR_DROP_MCAST		BIT(5)
#define MT_WF_RFCR_DROP_BCAST		BIT(6)
#define MT_WF_RFCR_DROP_MCAST_FILTERED	BIT(7)
#define MT_WF_RFCR_DROP_A3_MAC		BIT(8)
#define MT_WF_RFCR_DROP_A3_BSSID	BIT(9)
#define MT_WF_RFCR_DROP_A2_BSSID	BIT(10)
#define MT_WF_RFCR_DROP_OTHER_BEACON	BIT(11)
#define MT_WF_RFCR_DROP_FRAME_REPORT	BIT(12)
#define MT_WF_RFCR_DROP_CTL_RSV		BIT(13)
#define MT_WF_RFCR_DROP_CTS		BIT(14)
#define MT_WF_RFCR_DROP_RTS		BIT(15)
#define MT_WF_RFCR_DROP_DUPLICATE	BIT(16)
#define MT_WF_RFCR_DROP_OTHER_BSS	BIT(17)
#define MT_WF_RFCR_DROP_OTHER_UC	BIT(18)
#define MT_WF_RFCR_DROP_OTHER_TIM	BIT(19)
#define MT_WF_RFCR_DROP_NDPA		BIT(20)
#define MT_WF_RFCR_DROP_UNWANTED_CTL	BIT(21)

#define MT_WF_RFCR1(_band)		MT_WF_RMAC(_band, 0x004)
#define MT_WF_RFCR1_DROP_ACK		BIT(4)
#define MT_WF_RFCR1_DROP_BF_POLL	BIT(5)
#define MT_WF_RFCR1_DROP_BA		BIT(6)
#define MT_WF_RFCR1_DROP_CFEND		BIT(7)
#define MT_WF_RFCR1_DROP_CFACK		BIT(8)

#define MT_WF_RMAC_MIB_TIME0(_band)	MT_WF_RMAC(_band, 0x03c4)
#define MT_WF_RMAC_MIB_RXTIME_CLR	BIT(31)
#define MT_WF_RMAC_MIB_RXTIME_EN	BIT(30)

#define MT_WF_RMAC_MIB_AIRTIME14(_band)	MT_WF_RMAC(_band, 0x03b8)
#define MT_MIB_OBSSTIME_MASK		GENMASK(23, 0)
#define MT_WF_RMAC_MIB_AIRTIME0(_band)	MT_WF_RMAC(_band, 0x0380)

/* WFDMA0 */
#define MT_WFDMA0_BASE			0xd4000
#define MT_WFDMA0(ofs)			(MT_WFDMA0_BASE + (ofs))

#define MT_WFDMA0_RST			MT_WFDMA0(0x100)
#define MT_WFDMA0_RST_LOGIC_RST		BIT(4)
#define MT_WFDMA0_RST_DMASHDL_ALL_RST	BIT(5)

#define MT_WFDMA0_BUSY_ENA		MT_WFDMA0(0x13c)
#define MT_WFDMA0_BUSY_ENA_TX_FIFO0	BIT(0)
#define MT_WFDMA0_BUSY_ENA_TX_FIFO1	BIT(1)
#define MT_WFDMA0_BUSY_ENA_RX_FIFO	BIT(2)

#define MT_WFDMA0_GLO_CFG		MT_WFDMA0(0x208)
#define MT_WFDMA0_GLO_CFG_TX_DMA_EN	BIT(0)
#define MT_WFDMA0_GLO_CFG_RX_DMA_EN	BIT(2)

#define MT_WFDMA0_RST_DTX_PTR		MT_WFDMA0(0x20c)
#define MT_WFDMA0_PRI_DLY_INT_CFG0	MT_WFDMA0(0x2f0)

#define MT_RX_DATA_RING_BASE		MT_WFDMA0(0x500)

#define MT_WFDMA0_RX_RING0_EXT_CTRL	MT_WFDMA0(0x680)
#define MT_WFDMA0_RX_RING1_EXT_CTRL	MT_WFDMA0(0x684)
#define MT_WFDMA0_RX_RING2_EXT_CTRL	MT_WFDMA0(0x688)

/* WFDMA1 */
#define MT_WFDMA1_BASE			0xd5000
#define MT_WFDMA1(ofs)			(MT_WFDMA1_BASE + (ofs))

#define MT_WFDMA1_RST			MT_WFDMA1(0x100)
#define MT_WFDMA1_RST_LOGIC_RST		BIT(4)
#define MT_WFDMA1_RST_DMASHDL_ALL_RST	BIT(5)

#define MT_WFDMA1_BUSY_ENA		MT_WFDMA1(0x13c)
#define MT_WFDMA1_BUSY_ENA_TX_FIFO0	BIT(0)
#define MT_WFDMA1_BUSY_ENA_TX_FIFO1	BIT(1)
#define MT_WFDMA1_BUSY_ENA_RX_FIFO	BIT(2)

#define MT_MCU_CMD			MT_WFDMA1(0x1f0)
#define MT_MCU_CMD_STOP_DMA_FW_RELOAD	BIT(1)
#define MT_MCU_CMD_STOP_DMA		BIT(2)
#define MT_MCU_CMD_RESET_DONE		BIT(3)
#define MT_MCU_CMD_RECOVERY_DONE	BIT(4)
#define MT_MCU_CMD_NORMAL_STATE		BIT(5)
#define MT_MCU_CMD_ERROR_MASK		GENMASK(5, 1)

#define MT_WFDMA1_GLO_CFG		MT_WFDMA1(0x208)
#define MT_WFDMA1_GLO_CFG_TX_DMA_EN	BIT(0)
#define MT_WFDMA1_GLO_CFG_RX_DMA_EN	BIT(2)
#define MT_WFDMA1_GLO_CFG_OMIT_TX_INFO	BIT(28)
#define MT_WFDMA1_GLO_CFG_OMIT_RX_INFO	BIT(27)

#define MT_WFDMA1_RST_DTX_PTR		MT_WFDMA1(0x20c)
#define MT_WFDMA1_PRI_DLY_INT_CFG0	MT_WFDMA1(0x2f0)

#define MT_TX_RING_BASE			MT_WFDMA1(0x300)
#define MT_RX_EVENT_RING_BASE		MT_WFDMA1(0x500)

#define MT_WFDMA1_TX_RING0_EXT_CTRL	MT_WFDMA1(0x600)
#define MT_WFDMA1_TX_RING1_EXT_CTRL	MT_WFDMA1(0x604)
#define MT_WFDMA1_TX_RING2_EXT_CTRL	MT_WFDMA1(0x608)
#define MT_WFDMA1_TX_RING3_EXT_CTRL	MT_WFDMA1(0x60c)
#define MT_WFDMA1_TX_RING4_EXT_CTRL	MT_WFDMA1(0x610)
#define MT_WFDMA1_TX_RING5_EXT_CTRL	MT_WFDMA1(0x614)
#define MT_WFDMA1_TX_RING6_EXT_CTRL	MT_WFDMA1(0x618)
#define MT_WFDMA1_TX_RING7_EXT_CTRL	MT_WFDMA1(0x61c)

#define MT_WFDMA1_TX_RING16_EXT_CTRL	MT_WFDMA1(0x640)
#define MT_WFDMA1_TX_RING17_EXT_CTRL	MT_WFDMA1(0x644)
#define MT_WFDMA1_TX_RING18_EXT_CTRL	MT_WFDMA1(0x648)
#define MT_WFDMA1_TX_RING19_EXT_CTRL	MT_WFDMA1(0x64c)
#define MT_WFDMA1_TX_RING20_EXT_CTRL	MT_WFDMA1(0x650)
#define MT_WFDMA1_TX_RING21_EXT_CTRL	MT_WFDMA1(0x654)
#define MT_WFDMA1_TX_RING22_EXT_CTRL	MT_WFDMA1(0x658)
#define MT_WFDMA1_TX_RING23_EXT_CTRL	MT_WFDMA1(0x65c)

#define MT_WFDMA1_RX_RING0_EXT_CTRL	MT_WFDMA1(0x680)
#define MT_WFDMA1_RX_RING1_EXT_CTRL	MT_WFDMA1(0x684)
#define MT_WFDMA1_RX_RING2_EXT_CTRL	MT_WFDMA1(0x688)
#define MT_WFDMA1_RX_RING3_EXT_CTRL	MT_WFDMA1(0x68c)

/* WFDMA CSR */
#define MT_WFDMA_EXT_CSR_BASE		0xd7000
#define MT_WFDMA_EXT_CSR(ofs)		(MT_WFDMA_EXT_CSR_BASE + (ofs))

#define MT_INT_SOURCE_CSR		MT_WFDMA_EXT_CSR(0x10)
#define MT_INT_MASK_CSR			MT_WFDMA_EXT_CSR(0x14)
#define MT_INT_RX_DONE_DATA		BIT(16)
#define MT_INT_RX_DONE_WM		BIT(0)
#define MT_INT_RX_DONE_WA		BIT(1)
#define MT_INT_RX_DONE(_n)		((_n) ? BIT((_n) - 1) : BIT(16))
#define MT_INT_RX_DONE_ALL		(BIT(0) | BIT(1) | BIT(16))
#define MT_INT_TX_DONE_ALL		(BIT(15) | GENMASK(27, 26) | BIT(30))
#define MT_INT_MCU_CMD			BIT(29)

#define MT_WFDMA_EXT_CSR_HIF_MISC	MT_WFDMA_EXT_CSR(0x44)
#define MT_WFDMA_EXT_CSR_HIF_MISC_BUSY	BIT(0)

/* WFDMA0 PCIE1 */
#define MT_WFDMA0_PCIE1_BASE			0xd8000
#define MT_WFDMA0_PCIE1(ofs)			(MT_WFDMA0_PCIE1_BASE + (ofs))

#define MT_WFDMA0_PCIE1_BUSY_ENA		MT_WFDMA0_PCIE1(0x13c)
#define MT_WFDMA0_PCIE1_BUSY_ENA_TX_FIFO0	BIT(0)
#define MT_WFDMA0_PCIE1_BUSY_ENA_TX_FIFO1	BIT(1)
#define MT_WFDMA0_PCIE1_BUSY_ENA_RX_FIFO	BIT(2)

/* WFDMA1 PCIE1 */
#define MT_WFDMA1_PCIE1_BASE			0xd9000
#define MT_WFDMA1_PCIE1(ofs)			(MT_WFDMA0_PCIE1_BASE + (ofs))

#define MT_WFDMA1_PCIE1_BUSY_ENA		MT_WFDMA1_PCIE1(0x13c)
#define MT_WFDMA1_PCIE1_BUSY_ENA_TX_FIFO0	BIT(0)
#define MT_WFDMA1_PCIE1_BUSY_ENA_TX_FIFO1	BIT(1)
#define MT_WFDMA1_PCIE1_BUSY_ENA_RX_FIFO	BIT(2)

#define MT_INFRA_CFG_BASE		0xf1000
#define MT_INFRA(ofs)			(MT_INFRA_CFG_BASE + (ofs))

#define MT_HIF_REMAP_L1			MT_INFRA(0x1ac)
#define MT_HIF_REMAP_L1_MASK		GENMASK(15, 0)
#define MT_HIF_REMAP_L1_OFFSET		GENMASK(15, 0)
#define MT_HIF_REMAP_L1_BASE		GENMASK(31, 16)
#define MT_HIF_REMAP_BASE_L1		0xe0000

#define MT_HIF_REMAP_L2			MT_INFRA(0x1b0)
#define MT_HIF_REMAP_L2_MASK		GENMASK(19, 0)
#define MT_HIF_REMAP_L2_OFFSET		GENMASK(11, 0)
#define MT_HIF_REMAP_L2_BASE		GENMASK(31, 12)
#define MT_HIF_REMAP_BASE_L2		0x00000

#define MT_TOP_BASE			0x18060000
#define MT_TOP(ofs)			(MT_TOP_BASE + (ofs))

#define MT_TOP_LPCR_HOST_BAND0		MT_TOP(0x10)
#define MT_TOP_LPCR_HOST_FW_OWN		BIT(0)
#define MT_TOP_LPCR_HOST_DRV_OWN	BIT(1)

#define MT_TOP_MISC			MT_TOP(0xf0)
#define MT_TOP_MISC_FW_STATE		GENMASK(2, 0)

#define MT_HW_BOUND			0x70010020
#define MT_HW_CHIPID			0x70010200
#define MT_HW_REV			0x70010204

#define MT_PCIE_MAC_BASE		0x74030000
#define MT_PCIE_MAC(ofs)		(MT_PCIE_MAC_BASE + (ofs))
#define MT_PCIE_MAC_INT_ENABLE		MT_PCIE_MAC(0x188)

/* PHY: band 0(0x83080000), band 1(0x83090000) */
#define MT_WF_PHY_BASE			0x83080000
#define MT_WF_PHY(ofs)			(MT_WF_PHY_BASE + (ofs))

#define MT_WF_PHY_RX_CTRL1(_phy)	MT_WF_PHY(0x2004 + ((_phy) << 16))
#define MT_WF_PHY_RX_CTRL1_STSCNT_EN	GENMASK(11, 9)

#endif
