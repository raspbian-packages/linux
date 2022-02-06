/* SPDX-License-Identifier: ISC */
/* Copyright (C) 2020 MediaTek Inc. */

#ifndef __MT7921_REGS_H
#define __MT7921_REGS_H

/* MCU WFDMA1 */
#define MT_MCU_WFDMA1_BASE		0x3000
#define MT_MCU_WFDMA1(ofs)		(MT_MCU_WFDMA1_BASE + (ofs))

#define MT_MCU_INT_EVENT		MT_MCU_WFDMA1(0x108)
#define MT_MCU_INT_EVENT_DMA_STOPPED	BIT(0)
#define MT_MCU_INT_EVENT_DMA_INIT	BIT(1)
#define MT_MCU_INT_EVENT_SER_TRIGGER	BIT(2)
#define MT_MCU_INT_EVENT_RESET_DONE	BIT(3)

#define MT_PLE_BASE			0x820c0000
#define MT_PLE(ofs)			(MT_PLE_BASE + (ofs))

#define MT_PLE_FL_Q0_CTRL		MT_PLE(0x1b0)
#define MT_PLE_FL_Q1_CTRL		MT_PLE(0x1b4)
#define MT_PLE_FL_Q2_CTRL		MT_PLE(0x1b8)
#define MT_PLE_FL_Q3_CTRL		MT_PLE(0x1bc)

#define MT_PLE_AC_QEMPTY(ac, n)		MT_PLE(0x300 + 0x10 * (ac) + \
					       ((n) << 2))
#define MT_PLE_AMSDU_PACK_MSDU_CNT(n)	MT_PLE(0x10e0 + ((n) << 2))

#define MT_MDP_BASE			0x820cd000
#define MT_MDP(ofs)			(MT_MDP_BASE + (ofs))

#define MT_MDP_DCR0			MT_MDP(0x000)
#define MT_MDP_DCR0_DAMSDU_EN		BIT(15)
#define MT_MDP_DCR0_RX_HDR_TRANS_EN	BIT(19)

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
#define MT_WF_TMAC_BASE(_band)		((_band) ? 0x820f4000 : 0x820e4000)
#define MT_WF_TMAC(_band, ofs)		(MT_WF_TMAC_BASE(_band) + (ofs))

#define MT_TMAC_TCR0(_band)		MT_WF_TMAC(_band, 0)
#define MT_TMAC_TCR0_TBTT_STOP_CTRL	BIT(25)

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

#define MT_TMAC_TRCR0(_band)		MT_WF_TMAC(_band, 0x09c)
#define MT_TMAC_TFCR0(_band)		MT_WF_TMAC(_band, 0x1e0)

#define MT_WF_DMA_BASE(_band)		((_band) ? 0x820f7000 : 0x820e7000)
#define MT_WF_DMA(_band, ofs)		(MT_WF_DMA_BASE(_band) + (ofs))

#define MT_DMA_DCR0(_band)		MT_WF_DMA(_band, 0x000)
#define MT_DMA_DCR0_MAX_RX_LEN		GENMASK(15, 3)
#define MT_DMA_DCR0_RXD_G5_EN		BIT(23)

/* LPON: band 0(0x24200), band 1(0xa4200) */
#define MT_WF_LPON_BASE(_band)		((_band) ? 0x820fb000 : 0x820eb000)
#define MT_WF_LPON(_band, ofs)		(MT_WF_LPON_BASE(_band) + (ofs))

#define MT_LPON_UTTR0(_band)		MT_WF_LPON(_band, 0x080)
#define MT_LPON_UTTR1(_band)		MT_WF_LPON(_band, 0x084)

#define MT_LPON_TCR(_band, n)		MT_WF_LPON(_band, 0x0a8 + (n) * 4)
#define MT_LPON_TCR_SW_MODE		GENMASK(1, 0)
#define MT_LPON_TCR_SW_WRITE		BIT(0)

/* ETBF: band 0(0x24000), band 1(0xa4000) */
#define MT_WF_ETBF_BASE(_band)		((_band) ? 0x820fa000 : 0x820ea000)
#define MT_WF_ETBF(_band, ofs)		(MT_WF_ETBF_BASE(_band) + (ofs))

#define MT_ETBF_TX_APP_CNT(_band)	MT_WF_ETBF(_band, 0x150)
#define MT_ETBF_TX_IBF_CNT		GENMASK(31, 16)
#define MT_ETBF_TX_EBF_CNT		GENMASK(15, 0)

#define MT_ETBF_RX_FB_CNT(_band)	MT_WF_ETBF(_band, 0x158)
#define MT_ETBF_RX_FB_ALL		GENMASK(31, 24)
#define MT_ETBF_RX_FB_HE		GENMASK(23, 16)
#define MT_ETBF_RX_FB_VHT		GENMASK(15, 8)
#define MT_ETBF_RX_FB_HT		GENMASK(7, 0)

/* MIB: band 0(0x24800), band 1(0xa4800) */
#define MT_WF_MIB_BASE(_band)		((_band) ? 0x820fd000 : 0x820ed000)
#define MT_WF_MIB(_band, ofs)		(MT_WF_MIB_BASE(_band) + (ofs))

#define MT_MIB_SCR1(_band)		MT_WF_MIB(_band, 0x004)
#define MT_MIB_TXDUR_EN			BIT(8)
#define MT_MIB_RXDUR_EN			BIT(9)

#define MT_MIB_SDR3(_band)		MT_WF_MIB(_band, 0x698)
#define MT_MIB_SDR3_FCS_ERR_MASK	GENMASK(31, 16)

#define MT_MIB_SDR5(_band)		MT_WF_MIB(_band, 0x780)

#define MT_MIB_SDR9(_band)		MT_WF_MIB(_band, 0x02c)
#define MT_MIB_SDR9_BUSY_MASK		GENMASK(23, 0)

#define MT_MIB_SDR12(_band)		MT_WF_MIB(_band, 0x558)
#define MT_MIB_SDR14(_band)		MT_WF_MIB(_band, 0x564)
#define MT_MIB_SDR15(_band)		MT_WF_MIB(_band, 0x568)

#define MT_MIB_SDR16(_band)		MT_WF_MIB(_band, 0x048)
#define MT_MIB_SDR16_BUSY_MASK		GENMASK(23, 0)

#define MT_MIB_SDR22(_band)		MT_WF_MIB(_band, 0x770)
#define MT_MIB_SDR23(_band)		MT_WF_MIB(_band, 0x774)
#define MT_MIB_SDR31(_band)		MT_WF_MIB(_band, 0x55c)

#define MT_MIB_SDR32(_band)		MT_WF_MIB(_band, 0x7a8)
#define MT_MIB_SDR9_IBF_CNT_MASK	GENMASK(31, 16)
#define MT_MIB_SDR9_EBF_CNT_MASK	GENMASK(15, 0)

#define MT_MIB_SDR34(_band)		MT_WF_MIB(_band, 0x090)
#define MT_MIB_MU_BF_TX_CNT		GENMASK(15, 0)

#define MT_MIB_SDR36(_band)		MT_WF_MIB(_band, 0x054)
#define MT_MIB_SDR36_TXTIME_MASK	GENMASK(23, 0)
#define MT_MIB_SDR37(_band)		MT_WF_MIB(_band, 0x058)
#define MT_MIB_SDR37_RXTIME_MASK	GENMASK(23, 0)

#define MT_MIB_DR8(_band)		MT_WF_MIB(_band, 0x0c0)
#define MT_MIB_DR9(_band)		MT_WF_MIB(_band, 0x0c4)
#define MT_MIB_DR11(_band)		MT_WF_MIB(_band, 0x0cc)

#define MT_MIB_MB_SDR0(_band, n)	MT_WF_MIB(_band, 0x100 + ((n) << 4))
#define MT_MIB_RTS_RETRIES_COUNT_MASK	GENMASK(31, 16)
#define MT_MIB_RTS_COUNT_MASK		GENMASK(15, 0)

#define MT_MIB_MB_BSDR0(_band)		MT_WF_MIB(_band, 0x688)
#define MT_MIB_RTS_COUNT_MASK		GENMASK(15, 0)
#define MT_MIB_MB_BSDR1(_band)		MT_WF_MIB(_band, 0x690)
#define MT_MIB_RTS_FAIL_COUNT_MASK	GENMASK(15, 0)
#define MT_MIB_MB_BSDR2(_band)		MT_WF_MIB(_band, 0x518)
#define MT_MIB_BA_FAIL_COUNT_MASK	GENMASK(15, 0)
#define MT_MIB_MB_BSDR3(_band)		MT_WF_MIB(_band, 0x520)
#define MT_MIB_ACK_FAIL_COUNT_MASK	GENMASK(15, 0)

#define MT_MIB_MB_SDR2(_band, n)	MT_WF_MIB(_band, 0x108 + ((n) << 4))
#define MT_MIB_FRAME_RETRIES_COUNT_MASK	GENMASK(15, 0)

#define MT_TX_AGG_CNT(_band, n)		MT_WF_MIB(_band, 0x7dc + ((n) << 2))
#define MT_TX_AGG_CNT2(_band, n)	MT_WF_MIB(_band, 0x7ec + ((n) << 2))
#define MT_MIB_ARNG(_band, n)		MT_WF_MIB(_band, 0x0b0 + ((n) << 2))
#define MT_MIB_ARNCR_RANGE(val, n)	(((val) >> ((n) << 3)) & GENMASK(7, 0))

#define MT_WTBLON_TOP_BASE		0x820d4000
#define MT_WTBLON_TOP(ofs)		(MT_WTBLON_TOP_BASE + (ofs))
#define MT_WTBLON_TOP_WDUCR		MT_WTBLON_TOP(0x200)
#define MT_WTBLON_TOP_WDUCR_GROUP	GENMASK(2, 0)

#define MT_WTBL_UPDATE			MT_WTBLON_TOP(0x230)
#define MT_WTBL_UPDATE_WLAN_IDX		GENMASK(9, 0)
#define MT_WTBL_UPDATE_ADM_COUNT_CLEAR	BIT(12)
#define MT_WTBL_UPDATE_BUSY		BIT(31)

#define MT_WTBL_BASE			0x820d8000
#define MT_WTBL_LMAC_ID			GENMASK(14, 8)
#define MT_WTBL_LMAC_DW			GENMASK(7, 2)
#define MT_WTBL_LMAC_OFFS(_id, _dw)	(MT_WTBL_BASE | \
					FIELD_PREP(MT_WTBL_LMAC_ID, _id) | \
					FIELD_PREP(MT_WTBL_LMAC_DW, _dw))

/* AGG: band 0(0x20800), band 1(0xa0800) */
#define MT_WF_AGG_BASE(_band)		((_band) ? 0x820f2000 : 0x820e2000)
#define MT_WF_AGG(_band, ofs)		(MT_WF_AGG_BASE(_band) + (ofs))

#define MT_AGG_AWSCR0(_band, _n)	MT_WF_AGG(_band, 0x05c + (_n) * 4)
#define MT_AGG_PCR0(_band, _n)		MT_WF_AGG(_band, 0x06c + (_n) * 4)
#define MT_AGG_PCR0_MM_PROT		BIT(0)
#define MT_AGG_PCR0_GF_PROT		BIT(1)
#define MT_AGG_PCR0_BW20_PROT		BIT(2)
#define MT_AGG_PCR0_BW40_PROT		BIT(4)
#define MT_AGG_PCR0_BW80_PROT		BIT(6)
#define MT_AGG_PCR0_ERP_PROT		GENMASK(12, 8)
#define MT_AGG_PCR0_VHT_PROT		BIT(13)
#define MT_AGG_PCR0_PTA_WIN_DIS		BIT(15)

#define MT_AGG_PCR1_RTS0_NUM_THRES	GENMASK(31, 23)
#define MT_AGG_PCR1_RTS0_LEN_THRES	GENMASK(19, 0)

#define MT_AGG_ACR0(_band)		MT_WF_AGG(_band, 0x084)
#define MT_AGG_ACR_CFEND_RATE		GENMASK(13, 0)
#define MT_AGG_ACR_BAR_RATE		GENMASK(29, 16)

#define MT_AGG_MRCR(_band)		MT_WF_AGG(_band, 0x098)
#define MT_AGG_MRCR_BAR_CNT_LIMIT	GENMASK(15, 12)
#define MT_AGG_MRCR_LAST_RTS_CTS_RN	BIT(6)
#define MT_AGG_MRCR_RTS_FAIL_LIMIT	GENMASK(11, 7)
#define MT_AGG_MRCR_TXCMD_RTS_FAIL_LIMIT	GENMASK(28, 24)

#define MT_AGG_ATCR1(_band)		MT_WF_AGG(_band, 0x0f0)
#define MT_AGG_ATCR3(_band)		MT_WF_AGG(_band, 0x0f4)

/* ARB: band 0(0x20c00), band 1(0xa0c00) */
#define MT_WF_ARB_BASE(_band)		((_band) ? 0x820f3000 : 0x820e3000)
#define MT_WF_ARB(_band, ofs)		(MT_WF_ARB_BASE(_band) + (ofs))

#define MT_ARB_SCR(_band)		MT_WF_ARB(_band, 0x080)
#define MT_ARB_SCR_TX_DISABLE		BIT(8)
#define MT_ARB_SCR_RX_DISABLE		BIT(9)

#define MT_ARB_DRNGR0(_band, _n)	MT_WF_ARB(_band, 0x194 + (_n) * 4)

/* RMAC: band 0(0x21400), band 1(0xa1400) */
#define MT_WF_RMAC_BASE(_band)		((_band) ? 0x820f5000 : 0x820e5000)
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

#define MT_MCU_CMD			MT_WFDMA0(0x1f0)
#define MT_MCU_CMD_WAKE_RX_PCIE		BIT(0)
#define MT_MCU_CMD_STOP_DMA_FW_RELOAD	BIT(1)
#define MT_MCU_CMD_STOP_DMA		BIT(2)
#define MT_MCU_CMD_RESET_DONE		BIT(3)
#define MT_MCU_CMD_RECOVERY_DONE	BIT(4)
#define MT_MCU_CMD_NORMAL_STATE		BIT(5)
#define MT_MCU_CMD_ERROR_MASK		GENMASK(5, 1)

#define MT_MCU2HOST_SW_INT_ENA		MT_WFDMA0(0x1f4)

#define MT_WFDMA0_HOST_INT_STA		MT_WFDMA0(0x200)
#define HOST_RX_DONE_INT_STS0		BIT(0)	/* Rx mcu */
#define HOST_RX_DONE_INT_STS2		BIT(2)	/* Rx data */
#define HOST_RX_DONE_INT_STS4		BIT(22)	/* Rx mcu after fw downloaded */
#define HOST_TX_DONE_INT_STS16		BIT(26)
#define HOST_TX_DONE_INT_STS17		BIT(27) /* MCU tx done*/

#define MT_WFDMA0_HOST_INT_ENA		MT_WFDMA0(0x204)
#define HOST_RX_DONE_INT_ENA0		BIT(0)
#define HOST_RX_DONE_INT_ENA1		BIT(1)
#define HOST_RX_DONE_INT_ENA2		BIT(2)
#define HOST_RX_DONE_INT_ENA3		BIT(3)
#define HOST_TX_DONE_INT_ENA0		BIT(4)
#define HOST_TX_DONE_INT_ENA1		BIT(5)
#define HOST_TX_DONE_INT_ENA2		BIT(6)
#define HOST_TX_DONE_INT_ENA3		BIT(7)
#define HOST_TX_DONE_INT_ENA4		BIT(8)
#define HOST_TX_DONE_INT_ENA5		BIT(9)
#define HOST_TX_DONE_INT_ENA6		BIT(10)
#define HOST_TX_DONE_INT_ENA7		BIT(11)
#define HOST_TX_DONE_INT_ENA8		BIT(12)
#define HOST_TX_DONE_INT_ENA9		BIT(13)
#define HOST_TX_DONE_INT_ENA10		BIT(14)
#define HOST_TX_DONE_INT_ENA11		BIT(15)
#define HOST_TX_DONE_INT_ENA12		BIT(16)
#define HOST_TX_DONE_INT_ENA13		BIT(17)
#define HOST_TX_DONE_INT_ENA14		BIT(18)
#define HOST_RX_COHERENT_EN		BIT(20)
#define HOST_TX_COHERENT_EN		BIT(21)
#define HOST_RX_DONE_INT_ENA4		BIT(22)
#define HOST_RX_DONE_INT_ENA5		BIT(23)
#define HOST_TX_DONE_INT_ENA16		BIT(26)
#define HOST_TX_DONE_INT_ENA17		BIT(27)
#define MCU2HOST_SW_INT_ENA		BIT(29)
#define HOST_TX_DONE_INT_ENA18		BIT(30)

/* WFDMA interrupt */
#define MT_INT_RX_DONE_DATA		HOST_RX_DONE_INT_ENA2
#define MT_INT_RX_DONE_WM		HOST_RX_DONE_INT_ENA0
#define MT_INT_RX_DONE_WM2		HOST_RX_DONE_INT_ENA4
#define MT_INT_RX_DONE_ALL		(MT_INT_RX_DONE_DATA | \
					 MT_INT_RX_DONE_WM | \
					 MT_INT_RX_DONE_WM2)
#define MT_INT_TX_DONE_MCU_WM		HOST_TX_DONE_INT_ENA17
#define MT_INT_TX_DONE_FWDL		HOST_TX_DONE_INT_ENA16
#define MT_INT_TX_DONE_BAND0		HOST_TX_DONE_INT_ENA0
#define MT_INT_MCU_CMD			MCU2HOST_SW_INT_ENA

#define MT_INT_TX_DONE_MCU		(MT_INT_TX_DONE_MCU_WM |	\
					 MT_INT_TX_DONE_FWDL)
#define MT_INT_TX_DONE_ALL		(MT_INT_TX_DONE_MCU_WM |	\
					 MT_INT_TX_DONE_BAND0 |	\
					GENMASK(18, 4))

#define MT_WFDMA0_GLO_CFG		MT_WFDMA0(0x208)
#define MT_WFDMA0_GLO_CFG_TX_DMA_EN	BIT(0)
#define MT_WFDMA0_GLO_CFG_TX_DMA_BUSY	BIT(1)
#define MT_WFDMA0_GLO_CFG_RX_DMA_EN	BIT(2)
#define MT_WFDMA0_GLO_CFG_RX_DMA_BUSY	BIT(3)
#define MT_WFDMA0_GLO_CFG_TX_WB_DDONE	BIT(6)
#define MT_WFDMA0_GLO_CFG_FIFO_LITTLE_ENDIAN	BIT(12)
#define MT_WFDMA0_GLO_CFG_CSR_DISP_BASE_PTR_CHAIN_EN BIT(15)
#define MT_WFDMA0_GLO_CFG_OMIT_RX_INFO_PFET2	BIT(21)
#define MT_WFDMA0_GLO_CFG_OMIT_RX_INFO	BIT(27)
#define MT_WFDMA0_GLO_CFG_OMIT_TX_INFO	BIT(28)
#define MT_WFDMA0_GLO_CFG_CLK_GAT_DIS	BIT(30)

#define MT_WFDMA0_RST_DTX_PTR		MT_WFDMA0(0x20c)
#define MT_WFDMA0_GLO_CFG_EXT0		MT_WFDMA0(0x2b0)
#define MT_WFDMA0_CSR_TX_DMASHDL_ENABLE	BIT(6)
#define MT_WFDMA0_PRI_DLY_INT_CFG0	MT_WFDMA0(0x2f0)

#define MT_RX_DATA_RING_BASE		MT_WFDMA0(0x520)

#define MT_WFDMA0_TX_RING0_EXT_CTRL	MT_WFDMA0(0x600)
#define MT_WFDMA0_TX_RING1_EXT_CTRL	MT_WFDMA0(0x604)
#define MT_WFDMA0_TX_RING2_EXT_CTRL	MT_WFDMA0(0x608)
#define MT_WFDMA0_TX_RING3_EXT_CTRL	MT_WFDMA0(0x60c)
#define MT_WFDMA0_TX_RING4_EXT_CTRL	MT_WFDMA0(0x610)
#define MT_WFDMA0_TX_RING5_EXT_CTRL	MT_WFDMA0(0x614)
#define MT_WFDMA0_TX_RING6_EXT_CTRL	MT_WFDMA0(0x618)
#define MT_WFDMA0_TX_RING16_EXT_CTRL	MT_WFDMA0(0x640)
#define MT_WFDMA0_TX_RING17_EXT_CTRL	MT_WFDMA0(0x644)

#define MT_WFDMA0_RX_RING0_EXT_CTRL	MT_WFDMA0(0x680)
#define MT_WFDMA0_RX_RING1_EXT_CTRL	MT_WFDMA0(0x684)
#define MT_WFDMA0_RX_RING2_EXT_CTRL	MT_WFDMA0(0x688)
#define MT_WFDMA0_RX_RING3_EXT_CTRL	MT_WFDMA0(0x68c)
#define MT_WFDMA0_RX_RING4_EXT_CTRL	MT_WFDMA0(0x690)
#define MT_WFDMA0_RX_RING5_EXT_CTRL	MT_WFDMA0(0x694)

#define MT_TX_RING_BASE			MT_WFDMA0(0x300)
#define MT_RX_EVENT_RING_BASE		MT_WFDMA0(0x500)

/* WFDMA CSR */
#define MT_WFDMA_EXT_CSR_BASE          0xd7000
#define MT_WFDMA_EXT_CSR(ofs)          (MT_WFDMA_EXT_CSR_BASE + (ofs))
#define MT_WFDMA_EXT_CSR_HIF_MISC	MT_WFDMA_EXT_CSR(0x44)
#define MT_WFDMA_EXT_CSR_HIF_MISC_BUSY	BIT(0)

#define MT_INFRA_CFG_BASE		0xfe000
#define MT_INFRA(ofs)			(MT_INFRA_CFG_BASE + (ofs))

#define MT_HIF_REMAP_L1			MT_INFRA(0x24c)
#define MT_HIF_REMAP_L1_MASK		GENMASK(15, 0)
#define MT_HIF_REMAP_L1_OFFSET		GENMASK(15, 0)
#define MT_HIF_REMAP_L1_BASE		GENMASK(31, 16)
#define MT_HIF_REMAP_BASE_L1		0x40000

#define MT_SWDEF_BASE			0x41f200
#define MT_SWDEF(ofs)			(MT_SWDEF_BASE + (ofs))
#define MT_SWDEF_MODE			MT_SWDEF(0x3c)
#define MT_SWDEF_NORMAL_MODE		0
#define MT_SWDEF_ICAP_MODE		1
#define MT_SWDEF_SPECTRUM_MODE		2

#define MT_TOP_BASE			0x18060000
#define MT_TOP(ofs)			(MT_TOP_BASE + (ofs))

#define MT_TOP_LPCR_HOST_BAND0		MT_TOP(0x10)
#define MT_TOP_LPCR_HOST_FW_OWN		BIT(0)
#define MT_TOP_LPCR_HOST_DRV_OWN	BIT(1)

#define MT_TOP_MISC			MT_TOP(0xf0)
#define MT_TOP_MISC_FW_STATE		GENMASK(2, 0)

#define MT_MCU_WPDMA0_BASE		0x54000000
#define MT_MCU_WPDMA0(ofs)		(MT_MCU_WPDMA0_BASE + (ofs))

#define MT_WFDMA_DUMMY_CR		MT_MCU_WPDMA0(0x120)
#define MT_WFDMA_NEED_REINIT		BIT(1)

#define MT_HW_BOUND			0x70010020
#define MT_HW_CHIPID			0x70010200
#define MT_HW_REV			0x70010204

#define MT_PCIE_MAC_BASE		0x10000
#define MT_PCIE_MAC(ofs)		(MT_PCIE_MAC_BASE + (ofs))
#define MT_PCIE_MAC_INT_ENABLE		MT_PCIE_MAC(0x188)

#define MT_DMA_SHDL(ofs)		(0xd6000 + (ofs))
#define MT_DMASHDL_SW_CONTROL		MT_DMA_SHDL(0x004)
#define MT_DMASHDL_DMASHDL_BYPASS	BIT(28)
#define MT_DMASHDL_OPTIONAL		MT_DMA_SHDL(0x008)
#define MT_DMASHDL_PAGE			MT_DMA_SHDL(0x00c)
#define MT_DMASHDL_REFILL		MT_DMA_SHDL(0x010)
#define MT_DMASHDL_PKT_MAX_SIZE		MT_DMA_SHDL(0x01c)
#define MT_DMASHDL_PKT_MAX_SIZE_PLE	GENMASK(11, 0)
#define MT_DMASHDL_PKT_MAX_SIZE_PSE	GENMASK(27, 16)

#define MT_DMASHDL_GROUP_QUOTA(_n)	MT_DMA_SHDL(0x020 + ((_n) << 2))
#define MT_DMASHDL_GROUP_QUOTA_MIN	GENMASK(11, 0)
#define MT_DMASHDL_GROUP_QUOTA_MAX	GENMASK(27, 16)

#define MT_DMASHDL_Q_MAP(_n)		MT_DMA_SHDL(0x060 + ((_n) << 2))
#define MT_DMASHDL_Q_MAP_MASK		GENMASK(3, 0)
#define MT_DMASHDL_Q_MAP_SHIFT(_n)	(4 * ((_n) % 8))

#define MT_DMASHDL_SCHED_SET(_n)	MT_DMA_SHDL(0x070 + ((_n) << 2))

#define MT_CONN_ON_LPCTL		0x7c060010
#define PCIE_LPCR_HOST_OWN_SYNC		BIT(2)
#define PCIE_LPCR_HOST_CLR_OWN		BIT(1)
#define PCIE_LPCR_HOST_SET_OWN		BIT(0)

#define MT_WFSYS_SW_RST_B		0x18000140
#define WFSYS_SW_RST_B			BIT(0)
#define WFSYS_SW_INIT_DONE		BIT(4)

#define MT_CONN_ON_MISC			0x7c0600f0
#define MT_TOP_MISC2_FW_N9_RDY		GENMASK(1, 0)

#endif
