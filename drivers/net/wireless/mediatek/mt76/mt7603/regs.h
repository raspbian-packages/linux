/* SPDX-License-Identifier: ISC */

#ifndef __MT7603_REGS_H
#define __MT7603_REGS_H

#define MT_HW_REV			0x1000
#define MT_HW_CHIPID			0x1008
#define MT_TOP_MISC2			0x1134

#define MT_MCU_BASE			0x2000
#define MT_MCU(ofs)			(MT_MCU_BASE + (ofs))

#define MT_MCU_PCIE_REMAP_1		MT_MCU(0x500)
#define MT_MCU_PCIE_REMAP_1_OFFSET	GENMASK(17, 0)
#define MT_MCU_PCIE_REMAP_1_BASE	GENMASK(31, 18)

#define MT_MCU_PCIE_REMAP_2		MT_MCU(0x504)
#define MT_MCU_PCIE_REMAP_2_OFFSET	GENMASK(18, 0)
#define MT_MCU_PCIE_REMAP_2_BASE	GENMASK(31, 19)

#define MT_HIF_BASE			0x4000
#define MT_HIF(ofs)			(MT_HIF_BASE + (ofs))

#define MT_INT_SOURCE_CSR		MT_HIF(0x200)
#define MT_INT_MASK_CSR			MT_HIF(0x204)
#define MT_DELAY_INT_CFG		MT_HIF(0x210)

#define MT_INT_RX_DONE(_n)		BIT(_n)
#define MT_INT_RX_DONE_ALL		GENMASK(1, 0)
#define MT_INT_TX_DONE_ALL		GENMASK(19, 4)
#define MT_INT_TX_DONE(_n)		BIT((_n) + 4)

#define MT_INT_RX_COHERENT		BIT(20)
#define MT_INT_TX_COHERENT		BIT(21)
#define MT_INT_MAC_IRQ3			BIT(27)

#define MT_INT_MCU_CMD			BIT(30)

#define MT_WPDMA_GLO_CFG		MT_HIF(0x208)
#define MT_WPDMA_GLO_CFG_TX_DMA_EN	BIT(0)
#define MT_WPDMA_GLO_CFG_TX_DMA_BUSY	BIT(1)
#define MT_WPDMA_GLO_CFG_RX_DMA_EN	BIT(2)
#define MT_WPDMA_GLO_CFG_RX_DMA_BUSY	BIT(3)
#define MT_WPDMA_GLO_CFG_DMA_BURST_SIZE	GENMASK(5, 4)
#define MT_WPDMA_GLO_CFG_TX_WRITEBACK_DONE	BIT(6)
#define MT_WPDMA_GLO_CFG_BIG_ENDIAN	BIT(7)
#define MT_WPDMA_GLO_CFG_HDR_SEG_LEN	GENMASK(15, 8)
#define MT_WPDMA_GLO_CFG_SW_RESET	BIT(24)
#define MT_WPDMA_GLO_CFG_FORCE_TX_EOF	BIT(25)
#define MT_WPDMA_GLO_CFG_CLK_GATE_DIS	BIT(30)
#define MT_WPDMA_GLO_CFG_RX_2B_OFFSET	BIT(31)

#define MT_WPDMA_RST_IDX		MT_HIF(0x20c)

#define MT_WPDMA_DEBUG			MT_HIF(0x244)
#define MT_WPDMA_DEBUG_VALUE		GENMASK(17, 0)
#define MT_WPDMA_DEBUG_SEL		BIT(27)
#define MT_WPDMA_DEBUG_IDX		GENMASK(31, 28)

#define MT_TX_RING_BASE			MT_HIF(0x300)
#define MT_RX_RING_BASE			MT_HIF(0x400)

#define MT_TXTIME_THRESH_BASE		MT_HIF(0x500)
#define MT_TXTIME_THRESH(n)		(MT_TXTIME_THRESH_BASE + ((n) * 4))

#define MT_PAGE_COUNT_BASE		MT_HIF(0x540)
#define MT_PAGE_COUNT(n)		(MT_PAGE_COUNT_BASE + ((n) * 4))

#define MT_SCH_1			MT_HIF(0x588)
#define MT_SCH_2			MT_HIF(0x58c)
#define MT_SCH_3			MT_HIF(0x590)

#define MT_SCH_4			MT_HIF(0x594)
#define MT_SCH_4_FORCE_QID		GENMASK(4, 0)
#define MT_SCH_4_BYPASS			BIT(5)
#define MT_SCH_4_RESET			BIT(8)

#define MT_GROUP_THRESH_BASE		MT_HIF(0x598)
#define MT_GROUP_THRESH(n)		(MT_GROUP_THRESH_BASE + ((n) * 4))

#define MT_QUEUE_PRIORITY_1		MT_HIF(0x580)
#define MT_QUEUE_PRIORITY_2		MT_HIF(0x584)

#define MT_BMAP_0			MT_HIF(0x5b0)
#define MT_BMAP_1			MT_HIF(0x5b4)
#define MT_BMAP_2			MT_HIF(0x5b8)

#define MT_HIGH_PRIORITY_1		MT_HIF(0x5bc)
#define MT_HIGH_PRIORITY_2		MT_HIF(0x5c0)

#define MT_PRIORITY_MASK		MT_HIF(0x5c4)

#define MT_RSV_MAX_THRESH		MT_HIF(0x5c8)

#define MT_PSE_BASE			0x8000
#define MT_PSE(ofs)			(MT_PSE_BASE + (ofs))

#define MT_MCU_DEBUG_RESET		MT_PSE(0x16c)
#define MT_MCU_DEBUG_RESET_PSE		BIT(0)
#define MT_MCU_DEBUG_RESET_PSE_S	BIT(1)
#define MT_MCU_DEBUG_RESET_QUEUES	GENMASK(6, 2)

#define MT_PSE_FC_P0			MT_PSE(0x120)
#define MT_PSE_FC_P0_MIN_RESERVE	GENMASK(11, 0)
#define MT_PSE_FC_P0_MAX_QUOTA		GENMASK(27, 16)

#define MT_PSE_FRP			MT_PSE(0x138)
#define MT_PSE_FRP_P0			GENMASK(2, 0)
#define MT_PSE_FRP_P1			GENMASK(5, 3)
#define MT_PSE_FRP_P2_RQ0		GENMASK(8, 6)
#define MT_PSE_FRP_P2_RQ1		GENMASK(11, 9)
#define MT_PSE_FRP_P2_RQ2		GENMASK(14, 12)

#define MT_FC_RSV_COUNT_0		MT_PSE(0x13c)
#define MT_FC_RSV_COUNT_0_P0		GENMASK(11, 0)
#define MT_FC_RSV_COUNT_0_P1		GENMASK(27, 16)

#define MT_FC_SP2_Q0Q1			MT_PSE(0x14c)
#define MT_FC_SP2_Q0Q1_SRC_COUNT_Q0	GENMASK(11, 0)
#define MT_FC_SP2_Q0Q1_SRC_COUNT_Q1	GENMASK(27, 16)

#define MT_PSE_FW_SHARED		MT_PSE(0x17c)

#define MT_PSE_RTA			MT_PSE(0x194)
#define MT_PSE_RTA_QUEUE_ID		GENMASK(4, 0)
#define MT_PSE_RTA_PORT_ID		GENMASK(6, 5)
#define MT_PSE_RTA_REDIRECT_EN		BIT(7)
#define MT_PSE_RTA_TAG_ID		GENMASK(15, 8)
#define MT_PSE_RTA_WRITE		BIT(16)
#define MT_PSE_RTA_BUSY			BIT(31)

#define MT_WF_PHY_BASE			0x10000
#define MT_WF_PHY_OFFSET		0x1000
#define MT_WF_PHY(ofs)			(MT_WF_PHY_BASE + (ofs))

#define MT_AGC_BASE			MT_WF_PHY(0x500)
#define MT_AGC(n)			(MT_AGC_BASE + ((n) * 4))

#define MT_AGC1_BASE			MT_WF_PHY(0x1500)
#define MT_AGC1(n)			(MT_AGC1_BASE + ((n) * 4))

#define MT_AGC_41_RSSI_0		GENMASK(23, 16)
#define MT_AGC_41_RSSI_1		GENMASK(7, 0)

#define MT_RXTD_BASE			MT_WF_PHY(0x600)
#define MT_RXTD(n)			(MT_RXTD_BASE + ((n) * 4))

#define MT_RXTD_6_ACI_TH		GENMASK(4, 0)
#define MT_RXTD_6_CCAED_TH		GENMASK(14, 8)

#define MT_RXTD_8_LOWER_SIGNAL		GENMASK(5, 0)

#define MT_RXTD_13_ACI_TH_EN		BIT(0)

#define MT_WF_PHY_CR_TSSI_BASE		MT_WF_PHY(0xd00)
#define MT_WF_PHY_CR_TSSI(phy, n)	(MT_WF_PHY_CR_TSSI_BASE +	\
					 ((phy) * MT_WF_PHY_OFFSET) +	\
					 ((n) * 4))

#define MT_PHYCTRL_BASE			MT_WF_PHY(0x4100)
#define MT_PHYCTRL(n)			(MT_PHYCTRL_BASE + ((n) * 4))

#define MT_PHYCTRL_2_STATUS_RESET	BIT(6)
#define MT_PHYCTRL_2_STATUS_EN		BIT(7)

#define MT_PHYCTRL_STAT_PD		MT_PHYCTRL(3)
#define MT_PHYCTRL_STAT_PD_OFDM		GENMASK(31, 16)
#define MT_PHYCTRL_STAT_PD_CCK		GENMASK(15, 0)

#define MT_PHYCTRL_STAT_MDRDY		MT_PHYCTRL(8)
#define MT_PHYCTRL_STAT_MDRDY_OFDM	GENMASK(31, 16)
#define MT_PHYCTRL_STAT_MDRDY_CCK	GENMASK(15, 0)

#define MT_WF_AGG_BASE			0x21200
#define MT_WF_AGG(ofs)			(MT_WF_AGG_BASE + (ofs))

#define MT_AGG_ARCR			MT_WF_AGG(0x010)
#define MT_AGG_ARCR_INIT_RATE1		BIT(0)
#define MT_AGG_ARCR_FB_SGI_DISABLE	BIT(1)
#define MT_AGG_ARCR_RATE8_DOWN_WRAP	BIT(2)
#define MT_AGG_ARCR_RTS_RATE_THR	GENMASK(12, 8)
#define MT_AGG_ARCR_RATE_DOWN_RATIO	GENMASK(17, 16)
#define MT_AGG_ARCR_RATE_DOWN_RATIO_EN	BIT(19)
#define MT_AGG_ARCR_RATE_UP_EXTRA_TH	GENMASK(22, 20)
#define MT_AGG_ARCR_SPE_DIS_TH		GENMASK(27, 24)

#define MT_AGG_ARUCR			MT_WF_AGG(0x014)
#define MT_AGG_ARDCR			MT_WF_AGG(0x018)
#define MT_AGG_ARxCR_LIMIT_SHIFT(_n)	(4 * (_n))
#define MT_AGG_ARxCR_LIMIT(_n)		GENMASK(2 + \
						MT_AGG_ARxCR_LIMIT_SHIFT(_n), \
						MT_AGG_ARxCR_LIMIT_SHIFT(_n))

#define MT_AGG_LIMIT			MT_WF_AGG(0x040)
#define MT_AGG_LIMIT_1			MT_WF_AGG(0x044)
#define MT_AGG_LIMIT_AC(_n)		GENMASK(((_n) + 1) * 8 - 1, (_n) * 8)

#define MT_AGG_BA_SIZE_LIMIT_0		MT_WF_AGG(0x048)
#define MT_AGG_BA_SIZE_LIMIT_1		MT_WF_AGG(0x04c)
#define MT_AGG_BA_SIZE_LIMIT_SHIFT	8

#define MT_AGG_PCR			MT_WF_AGG(0x050)
#define MT_AGG_PCR_MM			BIT(16)
#define MT_AGG_PCR_GF			BIT(17)
#define MT_AGG_PCR_BW40			BIT(18)
#define MT_AGG_PCR_RIFS			BIT(19)
#define MT_AGG_PCR_BW80			BIT(20)
#define MT_AGG_PCR_BW160		BIT(21)
#define MT_AGG_PCR_ERP			BIT(22)

#define MT_AGG_PCR_RTS			MT_WF_AGG(0x054)
#define MT_AGG_PCR_RTS_THR		GENMASK(19, 0)
#define MT_AGG_PCR_RTS_PKT_THR		GENMASK(31, 25)

#define MT_AGG_ASRCR			MT_WF_AGG(0x060)
#define MT_AGG_ASRCR_RANGE(val, n)	(((val) >> ((n) << 3)) & GENMASK(5, 0))

#define MT_AGG_CONTROL			MT_WF_AGG(0x070)
#define MT_AGG_CONTROL_NO_BA_RULE	BIT(0)
#define MT_AGG_CONTROL_NO_BA_AR_RULE	BIT(1)
#define MT_AGG_CONTROL_CFEND_SPE_EN	BIT(3)
#define MT_AGG_CONTROL_CFEND_RATE	GENMASK(15, 4)
#define MT_AGG_CONTROL_BAR_SPE_EN	BIT(19)
#define MT_AGG_CONTROL_BAR_RATE		GENMASK(31, 20)

#define MT_AGG_TMP			MT_WF_AGG(0x0d8)

#define MT_AGG_BWCR			MT_WF_AGG(0x0ec)
#define MT_AGG_BWCR_BW			GENMASK(3, 2)

#define MT_AGG_RETRY_CONTROL		MT_WF_AGG(0x0f4)
#define MT_AGG_RETRY_CONTROL_RTS_LIMIT	GENMASK(11, 7)
#define MT_AGG_RETRY_CONTROL_BAR_LIMIT	GENMASK(15, 12)

#define MT_WF_DMA_BASE			0x21c00
#define MT_WF_DMA(ofs)			(MT_WF_DMA_BASE + (ofs))

#define MT_DMA_DCR0			MT_WF_DMA(0x000)
#define MT_DMA_DCR0_MAX_RX_LEN		GENMASK(15, 0)
#define MT_DMA_DCR0_DAMSDU		BIT(16)
#define MT_DMA_DCR0_RX_VEC_DROP		BIT(17)

#define MT_DMA_DCR1			MT_WF_DMA(0x004)

#define MT_DMA_FQCR0			MT_WF_DMA(0x008)
#define MT_DMA_FQCR0_TARGET_WCID	GENMASK(7, 0)
#define MT_DMA_FQCR0_TARGET_BSS		GENMASK(13, 8)
#define MT_DMA_FQCR0_TARGET_QID		GENMASK(20, 16)
#define MT_DMA_FQCR0_DEST_PORT_ID	GENMASK(23, 22)
#define MT_DMA_FQCR0_DEST_QUEUE_ID	GENMASK(28, 24)
#define MT_DMA_FQCR0_MODE		BIT(29)
#define MT_DMA_FQCR0_STATUS		BIT(30)
#define MT_DMA_FQCR0_BUSY		BIT(31)

#define MT_DMA_RCFR0			MT_WF_DMA(0x070)
#define MT_DMA_VCFR0			MT_WF_DMA(0x07c)

#define MT_DMA_TCFR0			MT_WF_DMA(0x080)
#define MT_DMA_TCFR1			MT_WF_DMA(0x084)
#define MT_DMA_TCFR_TXS_AGGR_TIMEOUT	GENMASK(27, 16)
#define MT_DMA_TCFR_TXS_QUEUE		BIT(14)
#define MT_DMA_TCFR_TXS_AGGR_COUNT	GENMASK(12, 8)
#define MT_DMA_TCFR_TXS_BIT_MAP		GENMASK(6, 0)

#define MT_DMA_TMCFR0			MT_WF_DMA(0x088)

#define MT_WF_ARB_BASE			0x21400
#define MT_WF_ARB(ofs)			(MT_WF_ARB_BASE + (ofs))

#define MT_WMM_AIFSN			MT_WF_ARB(0x020)
#define MT_WMM_AIFSN_MASK		GENMASK(3, 0)
#define MT_WMM_AIFSN_SHIFT(_n)		((_n) * 4)

#define MT_WMM_CWMAX_BASE		MT_WF_ARB(0x028)
#define MT_WMM_CWMAX(_n)		(MT_WMM_CWMAX_BASE + (((_n) / 2) << 2))
#define MT_WMM_CWMAX_SHIFT(_n)		(((_n) & 1) * 16)
#define MT_WMM_CWMAX_MASK		GENMASK(15, 0)

#define MT_WMM_CWMIN			MT_WF_ARB(0x040)
#define MT_WMM_CWMIN_MASK		GENMASK(7, 0)
#define MT_WMM_CWMIN_SHIFT(_n)		((_n) * 8)

#define MT_WF_ARB_RQCR			MT_WF_ARB(0x070)
#define MT_WF_ARB_RQCR_RX_START		BIT(0)
#define MT_WF_ARB_RQCR_RXV_START	BIT(4)
#define MT_WF_ARB_RQCR_RXV_R_EN		BIT(7)
#define MT_WF_ARB_RQCR_RXV_T_EN		BIT(8)

#define MT_ARB_SCR			MT_WF_ARB(0x080)
#define MT_ARB_SCR_BCNQ_OPMODE_MASK	GENMASK(1, 0)
#define MT_ARB_SCR_BCNQ_OPMODE_SHIFT(n)	((n) * 2)
#define MT_ARB_SCR_TX_DISABLE		BIT(8)
#define MT_ARB_SCR_RX_DISABLE		BIT(9)
#define MT_ARB_SCR_BCNQ_EMPTY_SKIP	BIT(28)
#define MT_ARB_SCR_TTTT_BTIM_PRIO	BIT(29)
#define MT_ARB_SCR_TBTT_BCN_PRIO	BIT(30)
#define MT_ARB_SCR_TBTT_BCAST_PRIO	BIT(31)

enum {
	MT_BCNQ_OPMODE_STA =	0,
	MT_BCNQ_OPMODE_AP =	1,
	MT_BCNQ_OPMODE_ADHOC =	2,
};

#define MT_WF_ARB_TX_START_0		MT_WF_ARB(0x100)
#define MT_WF_ARB_TX_START_1		MT_WF_ARB(0x104)
#define MT_WF_ARB_TX_FLUSH_0		MT_WF_ARB(0x108)
#define MT_WF_ARB_TX_FLUSH_1		MT_WF_ARB(0x10c)
#define MT_WF_ARB_TX_STOP_0		MT_WF_ARB(0x110)
#define MT_WF_ARB_TX_STOP_1		MT_WF_ARB(0x114)

#define MT_WF_ARB_BCN_START		MT_WF_ARB(0x118)
#define MT_WF_ARB_BCN_START_BSSn(n)	BIT(0 + (n))
#define MT_WF_ARB_BCN_START_T_PRE_TTTT	BIT(10)
#define MT_WF_ARB_BCN_START_T_TTTT	BIT(11)
#define MT_WF_ARB_BCN_START_T_PRE_TBTT	BIT(12)
#define MT_WF_ARB_BCN_START_T_TBTT	BIT(13)
#define MT_WF_ARB_BCN_START_T_SLOT_IDLE	BIT(14)
#define MT_WF_ARB_BCN_START_T_TX_START	BIT(15)
#define MT_WF_ARB_BCN_START_BSS0n(n)	BIT((n) ? 16 + ((n) - 1) : 0)

#define MT_WF_ARB_BCN_FLUSH		MT_WF_ARB(0x11c)
#define MT_WF_ARB_BCN_FLUSH_BSSn(n)	BIT(0 + (n))
#define MT_WF_ARB_BCN_FLUSH_BSS0n(n)	BIT((n) ? 16 + ((n) - 1) : 0)

#define MT_WF_ARB_CAB_START		MT_WF_ARB(0x120)
#define MT_WF_ARB_CAB_START_BSSn(n)	BIT(0 + (n))
#define MT_WF_ARB_CAB_START_BSS0n(n)	BIT((n) ? 16 + ((n) - 1) : 0)

#define MT_WF_ARB_CAB_FLUSH		MT_WF_ARB(0x124)
#define MT_WF_ARB_CAB_FLUSH_BSSn(n)	BIT(0 + (n))
#define MT_WF_ARB_CAB_FLUSH_BSS0n(n)	BIT((n) ? 16 + ((n) - 1) : 0)

#define MT_WF_ARB_CAB_COUNT(n)		MT_WF_ARB(0x128 + (n) * 4)
#define MT_WF_ARB_CAB_COUNT_SHIFT	4
#define MT_WF_ARB_CAB_COUNT_MASK	GENMASK(3, 0)
#define MT_WF_ARB_CAB_COUNT_B0_REG(n)	MT_WF_ARB_CAB_COUNT(((n) > 12 ? 2 : \
							     ((n) > 4 ? 1 : 0)))
#define MT_WF_ARB_CAB_COUNT_B0_SHIFT(n)	(((n) > 12 ? (n) - 12 : \
					 ((n) > 4 ? (n) - 4 : \
					  (n) ? (n) + 3 : 0)) * 4)

#define MT_TX_ABORT			MT_WF_ARB(0x134)
#define MT_TX_ABORT_EN			BIT(0)
#define MT_TX_ABORT_WCID		GENMASK(15, 8)

#define MT_WF_TMAC_BASE			0x21600
#define MT_WF_TMAC(ofs)			(MT_WF_TMAC_BASE + (ofs))

#define MT_TMAC_TCR			MT_WF_TMAC(0x000)
#define MT_TMAC_TCR_BLINK_SEL		GENMASK(7, 6)
#define MT_TMAC_TCR_PRE_RTS_GUARD	GENMASK(11, 8)
#define MT_TMAC_TCR_PRE_RTS_SEC_IDLE	GENMASK(13, 12)
#define MT_TMAC_TCR_RTS_SIGTA		BIT(14)
#define MT_TMAC_TCR_LDPC_OFS		BIT(15)
#define MT_TMAC_TCR_TX_STREAMS		GENMASK(17, 16)
#define MT_TMAC_TCR_SCH_IDLE_SEL	GENMASK(19, 18)
#define MT_TMAC_TCR_SCH_DET_PER_IOD	BIT(20)
#define MT_TMAC_TCR_DCH_DET_DISABLE	BIT(21)
#define MT_TMAC_TCR_TX_RIFS		BIT(22)
#define MT_TMAC_TCR_RX_RIFS_MODE	BIT(23)
#define MT_TMAC_TCR_TXOP_TBTT_CTL	BIT(24)
#define MT_TMAC_TCR_TBTT_TX_STOP_CTL	BIT(25)
#define MT_TMAC_TCR_TXOP_BURST_STOP	BIT(26)
#define MT_TMAC_TCR_RDG_RA_MODE		BIT(27)
#define MT_TMAC_TCR_RDG_RESP		BIT(29)
#define MT_TMAC_TCR_RDG_NO_PENDING	BIT(30)
#define MT_TMAC_TCR_SMOOTHING		BIT(31)

#define MT_WMM_TXOP_BASE		MT_WF_TMAC(0x010)
#define MT_WMM_TXOP(_n)			(MT_WMM_TXOP_BASE + \
					 ((((_n) / 2) ^ 0x1) << 2))
#define MT_WMM_TXOP_SHIFT(_n)		(((_n) & 1) * 16)
#define MT_WMM_TXOP_MASK		GENMASK(15, 0)

#define MT_TIMEOUT_CCK			MT_WF_TMAC(0x090)
#define MT_TIMEOUT_OFDM			MT_WF_TMAC(0x094)
#define MT_TIMEOUT_VAL_PLCP		GENMASK(15, 0)
#define MT_TIMEOUT_VAL_CCA		GENMASK(31, 16)

#define MT_TXREQ			MT_WF_TMAC(0x09c)
#define MT_TXREQ_CCA_SRC_SEL		GENMASK(31, 30)

#define MT_RXREQ			MT_WF_TMAC(0x0a0)
#define MT_RXREQ_DELAY			GENMASK(8, 0)

#define MT_IFS				MT_WF_TMAC(0x0a4)
#define MT_IFS_EIFS			GENMASK(8, 0)
#define MT_IFS_RIFS			GENMASK(14, 10)
#define MT_IFS_SIFS			GENMASK(22, 16)
#define MT_IFS_SLOT			GENMASK(30, 24)

#define MT_TMAC_PCR			MT_WF_TMAC(0x0b4)
#define MT_TMAC_PCR_RATE		GENMASK(8, 0)
#define MT_TMAC_PCR_RATE_FIXED		BIT(15)
#define MT_TMAC_PCR_ANT_ID		GENMASK(21, 16)
#define MT_TMAC_PCR_ANT_ID_SEL		BIT(22)
#define MT_TMAC_PCR_SPE_EN		BIT(23)
#define MT_TMAC_PCR_ANT_PRI		GENMASK(26, 24)
#define MT_TMAC_PCR_ANT_PRI_SEL		GENMASK(27)

#define MT_WF_RMAC_BASE			0x21800
#define MT_WF_RMAC(ofs)			(MT_WF_RMAC_BASE + (ofs))

#define MT_WF_RFCR			MT_WF_RMAC(0x000)
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

#define MT_BSSID0(idx)			MT_WF_RMAC(0x004 + (idx) * 8)
#define MT_BSSID1(idx)			MT_WF_RMAC(0x008 + (idx) * 8)
#define MT_BSSID1_VALID			BIT(16)

#define MT_MAC_ADDR0(idx)		MT_WF_RMAC(0x024 + (idx) * 8)
#define MT_MAC_ADDR1(idx)		MT_WF_RMAC(0x028 + (idx) * 8)
#define MT_MAC_ADDR1_ADDR		GENMASK(15, 0)
#define MT_MAC_ADDR1_VALID		BIT(16)

#define MT_BA_CONTROL_0			MT_WF_RMAC(0x068)
#define MT_BA_CONTROL_1			MT_WF_RMAC(0x06c)
#define MT_BA_CONTROL_1_ADDR		GENMASK(15, 0)
#define MT_BA_CONTROL_1_TID		GENMASK(19, 16)
#define MT_BA_CONTROL_1_IGNORE_TID	BIT(20)
#define MT_BA_CONTROL_1_IGNORE_ALL	BIT(21)
#define MT_BA_CONTROL_1_RESET		BIT(22)

#define MT_WF_RMACDR			MT_WF_RMAC(0x078)
#define MT_WF_RMACDR_TSF_PROBERSP_DIS	BIT(0)
#define MT_WF_RMACDR_TSF_TIM		BIT(4)
#define MT_WF_RMACDR_MBSSID_MASK	GENMASK(25, 24)
#define MT_WF_RMACDR_CHECK_HTC_BY_RATE	BIT(26)
#define MT_WF_RMACDR_MAXLEN_20BIT	BIT(30)

#define MT_WF_RMAC_RMCR			MT_WF_RMAC(0x080)
#define MT_WF_RMAC_RMCR_SMPS_MODE	GENMASK(21, 20)
#define MT_WF_RMAC_RMCR_RX_STREAMS	GENMASK(24, 22)
#define MT_WF_RMAC_RMCR_SMPS_RTS	BIT(25)

#define MT_WF_RMAC_CH_FREQ		MT_WF_RMAC(0x090)
#define MT_WF_RMAC_MAXMINLEN		MT_WF_RMAC(0x098)
#define MT_WF_RFCR1			MT_WF_RMAC(0x0a4)
#define MT_WF_RMAC_TMR_PA		MT_WF_RMAC(0x0e0)

#define MT_WF_SEC_BASE			0x21a00
#define MT_WF_SEC(ofs)			(MT_WF_SEC_BASE + (ofs))

#define MT_SEC_SCR			MT_WF_SEC(0x004)
#define MT_SEC_SCR_MASK_ORDER		GENMASK(1, 0)

#define MT_WTBL_OFF_BASE		0x23000
#define MT_WTBL_OFF(n)			(MT_WTBL_OFF_BASE + (n))

#define MT_WTBL_UPDATE			MT_WTBL_OFF(0x000)
#define MT_WTBL_UPDATE_WLAN_IDX		GENMASK(7, 0)
#define MT_WTBL_UPDATE_WTBL2		BIT(11)
#define MT_WTBL_UPDATE_ADM_COUNT_CLEAR	BIT(12)
#define MT_WTBL_UPDATE_RATE_UPDATE	BIT(13)
#define MT_WTBL_UPDATE_TX_COUNT_CLEAR	BIT(14)
#define MT_WTBL_UPDATE_RX_COUNT_CLEAR	BIT(15)
#define MT_WTBL_UPDATE_BUSY		BIT(16)

#define MT_WTBL_RMVTCR			MT_WTBL_OFF(0x008)
#define MT_WTBL_RMVTCR_RX_MV_MODE	BIT(23)

#define MT_LPON_BASE			0x24000
#define MT_LPON(n)			(MT_LPON_BASE + (n))

#define MT_LPON_T0CR			MT_LPON(0x010)
#define MT_LPON_T0CR_MODE		GENMASK(1, 0)

#define MT_LPON_UTTR0			MT_LPON(0x018)
#define MT_LPON_UTTR1			MT_LPON(0x01c)

#define MT_LPON_BTEIR			MT_LPON(0x020)
#define MT_LPON_BTEIR_MBSS_MODE		GENMASK(31, 29)

#define MT_PRE_TBTT			MT_LPON(0x030)
#define MT_PRE_TBTT_MASK		GENMASK(7, 0)
#define MT_PRE_TBTT_SHIFT		8

#define MT_TBTT				MT_LPON(0x034)
#define MT_TBTT_PERIOD			GENMASK(15, 0)
#define MT_TBTT_DTIM_PERIOD		GENMASK(23, 16)
#define MT_TBTT_TBTT_WAKE_PERIOD	GENMASK(27, 24)
#define MT_TBTT_DTIM_WAKE_PERIOD	GENMASK(30, 28)
#define MT_TBTT_CAL_ENABLE		BIT(31)

#define MT_TBTT_TIMER_CFG		MT_LPON(0x05c)

#define MT_LPON_SBTOR(n)		MT_LPON(0x0a0)
#define MT_LPON_SBTOR_SUB_BSS_EN	BIT(29)
#define MT_LPON_SBTOR_TIME_OFFSET	GENMASK(19, 0)

#define MT_INT_WAKEUP_BASE		0x24400
#define MT_INT_WAKEUP(n)		(MT_INT_WAKEUP_BASE + (n))

#define MT_HW_INT_STATUS(n)		MT_INT_WAKEUP(0x3c + (n) * 8)
#define MT_HW_INT_MASK(n)		MT_INT_WAKEUP(0x40 + (n) * 8)

#define MT_HW_INT3_TBTT0		BIT(15)
#define MT_HW_INT3_PRE_TBTT0		BIT(31)

#define MT_WTBL1_BASE			0x28000

#define MT_WTBL_ON_BASE			(MT_WTBL1_BASE + 0x2000)
#define MT_WTBL_ON(_n)			(MT_WTBL_ON_BASE + (_n))

#define MT_WTBL_RIUCR0			MT_WTBL_ON(0x200)

#define MT_WTBL_RIUCR1			MT_WTBL_ON(0x204)
#define MT_WTBL_RIUCR1_RATE0		GENMASK(11, 0)
#define MT_WTBL_RIUCR1_RATE1		GENMASK(23, 12)
#define MT_WTBL_RIUCR1_RATE2_LO		GENMASK(31, 24)

#define MT_WTBL_RIUCR2			MT_WTBL_ON(0x208)
#define MT_WTBL_RIUCR2_RATE2_HI		GENMASK(3, 0)
#define MT_WTBL_RIUCR2_RATE3		GENMASK(15, 4)
#define MT_WTBL_RIUCR2_RATE4		GENMASK(27, 16)
#define MT_WTBL_RIUCR2_RATE5_LO		GENMASK(31, 28)

#define MT_WTBL_RIUCR3			MT_WTBL_ON(0x20c)
#define MT_WTBL_RIUCR3_RATE5_HI		GENMASK(7, 0)
#define MT_WTBL_RIUCR3_RATE6		GENMASK(19, 8)
#define MT_WTBL_RIUCR3_RATE7		GENMASK(31, 20)

#define MT_MIB_BASE			0x2c000
#define MT_MIB(_n)			(MT_MIB_BASE + (_n))

#define MT_MIB_CTL			MT_MIB(0x00)
#define MT_MIB_CTL_PSCCA_TIME		GENMASK(13, 11)
#define MT_MIB_CTL_CCA_NAV_TX		GENMASK(16, 14)
#define MT_MIB_CTL_ED_TIME		GENMASK(30, 28)
#define MT_MIB_CTL_READ_CLR_DIS		BIT(31)

#define MT_MIB_STAT(_n)			MT_MIB(0x08 + (_n) * 4)

#define MT_MIB_STAT_CCA			MT_MIB_STAT(9)
#define MT_MIB_STAT_CCA_MASK		GENMASK(23, 0)

#define MT_MIB_STAT_PSCCA		MT_MIB_STAT(16)
#define MT_MIB_STAT_PSCCA_MASK		GENMASK(23, 0)

#define MT_TX_AGG_CNT(n)		MT_MIB(0xa8 + ((n) << 2))

#define MT_MIB_STAT_ED			MT_MIB_STAT(18)
#define MT_MIB_STAT_ED_MASK		GENMASK(23, 0)

#define MT_PCIE_REMAP_BASE_1		0x40000
#define MT_PCIE_REMAP_BASE_2		0x80000

#define MT_TX_HW_QUEUE_MGMT		4
#define MT_TX_HW_QUEUE_MCU		5
#define MT_TX_HW_QUEUE_BCN		7
#define MT_TX_HW_QUEUE_BMC		8

#define MT_LED_BASE_PHYS		0x80024000
#define MT_LED_PHYS(_n)			(MT_LED_BASE_PHYS + (_n))

#define MT_LED_CTRL			MT_LED_PHYS(0x00)

#define MT_LED_CTRL_REPLAY(_n)		BIT(0 + (8 * (_n)))
#define MT_LED_CTRL_POLARITY(_n)	BIT(1 + (8 * (_n)))
#define MT_LED_CTRL_TX_BLINK_MODE(_n)	BIT(2 + (8 * (_n)))
#define MT_LED_CTRL_TX_MANUAL_BLINK(_n)	BIT(3 + (8 * (_n)))
#define MT_LED_CTRL_TX_OVER_BLINK(_n)	BIT(5 + (8 * (_n)))
#define MT_LED_CTRL_KICK(_n)		BIT(7 + (8 * (_n)))

#define MT_LED_STATUS_0(_n)		MT_LED_PHYS(0x10 + ((_n) * 8))
#define MT_LED_STATUS_1(_n)		MT_LED_PHYS(0x14 + ((_n) * 8))
#define MT_LED_STATUS_OFF		GENMASK(31, 24)
#define MT_LED_STATUS_ON		GENMASK(23, 16)
#define MT_LED_STATUS_DURATION		GENMASK(15, 0)

#define MT_CLIENT_BASE_PHYS_ADDR	0x800c0000

#define MT_CLIENT_TMAC_INFO_TEMPLATE	0x040

#define MT_CLIENT_STATUS		0x06c

#define MT_CLIENT_RESET_TX		0x070
#define MT_CLIENT_RESET_TX_R_E_1	BIT(16)
#define MT_CLIENT_RESET_TX_R_E_2	BIT(17)
#define MT_CLIENT_RESET_TX_R_E_1_S	BIT(20)
#define MT_CLIENT_RESET_TX_R_E_2_S	BIT(21)

#define MT_EFUSE_BASE			0x81070000

#define MT_EFUSE_BASE_CTRL		0x000
#define MT_EFUSE_BASE_CTRL_EMPTY	BIT(30)

#define MT_EFUSE_CTRL			0x008
#define MT_EFUSE_CTRL_AOUT		GENMASK(5, 0)
#define MT_EFUSE_CTRL_MODE		GENMASK(7, 6)
#define MT_EFUSE_CTRL_LDO_OFF_TIME	GENMASK(13, 8)
#define MT_EFUSE_CTRL_LDO_ON_TIME	GENMASK(15, 14)
#define MT_EFUSE_CTRL_AIN		GENMASK(25, 16)
#define MT_EFUSE_CTRL_VALID		BIT(29)
#define MT_EFUSE_CTRL_KICK		BIT(30)
#define MT_EFUSE_CTRL_SEL		BIT(31)

#define MT_EFUSE_WDATA(_i)		(0x010 + ((_i) * 4))
#define MT_EFUSE_RDATA(_i)		(0x030 + ((_i) * 4))

#define MT_CLIENT_RXINF			0x068
#define MT_CLIENT_RXINF_RXSH_GROUPS	GENMASK(2, 0)

#define MT_PSE_BASE_PHYS_ADDR		0xa0000000

#define MT_PSE_WTBL_2_PHYS_ADDR		0xa5000000

#define MT_WTBL1_SIZE			(8 * 4)
#define MT_WTBL2_SIZE			(16 * 4)
#define MT_WTBL3_OFFSET			(MT7603_WTBL_SIZE * MT_WTBL2_SIZE)
#define MT_WTBL3_SIZE			(16 * 4)
#define MT_WTBL4_OFFSET			(MT7603_WTBL_SIZE * MT_WTBL3_SIZE + \
					 MT_WTBL3_OFFSET)
#define MT_WTBL4_SIZE			(8 * 4)

#define MT_WTBL1_W0_ADDR_HI		GENMASK(15, 0)
#define MT_WTBL1_W0_MUAR_IDX		GENMASK(21, 16)
#define MT_WTBL1_W0_RX_CHECK_A1		BIT(22)
#define MT_WTBL1_W0_KEY_IDX		GENMASK(24, 23)
#define MT_WTBL1_W0_RX_CHECK_KEY_IDX	BIT(25)
#define MT_WTBL1_W0_RX_KEY_VALID	BIT(26)
#define MT_WTBL1_W0_RX_IK_VALID		BIT(27)
#define MT_WTBL1_W0_RX_VALID		BIT(28)
#define MT_WTBL1_W0_RX_CHECK_A2		BIT(29)
#define MT_WTBL1_W0_RX_DATA_VALID	BIT(30)
#define MT_WTBL1_W0_WRITE_BURST		BIT(31)

#define MT_WTBL1_W1_ADDR_LO		GENMASK(31, 0)

#define MT_WTBL1_W2_MPDU_DENSITY	GENMASK(2, 0)
#define MT_WTBL1_W2_KEY_TYPE		GENMASK(6, 3)
#define MT_WTBL1_W2_EVEN_PN		BIT(7)
#define MT_WTBL1_W2_TO_DS		BIT(8)
#define MT_WTBL1_W2_FROM_DS		BIT(9)
#define MT_WTBL1_W2_HEADER_TRANS	BIT(10)
#define MT_WTBL1_W2_AMPDU_FACTOR	GENMASK(13, 11)
#define MT_WTBL1_W2_PWR_MGMT		BIT(14)
#define MT_WTBL1_W2_RDG			BIT(15)
#define MT_WTBL1_W2_RTS			BIT(16)
#define MT_WTBL1_W2_CFACK		BIT(17)
#define MT_WTBL1_W2_RDG_BA		BIT(18)
#define MT_WTBL1_W2_SMPS		BIT(19)
#define MT_WTBL1_W2_TXS_BAF_REPORT	BIT(20)
#define MT_WTBL1_W2_DYN_BW		BIT(21)
#define MT_WTBL1_W2_LDPC		BIT(22)
#define MT_WTBL1_W2_ITXBF		BIT(23)
#define MT_WTBL1_W2_ETXBF		BIT(24)
#define MT_WTBL1_W2_TXOP_PS		BIT(25)
#define MT_WTBL1_W2_MESH		BIT(26)
#define MT_WTBL1_W2_QOS			BIT(27)
#define MT_WTBL1_W2_HT			BIT(28)
#define MT_WTBL1_W2_VHT			BIT(29)
#define MT_WTBL1_W2_ADMISSION_CONTROL	BIT(30)
#define MT_WTBL1_W2_GROUP_ID		BIT(31)

#define MT_WTBL1_W3_WTBL2_FRAME_ID	GENMASK(10, 0)
#define MT_WTBL1_W3_WTBL2_ENTRY_ID	GENMASK(15, 11)
#define MT_WTBL1_W3_WTBL4_FRAME_ID	GENMASK(26, 16)
#define MT_WTBL1_W3_CHECK_PER		BIT(27)
#define MT_WTBL1_W3_KEEP_I_PSM		BIT(28)
#define MT_WTBL1_W3_I_PSM		BIT(29)
#define MT_WTBL1_W3_POWER_SAVE		BIT(30)
#define MT_WTBL1_W3_SKIP_TX		BIT(31)

#define MT_WTBL1_W4_WTBL3_FRAME_ID	GENMASK(10, 0)
#define MT_WTBL1_W4_WTBL3_ENTRY_ID	GENMASK(16, 11)
#define MT_WTBL1_W4_WTBL4_ENTRY_ID	GENMASK(22, 17)
#define MT_WTBL1_W4_PARTIAL_AID		GENMASK(31, 23)

#define MT_WTBL2_W0_PN_LO		GENMASK(31, 0)

#define MT_WTBL2_W1_PN_HI		GENMASK(15, 0)
#define MT_WTBL2_W1_NON_QOS_SEQNO	GENMASK(27, 16)

#define MT_WTBL2_W2_TID0_SN		GENMASK(11, 0)
#define MT_WTBL2_W2_TID1_SN		GENMASK(23, 12)
#define MT_WTBL2_W2_TID2_SN_LO		GENMASK(31, 24)

#define MT_WTBL2_W3_TID2_SN_HI		GENMASK(3, 0)
#define MT_WTBL2_W3_TID3_SN		GENMASK(15, 4)
#define MT_WTBL2_W3_TID4_SN		GENMASK(27, 16)
#define MT_WTBL2_W3_TID5_SN_LO		GENMASK(31, 28)

#define MT_WTBL2_W4_TID5_SN_HI		GENMASK(7, 0)
#define MT_WTBL2_W4_TID6_SN		GENMASK(19, 8)
#define MT_WTBL2_W4_TID7_SN		GENMASK(31, 20)

#define MT_WTBL2_W5_TX_COUNT_RATE1	GENMASK(15, 0)
#define MT_WTBL2_W5_FAIL_COUNT_RATE1	GENAMSK(31, 16)

#define MT_WTBL2_W6_TX_COUNT_RATE2	GENMASK(7, 0)
#define MT_WTBL2_W6_TX_COUNT_RATE3	GENMASK(15, 8)
#define MT_WTBL2_W6_TX_COUNT_RATE4	GENMASK(23, 16)
#define MT_WTBL2_W6_TX_COUNT_RATE5	GENMASK(31, 24)

#define MT_WTBL2_W7_TX_COUNT_CUR_BW	GENMASK(15, 0)
#define MT_WTBL2_W7_FAIL_COUNT_CUR_BW	GENMASK(31, 16)

#define MT_WTBL2_W8_TX_COUNT_OTHER_BW	GENMASK(15, 0)
#define MT_WTBL2_W8_FAIL_COUNT_OTHER_BW	GENMASK(31, 16)

#define MT_WTBL2_W9_POWER_OFFSET	GENMASK(4, 0)
#define MT_WTBL2_W9_SPATIAL_EXT		BIT(5)
#define MT_WTBL2_W9_ANT_PRIORITY	GENMASK(8, 6)
#define MT_WTBL2_W9_CC_BW_SEL		GENMASK(10, 9)
#define MT_WTBL2_W9_CHANGE_BW_RATE	GENMASK(13, 11)
#define MT_WTBL2_W9_BW_CAP		GENMASK(15, 14)
#define MT_WTBL2_W9_SHORT_GI_20		BIT(16)
#define MT_WTBL2_W9_SHORT_GI_40		BIT(17)
#define MT_WTBL2_W9_SHORT_GI_80		BIT(18)
#define MT_WTBL2_W9_SHORT_GI_160	BIT(19)
#define MT_WTBL2_W9_MPDU_FAIL_COUNT	GENMASK(25, 23)
#define MT_WTBL2_W9_MPDU_OK_COUNT	GENMASK(28, 26)
#define MT_WTBL2_W9_RATE_IDX		GENMASK(31, 29)

#define MT_WTBL2_W10_RATE1		GENMASK(11, 0)
#define MT_WTBL2_W10_RATE2		GENMASK(23, 12)
#define MT_WTBL2_W10_RATE3_LO		GENMASK(31, 24)

#define MT_WTBL2_W11_RATE3_HI		GENMASK(3, 0)
#define MT_WTBL2_W11_RATE4		GENMASK(15, 4)
#define MT_WTBL2_W11_RATE5		GENMASK(27, 16)
#define MT_WTBL2_W11_RATE6_LO		GENMASK(31, 28)

#define MT_WTBL2_W12_RATE6_HI		GENMASK(7, 0)
#define MT_WTBL2_W12_RATE7		GENMASK(19, 8)
#define MT_WTBL2_W12_RATE8		GENMASK(31, 20)

#define MT_WTBL2_W13_AVG_RCPI0		GENMASK(7, 0)
#define MT_WTBL2_W13_AVG_RCPI1		GENMASK(15, 8)
#define MT_WTBL2_W13_AVG_RCPI2		GENAMSK(23, 16)

#define MT_WTBL2_W14_CC_NOISE_1S	GENMASK(6, 0)
#define MT_WTBL2_W14_CC_NOISE_2S	GENMASK(13, 7)
#define MT_WTBL2_W14_CC_NOISE_3S	GENMASK(20, 14)
#define MT_WTBL2_W14_CHAN_EST_RMS	GENMASK(24, 21)
#define MT_WTBL2_W14_CC_NOISE_SEL	BIT(15)
#define MT_WTBL2_W14_ANT_SEL		GENMASK(31, 26)

#define MT_WTBL2_W15_BA_WIN_SIZE	GENMASK(2, 0)
#define MT_WTBL2_W15_BA_WIN_SIZE_SHIFT	3
#define MT_WTBL2_W15_BA_EN_TIDS		GENMASK(31, 24)

#define MT_WTBL1_OR			(MT_WTBL1_BASE + 0x2300)
#define MT_WTBL1_OR_PSM_WRITE		BIT(31)

enum mt7603_cipher_type {
	MT_CIPHER_NONE,
	MT_CIPHER_WEP40,
	MT_CIPHER_TKIP,
	MT_CIPHER_TKIP_NO_MIC,
	MT_CIPHER_AES_CCMP,
	MT_CIPHER_WEP104,
	MT_CIPHER_BIP_CMAC_128,
	MT_CIPHER_WEP128,
	MT_CIPHER_WAPI,
};

#endif
