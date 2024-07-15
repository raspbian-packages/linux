/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * ALSA SoC Audio Layer - Rockchip I2S/TDM Controller driver
 *
 * Copyright (c) 2018 Rockchip Electronics Co. Ltd.
 * Author: Sugar Zhang <sugar.zhang@rock-chips.com>
 *
 */

#ifndef _ROCKCHIP_I2S_TDM_H
#define _ROCKCHIP_I2S_TDM_H

/*
 * TXCR
 * transmit operation control register
 */
#define I2S_TXCR_PATH_SHIFT(x)	(23 + (x) * 2)
#define I2S_TXCR_PATH_MASK(x)	(0x3 << I2S_TXCR_PATH_SHIFT(x))
#define I2S_TXCR_PATH(x, v)	((v) << I2S_TXCR_PATH_SHIFT(x))
#define I2S_TXCR_RCNT_SHIFT	17
#define I2S_TXCR_RCNT_MASK	(0x3f << I2S_TXCR_RCNT_SHIFT)
#define I2S_TXCR_CSR_SHIFT	15
#define I2S_TXCR_CSR(x)		((x) << I2S_TXCR_CSR_SHIFT)
#define I2S_TXCR_CSR_MASK	(3 << I2S_TXCR_CSR_SHIFT)
#define I2S_TXCR_HWT		BIT(14)
#define I2S_TXCR_SJM_SHIFT	12
#define I2S_TXCR_SJM_R		(0 << I2S_TXCR_SJM_SHIFT)
#define I2S_TXCR_SJM_L		(1 << I2S_TXCR_SJM_SHIFT)
#define I2S_TXCR_FBM_SHIFT	11
#define I2S_TXCR_FBM_MSB	(0 << I2S_TXCR_FBM_SHIFT)
#define I2S_TXCR_FBM_LSB	(1 << I2S_TXCR_FBM_SHIFT)
#define I2S_TXCR_IBM_SHIFT	9
#define I2S_TXCR_IBM_NORMAL	(0 << I2S_TXCR_IBM_SHIFT)
#define I2S_TXCR_IBM_LSJM	(1 << I2S_TXCR_IBM_SHIFT)
#define I2S_TXCR_IBM_RSJM	(2 << I2S_TXCR_IBM_SHIFT)
#define I2S_TXCR_IBM_MASK	(3 << I2S_TXCR_IBM_SHIFT)
#define I2S_TXCR_PBM_SHIFT	7
#define I2S_TXCR_PBM_MODE(x)	((x) << I2S_TXCR_PBM_SHIFT)
#define I2S_TXCR_PBM_MASK	(3 << I2S_TXCR_PBM_SHIFT)
#define I2S_TXCR_TFS_SHIFT	5
#define I2S_TXCR_TFS_I2S	(0 << I2S_TXCR_TFS_SHIFT)
#define I2S_TXCR_TFS_PCM	(1 << I2S_TXCR_TFS_SHIFT)
#define I2S_TXCR_TFS_TDM_PCM	(2 << I2S_TXCR_TFS_SHIFT)
#define I2S_TXCR_TFS_TDM_I2S	(3 << I2S_TXCR_TFS_SHIFT)
#define I2S_TXCR_TFS_MASK	(3 << I2S_TXCR_TFS_SHIFT)
#define I2S_TXCR_VDW_SHIFT	0
#define I2S_TXCR_VDW(x)		(((x) - 1) << I2S_TXCR_VDW_SHIFT)
#define I2S_TXCR_VDW_MASK	(0x1f << I2S_TXCR_VDW_SHIFT)

/*
 * RXCR
 * receive operation control register
 */
#define I2S_RXCR_PATH_SHIFT(x)	(17 + (x) * 2)
#define I2S_RXCR_PATH_MASK(x)	(0x3 << I2S_RXCR_PATH_SHIFT(x))
#define I2S_RXCR_PATH(x, v)	((v) << I2S_RXCR_PATH_SHIFT(x))
#define I2S_RXCR_CSR_SHIFT	15
#define I2S_RXCR_CSR(x)		((x) << I2S_RXCR_CSR_SHIFT)
#define I2S_RXCR_CSR_MASK	(3 << I2S_RXCR_CSR_SHIFT)
#define I2S_RXCR_HWT		BIT(14)
#define I2S_RXCR_SJM_SHIFT	12
#define I2S_RXCR_SJM_R		(0 << I2S_RXCR_SJM_SHIFT)
#define I2S_RXCR_SJM_L		(1 << I2S_RXCR_SJM_SHIFT)
#define I2S_RXCR_FBM_SHIFT	11
#define I2S_RXCR_FBM_MSB	(0 << I2S_RXCR_FBM_SHIFT)
#define I2S_RXCR_FBM_LSB	(1 << I2S_RXCR_FBM_SHIFT)
#define I2S_RXCR_IBM_SHIFT	9
#define I2S_RXCR_IBM_NORMAL	(0 << I2S_RXCR_IBM_SHIFT)
#define I2S_RXCR_IBM_LSJM	(1 << I2S_RXCR_IBM_SHIFT)
#define I2S_RXCR_IBM_RSJM	(2 << I2S_RXCR_IBM_SHIFT)
#define I2S_RXCR_IBM_MASK	(3 << I2S_RXCR_IBM_SHIFT)
#define I2S_RXCR_PBM_SHIFT	7
#define I2S_RXCR_PBM_MODE(x)	((x) << I2S_RXCR_PBM_SHIFT)
#define I2S_RXCR_PBM_MASK	(3 << I2S_RXCR_PBM_SHIFT)
#define I2S_RXCR_TFS_SHIFT	5
#define I2S_RXCR_TFS_I2S	(0 << I2S_RXCR_TFS_SHIFT)
#define I2S_RXCR_TFS_PCM	(1 << I2S_RXCR_TFS_SHIFT)
#define I2S_RXCR_TFS_TDM_PCM	(2 << I2S_RXCR_TFS_SHIFT)
#define I2S_RXCR_TFS_TDM_I2S	(3 << I2S_RXCR_TFS_SHIFT)
#define I2S_RXCR_TFS_MASK	(3 << I2S_RXCR_TFS_SHIFT)
#define I2S_RXCR_VDW_SHIFT	0
#define I2S_RXCR_VDW(x)		(((x) - 1) << I2S_RXCR_VDW_SHIFT)
#define I2S_RXCR_VDW_MASK	(0x1f << I2S_RXCR_VDW_SHIFT)

/*
 * CKR
 * clock generation register
 */
#define I2S_CKR_TRCM_SHIFT	28
#define I2S_CKR_TRCM(x)	((x) << I2S_CKR_TRCM_SHIFT)
#define I2S_CKR_TRCM_TXRX	(0 << I2S_CKR_TRCM_SHIFT)
#define I2S_CKR_TRCM_TXONLY	(1 << I2S_CKR_TRCM_SHIFT)
#define I2S_CKR_TRCM_RXONLY	(2 << I2S_CKR_TRCM_SHIFT)
#define I2S_CKR_TRCM_MASK	(3 << I2S_CKR_TRCM_SHIFT)
#define I2S_CKR_MSS_SHIFT	27
#define I2S_CKR_MSS_MASTER	(0 << I2S_CKR_MSS_SHIFT)
#define I2S_CKR_MSS_SLAVE	(1 << I2S_CKR_MSS_SHIFT)
#define I2S_CKR_MSS_MASK	(1 << I2S_CKR_MSS_SHIFT)
#define I2S_CKR_CKP_SHIFT	26
#define I2S_CKR_CKP_NORMAL	(0 << I2S_CKR_CKP_SHIFT)
#define I2S_CKR_CKP_INVERTED	(1 << I2S_CKR_CKP_SHIFT)
#define I2S_CKR_CKP_MASK	(1 << I2S_CKR_CKP_SHIFT)
#define I2S_CKR_RLP_SHIFT	25
#define I2S_CKR_RLP_NORMAL	(0 << I2S_CKR_RLP_SHIFT)
#define I2S_CKR_RLP_INVERTED	(1 << I2S_CKR_RLP_SHIFT)
#define I2S_CKR_RLP_MASK	(1 << I2S_CKR_RLP_SHIFT)
#define I2S_CKR_TLP_SHIFT	24
#define I2S_CKR_TLP_NORMAL	(0 << I2S_CKR_TLP_SHIFT)
#define I2S_CKR_TLP_INVERTED	(1 << I2S_CKR_TLP_SHIFT)
#define I2S_CKR_TLP_MASK	(1 << I2S_CKR_TLP_SHIFT)
#define I2S_CKR_MDIV_SHIFT	16
#define I2S_CKR_MDIV(x)		(((x) - 1) << I2S_CKR_MDIV_SHIFT)
#define I2S_CKR_MDIV_MASK	(0xff << I2S_CKR_MDIV_SHIFT)
#define I2S_CKR_RSD_SHIFT	8
#define I2S_CKR_RSD(x)		(((x) - 1) << I2S_CKR_RSD_SHIFT)
#define I2S_CKR_RSD_MASK	(0xff << I2S_CKR_RSD_SHIFT)
#define I2S_CKR_TSD_SHIFT	0
#define I2S_CKR_TSD(x)		(((x) - 1) << I2S_CKR_TSD_SHIFT)
#define I2S_CKR_TSD_MASK	(0xff << I2S_CKR_TSD_SHIFT)

/*
 * FIFOLR
 * FIFO level register
 */
#define I2S_FIFOLR_RFL_SHIFT	24
#define I2S_FIFOLR_RFL_MASK	(0x3f << I2S_FIFOLR_RFL_SHIFT)
#define I2S_FIFOLR_TFL3_SHIFT	18
#define I2S_FIFOLR_TFL3_MASK	(0x3f << I2S_FIFOLR_TFL3_SHIFT)
#define I2S_FIFOLR_TFL2_SHIFT	12
#define I2S_FIFOLR_TFL2_MASK	(0x3f << I2S_FIFOLR_TFL2_SHIFT)
#define I2S_FIFOLR_TFL1_SHIFT	6
#define I2S_FIFOLR_TFL1_MASK	(0x3f << I2S_FIFOLR_TFL1_SHIFT)
#define I2S_FIFOLR_TFL0_SHIFT	0
#define I2S_FIFOLR_TFL0_MASK	(0x3f << I2S_FIFOLR_TFL0_SHIFT)

/*
 * DMACR
 * DMA control register
 */
#define I2S_DMACR_RDE_SHIFT	24
#define I2S_DMACR_RDE_DISABLE	(0 << I2S_DMACR_RDE_SHIFT)
#define I2S_DMACR_RDE_ENABLE	(1 << I2S_DMACR_RDE_SHIFT)
#define I2S_DMACR_RDL_SHIFT	16
#define I2S_DMACR_RDL(x)	(((x) - 1) << I2S_DMACR_RDL_SHIFT)
#define I2S_DMACR_RDL_MASK	(0x1f << I2S_DMACR_RDL_SHIFT)
#define I2S_DMACR_TDE_SHIFT	8
#define I2S_DMACR_TDE_DISABLE	(0 << I2S_DMACR_TDE_SHIFT)
#define I2S_DMACR_TDE_ENABLE	(1 << I2S_DMACR_TDE_SHIFT)
#define I2S_DMACR_TDL_SHIFT	0
#define I2S_DMACR_TDL(x)	((x) << I2S_DMACR_TDL_SHIFT)
#define I2S_DMACR_TDL_MASK	(0x1f << I2S_DMACR_TDL_SHIFT)

/*
 * INTCR
 * interrupt control register
 */
#define I2S_INTCR_RFT_SHIFT	20
#define I2S_INTCR_RFT(x)	(((x) - 1) << I2S_INTCR_RFT_SHIFT)
#define I2S_INTCR_RXOIC		BIT(18)
#define I2S_INTCR_RXOIE_SHIFT	17
#define I2S_INTCR_RXOIE_DISABLE	(0 << I2S_INTCR_RXOIE_SHIFT)
#define I2S_INTCR_RXOIE_ENABLE	(1 << I2S_INTCR_RXOIE_SHIFT)
#define I2S_INTCR_RXFIE_SHIFT	16
#define I2S_INTCR_RXFIE_DISABLE	(0 << I2S_INTCR_RXFIE_SHIFT)
#define I2S_INTCR_RXFIE_ENABLE	(1 << I2S_INTCR_RXFIE_SHIFT)
#define I2S_INTCR_TFT_SHIFT	4
#define I2S_INTCR_TFT(x)	(((x) - 1) << I2S_INTCR_TFT_SHIFT)
#define I2S_INTCR_TFT_MASK	(0x1f << I2S_INTCR_TFT_SHIFT)
#define I2S_INTCR_TXUIC		BIT(2)
#define I2S_INTCR_TXUIE_SHIFT	1
#define I2S_INTCR_TXUIE_DISABLE	(0 << I2S_INTCR_TXUIE_SHIFT)
#define I2S_INTCR_TXUIE_ENABLE	(1 << I2S_INTCR_TXUIE_SHIFT)

/*
 * INTSR
 * interrupt status register
 */
#define I2S_INTSR_TXEIE_SHIFT	0
#define I2S_INTSR_TXEIE_DISABLE	(0 << I2S_INTSR_TXEIE_SHIFT)
#define I2S_INTSR_TXEIE_ENABLE	(1 << I2S_INTSR_TXEIE_SHIFT)
#define I2S_INTSR_RXOI_SHIFT	17
#define I2S_INTSR_RXOI_INA	(0 << I2S_INTSR_RXOI_SHIFT)
#define I2S_INTSR_RXOI_ACT	(1 << I2S_INTSR_RXOI_SHIFT)
#define I2S_INTSR_RXFI_SHIFT	16
#define I2S_INTSR_RXFI_INA	(0 << I2S_INTSR_RXFI_SHIFT)
#define I2S_INTSR_RXFI_ACT	(1 << I2S_INTSR_RXFI_SHIFT)
#define I2S_INTSR_TXUI_SHIFT	1
#define I2S_INTSR_TXUI_INA	(0 << I2S_INTSR_TXUI_SHIFT)
#define I2S_INTSR_TXUI_ACT	(1 << I2S_INTSR_TXUI_SHIFT)
#define I2S_INTSR_TXEI_SHIFT	0
#define I2S_INTSR_TXEI_INA	(0 << I2S_INTSR_TXEI_SHIFT)
#define I2S_INTSR_TXEI_ACT	(1 << I2S_INTSR_TXEI_SHIFT)

/*
 * XFER
 * Transfer start register
 */
#define I2S_XFER_RXS_SHIFT	1
#define I2S_XFER_RXS_STOP	(0 << I2S_XFER_RXS_SHIFT)
#define I2S_XFER_RXS_START	(1 << I2S_XFER_RXS_SHIFT)
#define I2S_XFER_TXS_SHIFT	0
#define I2S_XFER_TXS_STOP	(0 << I2S_XFER_TXS_SHIFT)
#define I2S_XFER_TXS_START	(1 << I2S_XFER_TXS_SHIFT)

/*
 * CLR
 * clear SCLK domain logic register
 */
#define I2S_CLR_RXC	BIT(1)
#define I2S_CLR_TXC	BIT(0)

/*
 * TXDR
 * Transimt FIFO data register, write only.
 */
#define I2S_TXDR_MASK	(0xff)

/*
 * RXDR
 * Receive FIFO data register, write only.
 */
#define I2S_RXDR_MASK	(0xff)

/*
 * TDM_CTRL
 * TDM ctrl register
 */
#define TDM_FSYNC_WIDTH_SEL1_MSK	GENMASK(20, 18)
#define TDM_FSYNC_WIDTH_SEL1(x)		(((x) - 1) << 18)
#define TDM_FSYNC_WIDTH_SEL0_MSK	BIT(17)
#define TDM_FSYNC_WIDTH_HALF_FRAME	0
#define TDM_FSYNC_WIDTH_ONE_FRAME	BIT(17)
#define TDM_SHIFT_CTRL_MSK		GENMASK(16, 14)
#define TDM_SHIFT_CTRL(x)		((x) << 14)
#define TDM_SLOT_BIT_WIDTH_MSK		GENMASK(13, 9)
#define TDM_SLOT_BIT_WIDTH(x)		(((x) - 1) << 9)
#define TDM_FRAME_WIDTH_MSK		GENMASK(8, 0)
#define TDM_FRAME_WIDTH(x)		(((x) - 1) << 0)

/*
 * CLKDIV
 * Mclk div register
 */
#define I2S_CLKDIV_TXM_SHIFT	0
#define I2S_CLKDIV_TXM(x)		(((x) - 1) << I2S_CLKDIV_TXM_SHIFT)
#define I2S_CLKDIV_TXM_MASK	(0xff << I2S_CLKDIV_TXM_SHIFT)
#define I2S_CLKDIV_RXM_SHIFT	8
#define I2S_CLKDIV_RXM(x)		(((x) - 1) << I2S_CLKDIV_RXM_SHIFT)
#define I2S_CLKDIV_RXM_MASK	(0xff << I2S_CLKDIV_RXM_SHIFT)

/* Clock divider id */
enum {
	ROCKCHIP_DIV_MCLK = 0,
	ROCKCHIP_DIV_BCLK,
};

/* channel select */
#define I2S_CSR_SHIFT	15
#define I2S_CHN_2	(0 << I2S_CSR_SHIFT)
#define I2S_CHN_4	(1 << I2S_CSR_SHIFT)
#define I2S_CHN_6	(2 << I2S_CSR_SHIFT)
#define I2S_CHN_8	(3 << I2S_CSR_SHIFT)

/* io direction cfg register */
#define I2S_IO_DIRECTION_MASK	(7)
#define I2S_IO_8CH_OUT_2CH_IN	(7)
#define I2S_IO_6CH_OUT_4CH_IN	(3)
#define I2S_IO_4CH_OUT_6CH_IN	(1)
#define I2S_IO_2CH_OUT_8CH_IN	(0)

/* I2S REGS */
#define I2S_TXCR	(0x0000)
#define I2S_RXCR	(0x0004)
#define I2S_CKR		(0x0008)
#define I2S_TXFIFOLR	(0x000c)
#define I2S_DMACR	(0x0010)
#define I2S_INTCR	(0x0014)
#define I2S_INTSR	(0x0018)
#define I2S_XFER	(0x001c)
#define I2S_CLR		(0x0020)
#define I2S_TXDR	(0x0024)
#define I2S_RXDR	(0x0028)
#define I2S_RXFIFOLR	(0x002c)
#define I2S_TDM_TXCR	(0x0030)
#define I2S_TDM_RXCR	(0x0034)
#define I2S_CLKDIV	(0x0038)

#define HIWORD_UPDATE(v, h, l)	(((v) << (l)) | (GENMASK((h), (l)) << 16))

/* PX30 GRF CONFIGS */
#define PX30_I2S0_CLK_IN_SRC_FROM_TX		HIWORD_UPDATE(1, 13, 12)
#define PX30_I2S0_CLK_IN_SRC_FROM_RX		HIWORD_UPDATE(2, 13, 12)
#define PX30_I2S0_MCLK_OUT_SRC_FROM_TX		HIWORD_UPDATE(1, 5, 5)
#define PX30_I2S0_MCLK_OUT_SRC_FROM_RX		HIWORD_UPDATE(0, 5, 5)

#define PX30_I2S0_CLK_TXONLY \
	(PX30_I2S0_MCLK_OUT_SRC_FROM_TX | PX30_I2S0_CLK_IN_SRC_FROM_TX)

#define PX30_I2S0_CLK_RXONLY \
	(PX30_I2S0_MCLK_OUT_SRC_FROM_RX | PX30_I2S0_CLK_IN_SRC_FROM_RX)

/* RK1808 GRF CONFIGS */
#define RK1808_I2S0_MCLK_OUT_SRC_FROM_RX	HIWORD_UPDATE(1, 2, 2)
#define RK1808_I2S0_MCLK_OUT_SRC_FROM_TX	HIWORD_UPDATE(0, 2, 2)
#define RK1808_I2S0_CLK_IN_SRC_FROM_TX		HIWORD_UPDATE(1, 1, 0)
#define RK1808_I2S0_CLK_IN_SRC_FROM_RX		HIWORD_UPDATE(2, 1, 0)

#define RK1808_I2S0_CLK_TXONLY \
	(RK1808_I2S0_MCLK_OUT_SRC_FROM_TX | RK1808_I2S0_CLK_IN_SRC_FROM_TX)

#define RK1808_I2S0_CLK_RXONLY \
	(RK1808_I2S0_MCLK_OUT_SRC_FROM_RX | RK1808_I2S0_CLK_IN_SRC_FROM_RX)

/* RK3308 GRF CONFIGS */
#define RK3308_I2S0_8CH_MCLK_OUT_SRC_FROM_RX	HIWORD_UPDATE(1, 10, 10)
#define RK3308_I2S0_8CH_MCLK_OUT_SRC_FROM_TX	HIWORD_UPDATE(0, 10, 10)
#define RK3308_I2S0_8CH_CLK_IN_RX_SRC_FROM_TX	HIWORD_UPDATE(1, 9, 9)
#define RK3308_I2S0_8CH_CLK_IN_RX_SRC_FROM_RX	HIWORD_UPDATE(0, 9, 9)
#define RK3308_I2S0_8CH_CLK_IN_TX_SRC_FROM_RX	HIWORD_UPDATE(1, 8, 8)
#define RK3308_I2S0_8CH_CLK_IN_TX_SRC_FROM_TX	HIWORD_UPDATE(0, 8, 8)
#define RK3308_I2S1_8CH_MCLK_OUT_SRC_FROM_RX	HIWORD_UPDATE(1, 2, 2)
#define RK3308_I2S1_8CH_MCLK_OUT_SRC_FROM_TX	HIWORD_UPDATE(0, 2, 2)
#define RK3308_I2S1_8CH_CLK_IN_RX_SRC_FROM_TX	HIWORD_UPDATE(1, 1, 1)
#define RK3308_I2S1_8CH_CLK_IN_RX_SRC_FROM_RX	HIWORD_UPDATE(0, 1, 1)
#define RK3308_I2S1_8CH_CLK_IN_TX_SRC_FROM_RX	HIWORD_UPDATE(1, 0, 0)
#define RK3308_I2S1_8CH_CLK_IN_TX_SRC_FROM_TX	HIWORD_UPDATE(0, 0, 0)

#define RK3308_I2S0_CLK_TXONLY \
	(RK3308_I2S0_8CH_MCLK_OUT_SRC_FROM_TX | \
	RK3308_I2S0_8CH_CLK_IN_RX_SRC_FROM_TX | \
	RK3308_I2S0_8CH_CLK_IN_TX_SRC_FROM_TX)

#define RK3308_I2S0_CLK_RXONLY \
	(RK3308_I2S0_8CH_MCLK_OUT_SRC_FROM_RX | \
	RK3308_I2S0_8CH_CLK_IN_RX_SRC_FROM_RX | \
	RK3308_I2S0_8CH_CLK_IN_TX_SRC_FROM_RX)

#define RK3308_I2S1_CLK_TXONLY \
	(RK3308_I2S1_8CH_MCLK_OUT_SRC_FROM_TX | \
	RK3308_I2S1_8CH_CLK_IN_RX_SRC_FROM_TX | \
	RK3308_I2S1_8CH_CLK_IN_TX_SRC_FROM_TX)

#define RK3308_I2S1_CLK_RXONLY \
	(RK3308_I2S1_8CH_MCLK_OUT_SRC_FROM_RX | \
	RK3308_I2S1_8CH_CLK_IN_RX_SRC_FROM_RX | \
	RK3308_I2S1_8CH_CLK_IN_TX_SRC_FROM_RX)

/* RK3568 GRF CONFIGS */
#define RK3568_I2S1_MCLK_OUT_SRC_FROM_TX	HIWORD_UPDATE(1, 5, 5)
#define RK3568_I2S1_MCLK_OUT_SRC_FROM_RX	HIWORD_UPDATE(0, 5, 5)

#define RK3568_I2S1_CLK_TXONLY \
	RK3568_I2S1_MCLK_OUT_SRC_FROM_TX

#define RK3568_I2S1_CLK_RXONLY \
	RK3568_I2S1_MCLK_OUT_SRC_FROM_RX

#define RK3568_I2S3_MCLK_OUT_SRC_FROM_TX	HIWORD_UPDATE(1, 15, 15)
#define RK3568_I2S3_MCLK_OUT_SRC_FROM_RX	HIWORD_UPDATE(0, 15, 15)
#define RK3568_I2S3_SCLK_SRC_FROM_TX		HIWORD_UPDATE(1, 7, 7)
#define RK3568_I2S3_SCLK_SRC_FROM_RX		HIWORD_UPDATE(0, 7, 7)
#define RK3568_I2S3_LRCK_SRC_FROM_TX		HIWORD_UPDATE(1, 6, 6)
#define RK3568_I2S3_LRCK_SRC_FROM_RX		HIWORD_UPDATE(0, 6, 6)

#define RK3568_I2S3_MCLK_TXONLY \
	RK3568_I2S3_MCLK_OUT_SRC_FROM_TX

#define RK3568_I2S3_CLK_TXONLY \
	(RK3568_I2S3_SCLK_SRC_FROM_TX | \
	RK3568_I2S3_LRCK_SRC_FROM_TX)

#define RK3568_I2S3_MCLK_RXONLY \
	RK3568_I2S3_MCLK_OUT_SRC_FROM_RX

#define RK3568_I2S3_CLK_RXONLY \
	(RK3568_I2S3_SCLK_SRC_FROM_RX | \
	RK3568_I2S3_LRCK_SRC_FROM_RX)

#define RK3568_I2S3_MCLK_IE			HIWORD_UPDATE(0, 3, 3)
#define RK3568_I2S3_MCLK_OE			HIWORD_UPDATE(1, 3, 3)
#define RK3568_I2S2_MCLK_IE			HIWORD_UPDATE(0, 2, 2)
#define RK3568_I2S2_MCLK_OE			HIWORD_UPDATE(1, 2, 2)
#define RK3568_I2S1_MCLK_TX_IE			HIWORD_UPDATE(0, 1, 1)
#define RK3568_I2S1_MCLK_TX_OE			HIWORD_UPDATE(1, 1, 1)
#define RK3568_I2S1_MCLK_RX_IE			HIWORD_UPDATE(0, 0, 0)
#define RK3568_I2S1_MCLK_RX_OE			HIWORD_UPDATE(1, 0, 0)

/* RV1126 GRF CONFIGS */
#define RV1126_I2S0_MCLK_OUT_SRC_FROM_TX	HIWORD_UPDATE(0, 9, 9)
#define RV1126_I2S0_MCLK_OUT_SRC_FROM_RX	HIWORD_UPDATE(1, 9, 9)

#define RV1126_I2S0_CLK_TXONLY \
	RV1126_I2S0_MCLK_OUT_SRC_FROM_TX

#define RV1126_I2S0_CLK_RXONLY \
	RV1126_I2S0_MCLK_OUT_SRC_FROM_RX

#endif /* _ROCKCHIP_I2S_TDM_H */
