// SPDX-License-Identifier: ISC
/* Copyright (C) 2020 MediaTek Inc. */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pci.h>

#include "mt7915.h"
#include "mac.h"
#include "../trace.h"

static const u32 mt7915_reg[] = {
	[INT_SOURCE_CSR]	= 0xd7010,
	[INT_MASK_CSR]		= 0xd7014,
	[INT1_SOURCE_CSR]	= 0xd7088,
	[INT1_MASK_CSR]		= 0xd708c,
	[INT_MCU_CMD_SOURCE]	= 0xd51f0,
	[INT_MCU_CMD_EVENT]	= 0x3108,
	[WFDMA0_ADDR]		= 0xd4000,
	[WFDMA0_PCIE1_ADDR]	= 0xd8000,
	[WFDMA_EXT_CSR_ADDR]	= 0xd7000,
	[CBTOP1_PHY_END]	= 0x77ffffff,
	[INFRA_MCU_ADDR_END]	= 0x7c3fffff,
	[FW_EXCEPTION_ADDR]	= 0x219848,
	[SWDEF_BASE_ADDR]	= 0x41f200,
};

static const u32 mt7916_reg[] = {
	[INT_SOURCE_CSR]	= 0xd4200,
	[INT_MASK_CSR]		= 0xd4204,
	[INT1_SOURCE_CSR]	= 0xd8200,
	[INT1_MASK_CSR]		= 0xd8204,
	[INT_MCU_CMD_SOURCE]	= 0xd41f0,
	[INT_MCU_CMD_EVENT]	= 0x2108,
	[WFDMA0_ADDR]		= 0xd4000,
	[WFDMA0_PCIE1_ADDR]	= 0xd8000,
	[WFDMA_EXT_CSR_ADDR]	= 0xd7000,
	[CBTOP1_PHY_END]	= 0x7fffffff,
	[INFRA_MCU_ADDR_END]	= 0x7c085fff,
	[FW_EXCEPTION_ADDR]	= 0x022050bc,
	[SWDEF_BASE_ADDR]	= 0x411400,
};

static const u32 mt7986_reg[] = {
	[INT_SOURCE_CSR]	= 0x24200,
	[INT_MASK_CSR]		= 0x24204,
	[INT1_SOURCE_CSR]	= 0x28200,
	[INT1_MASK_CSR]		= 0x28204,
	[INT_MCU_CMD_SOURCE]	= 0x241f0,
	[INT_MCU_CMD_EVENT]	= 0x54000108,
	[WFDMA0_ADDR]		= 0x24000,
	[WFDMA0_PCIE1_ADDR]	= 0x28000,
	[WFDMA_EXT_CSR_ADDR]	= 0x27000,
	[CBTOP1_PHY_END]	= 0x7fffffff,
	[INFRA_MCU_ADDR_END]	= 0x7c085fff,
	[FW_EXCEPTION_ADDR]	= 0x02204ffc,
	[SWDEF_BASE_ADDR]	= 0x411400,
};

static const u32 mt7915_offs[] = {
	[TMAC_CDTR]		= 0x090,
	[TMAC_ODTR]		= 0x094,
	[TMAC_ATCR]		= 0x098,
	[TMAC_TRCR0]		= 0x09c,
	[TMAC_ICR0]		= 0x0a4,
	[TMAC_ICR1]		= 0x0b4,
	[TMAC_CTCR0]		= 0x0f4,
	[TMAC_TFCR0]		= 0x1e0,
	[MDP_BNRCFR0]		= 0x070,
	[MDP_BNRCFR1]		= 0x074,
	[ARB_DRNGR0]		= 0x194,
	[ARB_SCR]		= 0x080,
	[RMAC_MIB_AIRTIME14]	= 0x3b8,
	[AGG_AWSCR0]		= 0x05c,
	[AGG_PCR0]		= 0x06c,
	[AGG_ACR0]		= 0x084,
	[AGG_ACR4]		= 0x08c,
	[AGG_MRCR]		= 0x098,
	[AGG_ATCR1]		= 0x0f0,
	[AGG_ATCR3]		= 0x0f4,
	[LPON_UTTR0]		= 0x080,
	[LPON_UTTR1]		= 0x084,
	[LPON_FRCR]		= 0x314,
	[MIB_SDR3]		= 0x014,
	[MIB_SDR4]		= 0x018,
	[MIB_SDR5]		= 0x01c,
	[MIB_SDR7]		= 0x024,
	[MIB_SDR8]		= 0x028,
	[MIB_SDR9]		= 0x02c,
	[MIB_SDR10]		= 0x030,
	[MIB_SDR11]		= 0x034,
	[MIB_SDR12]		= 0x038,
	[MIB_SDR13]		= 0x03c,
	[MIB_SDR14]		= 0x040,
	[MIB_SDR15]		= 0x044,
	[MIB_SDR16]		= 0x048,
	[MIB_SDR17]		= 0x04c,
	[MIB_SDR18]		= 0x050,
	[MIB_SDR19]		= 0x054,
	[MIB_SDR20]		= 0x058,
	[MIB_SDR21]		= 0x05c,
	[MIB_SDR22]		= 0x060,
	[MIB_SDR23]		= 0x064,
	[MIB_SDR24]		= 0x068,
	[MIB_SDR25]		= 0x06c,
	[MIB_SDR27]		= 0x074,
	[MIB_SDR28]		= 0x078,
	[MIB_SDR29]		= 0x07c,
	[MIB_SDRVEC]		= 0x080,
	[MIB_SDR31]		= 0x084,
	[MIB_SDR32]		= 0x088,
	[MIB_SDRMUBF]		= 0x090,
	[MIB_DR8]		= 0x0c0,
	[MIB_DR9]		= 0x0c4,
	[MIB_DR11]		= 0x0cc,
	[MIB_MB_SDR0]		= 0x100,
	[MIB_MB_SDR1]		= 0x104,
	[TX_AGG_CNT]		= 0x0a8,
	[TX_AGG_CNT2]		= 0x164,
	[MIB_ARNG]		= 0x4b8,
	[WTBLON_TOP_WDUCR]	= 0x0,
	[WTBL_UPDATE]		= 0x030,
	[PLE_FL_Q_EMPTY]	= 0x0b0,
	[PLE_FL_Q_CTRL]		= 0x1b0,
	[PLE_AC_QEMPTY]		= 0x500,
	[PLE_FREEPG_CNT]	= 0x100,
	[PLE_FREEPG_HEAD_TAIL]	= 0x104,
	[PLE_PG_HIF_GROUP]	= 0x110,
	[PLE_HIF_PG_INFO]	= 0x114,
	[AC_OFFSET]		= 0x040,
	[ETBF_PAR_RPT0]		= 0x068,
};

static const u32 mt7916_offs[] = {
	[TMAC_CDTR]		= 0x0c8,
	[TMAC_ODTR]		= 0x0cc,
	[TMAC_ATCR]		= 0x00c,
	[TMAC_TRCR0]		= 0x010,
	[TMAC_ICR0]		= 0x014,
	[TMAC_ICR1]		= 0x018,
	[TMAC_CTCR0]		= 0x114,
	[TMAC_TFCR0]		= 0x0e4,
	[MDP_BNRCFR0]		= 0x090,
	[MDP_BNRCFR1]		= 0x094,
	[ARB_DRNGR0]		= 0x1e0,
	[ARB_SCR]		= 0x000,
	[RMAC_MIB_AIRTIME14]	= 0x0398,
	[AGG_AWSCR0]		= 0x030,
	[AGG_PCR0]		= 0x040,
	[AGG_ACR0]		= 0x054,
	[AGG_ACR4]		= 0x05c,
	[AGG_MRCR]		= 0x068,
	[AGG_ATCR1]		= 0x1a8,
	[AGG_ATCR3]		= 0x080,
	[LPON_UTTR0]		= 0x360,
	[LPON_UTTR1]		= 0x364,
	[LPON_FRCR]		= 0x37c,
	[MIB_SDR3]		= 0x698,
	[MIB_SDR4]		= 0x788,
	[MIB_SDR5]		= 0x780,
	[MIB_SDR7]		= 0x5a8,
	[MIB_SDR8]		= 0x78c,
	[MIB_SDR9]		= 0x024,
	[MIB_SDR10]		= 0x76c,
	[MIB_SDR11]		= 0x790,
	[MIB_SDR12]		= 0x558,
	[MIB_SDR13]		= 0x560,
	[MIB_SDR14]		= 0x564,
	[MIB_SDR15]		= 0x568,
	[MIB_SDR16]		= 0x7fc,
	[MIB_SDR17]		= 0x800,
	[MIB_SDR18]		= 0x030,
	[MIB_SDR19]		= 0x5ac,
	[MIB_SDR20]		= 0x5b0,
	[MIB_SDR21]		= 0x5b4,
	[MIB_SDR22]		= 0x770,
	[MIB_SDR23]		= 0x774,
	[MIB_SDR24]		= 0x778,
	[MIB_SDR25]		= 0x77c,
	[MIB_SDR27]		= 0x080,
	[MIB_SDR28]		= 0x084,
	[MIB_SDR29]		= 0x650,
	[MIB_SDRVEC]		= 0x5a8,
	[MIB_SDR31]		= 0x55c,
	[MIB_SDR32]		= 0x7a8,
	[MIB_SDRMUBF]		= 0x7ac,
	[MIB_DR8]		= 0x56c,
	[MIB_DR9]		= 0x570,
	[MIB_DR11]		= 0x574,
	[MIB_MB_SDR0]		= 0x688,
	[MIB_MB_SDR1]		= 0x690,
	[TX_AGG_CNT]		= 0x7dc,
	[TX_AGG_CNT2]		= 0x7ec,
	[MIB_ARNG]		= 0x0b0,
	[WTBLON_TOP_WDUCR]	= 0x200,
	[WTBL_UPDATE]		= 0x230,
	[PLE_FL_Q_EMPTY]	= 0x360,
	[PLE_FL_Q_CTRL]		= 0x3e0,
	[PLE_AC_QEMPTY]		= 0x600,
	[PLE_FREEPG_CNT]	= 0x380,
	[PLE_FREEPG_HEAD_TAIL]	= 0x384,
	[PLE_PG_HIF_GROUP]	= 0x00c,
	[PLE_HIF_PG_INFO]	= 0x388,
	[AC_OFFSET]		= 0x080,
	[ETBF_PAR_RPT0]		= 0x100,
};

static const struct mt76_connac_reg_map mt7915_reg_map[] = {
	{ 0x00400000, 0x80000, 0x10000 }, /* WF_MCU_SYSRAM */
	{ 0x00410000, 0x90000, 0x10000 }, /* WF_MCU_SYSRAM (configure regs) */
	{ 0x40000000, 0x70000, 0x10000 }, /* WF_UMAC_SYSRAM */
	{ 0x54000000, 0x02000, 0x01000 }, /* WFDMA PCIE0 MCU DMA0 */
	{ 0x55000000, 0x03000, 0x01000 }, /* WFDMA PCIE0 MCU DMA1 */
	{ 0x58000000, 0x06000, 0x01000 }, /* WFDMA PCIE1 MCU DMA0 (MEM_DMA) */
	{ 0x59000000, 0x07000, 0x01000 }, /* WFDMA PCIE1 MCU DMA1 */
	{ 0x7c000000, 0xf0000, 0x10000 }, /* CONN_INFRA */
	{ 0x7c020000, 0xd0000, 0x10000 }, /* CONN_INFRA, WFDMA */
	{ 0x80020000, 0xb0000, 0x10000 }, /* WF_TOP_MISC_OFF */
	{ 0x81020000, 0xc0000, 0x10000 }, /* WF_TOP_MISC_ON */
	{ 0x820c0000, 0x08000, 0x04000 }, /* WF_UMAC_TOP (PLE) */
	{ 0x820c8000, 0x0c000, 0x02000 }, /* WF_UMAC_TOP (PSE) */
	{ 0x820cc000, 0x0e000, 0x02000 }, /* WF_UMAC_TOP (PP) */
	{ 0x820ce000, 0x21c00, 0x00200 }, /* WF_LMAC_TOP (WF_SEC) */
	{ 0x820cf000, 0x22000, 0x01000 }, /* WF_LMAC_TOP (WF_PF) */
	{ 0x820d0000, 0x30000, 0x10000 }, /* WF_LMAC_TOP (WF_WTBLON) */
	{ 0x820e0000, 0x20000, 0x00400 }, /* WF_LMAC_TOP BN0 (WF_CFG) */
	{ 0x820e1000, 0x20400, 0x00200 }, /* WF_LMAC_TOP BN0 (WF_TRB) */
	{ 0x820e2000, 0x20800, 0x00400 }, /* WF_LMAC_TOP BN0 (WF_AGG) */
	{ 0x820e3000, 0x20c00, 0x00400 }, /* WF_LMAC_TOP BN0 (WF_ARB) */
	{ 0x820e4000, 0x21000, 0x00400 }, /* WF_LMAC_TOP BN0 (WF_TMAC) */
	{ 0x820e5000, 0x21400, 0x00800 }, /* WF_LMAC_TOP BN0 (WF_RMAC) */
	{ 0x820e7000, 0x21e00, 0x00200 }, /* WF_LMAC_TOP BN0 (WF_DMA) */
	{ 0x820e9000, 0x23400, 0x00200 }, /* WF_LMAC_TOP BN0 (WF_WTBLOFF) */
	{ 0x820ea000, 0x24000, 0x00200 }, /* WF_LMAC_TOP BN0 (WF_ETBF) */
	{ 0x820eb000, 0x24200, 0x00400 }, /* WF_LMAC_TOP BN0 (WF_LPON) */
	{ 0x820ec000, 0x24600, 0x00200 }, /* WF_LMAC_TOP BN0 (WF_INT) */
	{ 0x820ed000, 0x24800, 0x00800 }, /* WF_LMAC_TOP BN0 (WF_MIB) */
	{ 0x820f0000, 0xa0000, 0x00400 }, /* WF_LMAC_TOP BN1 (WF_CFG) */
	{ 0x820f1000, 0xa0600, 0x00200 }, /* WF_LMAC_TOP BN1 (WF_TRB) */
	{ 0x820f2000, 0xa0800, 0x00400 }, /* WF_LMAC_TOP BN1 (WF_AGG) */
	{ 0x820f3000, 0xa0c00, 0x00400 }, /* WF_LMAC_TOP BN1 (WF_ARB) */
	{ 0x820f4000, 0xa1000, 0x00400 }, /* WF_LMAC_TOP BN1 (WF_TMAC) */
	{ 0x820f5000, 0xa1400, 0x00800 }, /* WF_LMAC_TOP BN1 (WF_RMAC) */
	{ 0x820f7000, 0xa1e00, 0x00200 }, /* WF_LMAC_TOP BN1 (WF_DMA) */
	{ 0x820f9000, 0xa3400, 0x00200 }, /* WF_LMAC_TOP BN1 (WF_WTBLOFF) */
	{ 0x820fa000, 0xa4000, 0x00200 }, /* WF_LMAC_TOP BN1 (WF_ETBF) */
	{ 0x820fb000, 0xa4200, 0x00400 }, /* WF_LMAC_TOP BN1 (WF_LPON) */
	{ 0x820fc000, 0xa4600, 0x00200 }, /* WF_LMAC_TOP BN1 (WF_INT) */
	{ 0x820fd000, 0xa4800, 0x00800 }, /* WF_LMAC_TOP BN1 (WF_MIB) */
	{ 0x0, 0x0, 0x0 }, /* imply end of search */
};

static const struct mt76_connac_reg_map mt7916_reg_map[] = {
	{ 0x54000000, 0x02000, 0x01000 }, /* WFDMA_0 (PCIE0 MCU DMA0) */
	{ 0x55000000, 0x03000, 0x01000 }, /* WFDMA_1 (PCIE0 MCU DMA1) */
	{ 0x56000000, 0x04000, 0x01000 }, /* WFDMA_2 (Reserved) */
	{ 0x57000000, 0x05000, 0x01000 }, /* WFDMA_3 (MCU wrap CR) */
	{ 0x58000000, 0x06000, 0x01000 }, /* WFDMA_4 (PCIE1 MCU DMA0) */
	{ 0x59000000, 0x07000, 0x01000 }, /* WFDMA_5 (PCIE1 MCU DMA1) */
	{ 0x820c0000, 0x08000, 0x04000 }, /* WF_UMAC_TOP (PLE) */
	{ 0x820c8000, 0x0c000, 0x02000 }, /* WF_UMAC_TOP (PSE) */
	{ 0x820cc000, 0x0e000, 0x02000 }, /* WF_UMAC_TOP (PP) */
	{ 0x820e0000, 0x20000, 0x00400 }, /* WF_LMAC_TOP BN0 (WF_CFG) */
	{ 0x820e1000, 0x20400, 0x00200 }, /* WF_LMAC_TOP BN0 (WF_TRB) */
	{ 0x820e2000, 0x20800, 0x00400 }, /* WF_LMAC_TOP BN0 (WF_AGG) */
	{ 0x820e3000, 0x20c00, 0x00400 }, /* WF_LMAC_TOP BN0 (WF_ARB) */
	{ 0x820e4000, 0x21000, 0x00400 }, /* WF_LMAC_TOP BN0 (WF_TMAC) */
	{ 0x820e5000, 0x21400, 0x00800 }, /* WF_LMAC_TOP BN0 (WF_RMAC) */
	{ 0x820ce000, 0x21c00, 0x00200 }, /* WF_LMAC_TOP (WF_SEC) */
	{ 0x820e7000, 0x21e00, 0x00200 }, /* WF_LMAC_TOP BN0 (WF_DMA) */
	{ 0x820cf000, 0x22000, 0x01000 }, /* WF_LMAC_TOP (WF_PF) */
	{ 0x820e9000, 0x23400, 0x00200 }, /* WF_LMAC_TOP BN0 (WF_WTBLOFF) */
	{ 0x820ea000, 0x24000, 0x00200 }, /* WF_LMAC_TOP BN0 (WF_ETBF) */
	{ 0x820eb000, 0x24200, 0x00400 }, /* WF_LMAC_TOP BN0 (WF_LPON) */
	{ 0x820ec000, 0x24600, 0x00200 }, /* WF_LMAC_TOP BN0 (WF_INT) */
	{ 0x820ed000, 0x24800, 0x00800 }, /* WF_LMAC_TOP BN0 (WF_MIB) */
	{ 0x820ca000, 0x26000, 0x02000 }, /* WF_LMAC_TOP BN0 (WF_MUCOP) */
	{ 0x820d0000, 0x30000, 0x10000 }, /* WF_LMAC_TOP (WF_WTBLON) */
	{ 0x00400000, 0x80000, 0x10000 }, /* WF_MCU_SYSRAM */
	{ 0x00410000, 0x90000, 0x10000 }, /* WF_MCU_SYSRAM (configure cr) */
	{ 0x820f0000, 0xa0000, 0x00400 }, /* WF_LMAC_TOP BN1 (WF_CFG) */
	{ 0x820f1000, 0xa0600, 0x00200 }, /* WF_LMAC_TOP BN1 (WF_TRB) */
	{ 0x820f2000, 0xa0800, 0x00400 }, /* WF_LMAC_TOP BN1 (WF_AGG) */
	{ 0x820f3000, 0xa0c00, 0x00400 }, /* WF_LMAC_TOP BN1 (WF_ARB) */
	{ 0x820f4000, 0xa1000, 0x00400 }, /* WF_LMAC_TOP BN1 (WF_TMAC) */
	{ 0x820f5000, 0xa1400, 0x00800 }, /* WF_LMAC_TOP BN1 (WF_RMAC) */
	{ 0x820f7000, 0xa1e00, 0x00200 }, /* WF_LMAC_TOP BN1 (WF_DMA) */
	{ 0x820f9000, 0xa3400, 0x00200 }, /* WF_LMAC_TOP BN1 (WF_WTBLOFF) */
	{ 0x820fa000, 0xa4000, 0x00200 }, /* WF_LMAC_TOP BN1 (WF_ETBF) */
	{ 0x820fb000, 0xa4200, 0x00400 }, /* WF_LMAC_TOP BN1 (WF_LPON) */
	{ 0x820fc000, 0xa4600, 0x00200 }, /* WF_LMAC_TOP BN1 (WF_INT) */
	{ 0x820fd000, 0xa4800, 0x00800 }, /* WF_LMAC_TOP BN1 (WF_MIB) */
	{ 0x820c4000, 0xa8000, 0x01000 }, /* WF_LMAC_TOP (WF_UWTBL ) */
	{ 0x820b0000, 0xae000, 0x01000 }, /* [APB2] WFSYS_ON */
	{ 0x80020000, 0xb0000, 0x10000 }, /* WF_TOP_MISC_OFF */
	{ 0x81020000, 0xc0000, 0x10000 }, /* WF_TOP_MISC_ON */
	{ 0x0, 0x0, 0x0 }, /* imply end of search */
};

static const struct mt76_connac_reg_map mt7986_reg_map[] = {
	{ 0x54000000, 0x402000, 0x01000 }, /* WFDMA_0 (PCIE0 MCU DMA0) */
	{ 0x55000000, 0x403000, 0x01000 }, /* WFDMA_1 (PCIE0 MCU DMA1) */
	{ 0x56000000, 0x404000, 0x01000 }, /* WFDMA_2 (Reserved) */
	{ 0x57000000, 0x405000, 0x01000 }, /* WFDMA_3 (MCU wrap CR) */
	{ 0x58000000, 0x406000, 0x01000 }, /* WFDMA_4 (PCIE1 MCU DMA0) */
	{ 0x59000000, 0x407000, 0x01000 }, /* WFDMA_5 (PCIE1 MCU DMA1) */
	{ 0x820c0000, 0x408000, 0x04000 }, /* WF_UMAC_TOP (PLE) */
	{ 0x820c8000, 0x40c000, 0x02000 }, /* WF_UMAC_TOP (PSE) */
	{ 0x820cc000, 0x40e000, 0x02000 }, /* WF_UMAC_TOP (PP) */
	{ 0x820e0000, 0x420000, 0x00400 }, /* WF_LMAC_TOP BN0 (WF_CFG) */
	{ 0x820e1000, 0x420400, 0x00200 }, /* WF_LMAC_TOP BN0 (WF_TRB) */
	{ 0x820e2000, 0x420800, 0x00400 }, /* WF_LMAC_TOP BN0 (WF_AGG) */
	{ 0x820e3000, 0x420c00, 0x00400 }, /* WF_LMAC_TOP BN0 (WF_ARB) */
	{ 0x820e4000, 0x421000, 0x00400 }, /* WF_LMAC_TOP BN0 (WF_TMAC) */
	{ 0x820e5000, 0x421400, 0x00800 }, /* WF_LMAC_TOP BN0 (WF_RMAC) */
	{ 0x820ce000, 0x421c00, 0x00200 }, /* WF_LMAC_TOP (WF_SEC) */
	{ 0x820e7000, 0x421e00, 0x00200 }, /* WF_LMAC_TOP BN0 (WF_DMA) */
	{ 0x820cf000, 0x422000, 0x01000 }, /* WF_LMAC_TOP (WF_PF) */
	{ 0x820e9000, 0x423400, 0x00200 }, /* WF_LMAC_TOP BN0 (WF_WTBLOFF) */
	{ 0x820ea000, 0x424000, 0x00200 }, /* WF_LMAC_TOP BN0 (WF_ETBF) */
	{ 0x820eb000, 0x424200, 0x00400 }, /* WF_LMAC_TOP BN0 (WF_LPON) */
	{ 0x820ec000, 0x424600, 0x00200 }, /* WF_LMAC_TOP BN0 (WF_INT) */
	{ 0x820ed000, 0x424800, 0x00800 }, /* WF_LMAC_TOP BN0 (WF_MIB) */
	{ 0x820ca000, 0x426000, 0x02000 }, /* WF_LMAC_TOP BN0 (WF_MUCOP) */
	{ 0x820d0000, 0x430000, 0x10000 }, /* WF_LMAC_TOP (WF_WTBLON) */
	{ 0x00400000, 0x480000, 0x10000 }, /* WF_MCU_SYSRAM */
	{ 0x00410000, 0x490000, 0x10000 }, /* WF_MCU_SYSRAM */
	{ 0x820f0000, 0x4a0000, 0x00400 }, /* WF_LMAC_TOP BN1 (WF_CFG) */
	{ 0x820f1000, 0x4a0600, 0x00200 }, /* WF_LMAC_TOP BN1 (WF_TRB) */
	{ 0x820f2000, 0x4a0800, 0x00400 }, /* WF_LMAC_TOP BN1 (WF_AGG) */
	{ 0x820f3000, 0x4a0c00, 0x00400 }, /* WF_LMAC_TOP BN1 (WF_ARB) */
	{ 0x820f4000, 0x4a1000, 0x00400 }, /* WF_LMAC_TOP BN1 (WF_TMAC) */
	{ 0x820f5000, 0x4a1400, 0x00800 }, /* WF_LMAC_TOP BN1 (WF_RMAC) */
	{ 0x820f7000, 0x4a1e00, 0x00200 }, /* WF_LMAC_TOP BN1 (WF_DMA) */
	{ 0x820f9000, 0x4a3400, 0x00200 }, /* WF_LMAC_TOP BN1 (WF_WTBLOFF) */
	{ 0x820fa000, 0x4a4000, 0x00200 }, /* WF_LMAC_TOP BN1 (WF_ETBF) */
	{ 0x820fb000, 0x4a4200, 0x00400 }, /* WF_LMAC_TOP BN1 (WF_LPON) */
	{ 0x820fc000, 0x4a4600, 0x00200 }, /* WF_LMAC_TOP BN1 (WF_INT) */
	{ 0x820fd000, 0x4a4800, 0x00800 }, /* WF_LMAC_TOP BN1 (WF_MIB) */
	{ 0x820c4000, 0x4a8000, 0x01000 }, /* WF_LMAC_TOP (WF_UWTBL ) */
	{ 0x820b0000, 0x4ae000, 0x01000 }, /* [APB2] WFSYS_ON */
	{ 0x80020000, 0x4b0000, 0x10000 }, /* WF_TOP_MISC_OFF */
	{ 0x81020000, 0x4c0000, 0x10000 }, /* WF_TOP_MISC_ON */
	{ 0x89000000, 0x4d0000, 0x01000 }, /* WF_MCU_CFG_ON */
	{ 0x89010000, 0x4d1000, 0x01000 }, /* WF_MCU_CIRQ */
	{ 0x89020000, 0x4d2000, 0x01000 }, /* WF_MCU_GPT */
	{ 0x89030000, 0x4d3000, 0x01000 }, /* WF_MCU_WDT */
	{ 0x80010000, 0x4d4000, 0x01000 }, /* WF_AXIDMA */
	{ 0x0, 0x0, 0x0 }, /* imply end of search */
};

static u32 mt7915_reg_map_l1(struct mt7915_dev *dev, u32 addr)
{
	u32 offset = FIELD_GET(MT_HIF_REMAP_L1_OFFSET, addr);
	u32 base = FIELD_GET(MT_HIF_REMAP_L1_BASE, addr);
	u32 l1_remap;

	if (is_mt7986(&dev->mt76))
		return MT_CONN_INFRA_OFFSET(addr);

	l1_remap = is_mt7915(&dev->mt76) ?
		   MT_HIF_REMAP_L1 : MT_HIF_REMAP_L1_MT7916;

	dev->bus_ops->rmw(&dev->mt76, l1_remap,
			  MT_HIF_REMAP_L1_MASK,
			  FIELD_PREP(MT_HIF_REMAP_L1_MASK, base));
	/* use read to push write */
	dev->bus_ops->rr(&dev->mt76, l1_remap);

	return MT_HIF_REMAP_BASE_L1 + offset;
}

static u32 mt7915_reg_map_l2(struct mt7915_dev *dev, u32 addr)
{
	u32 offset, base;

	if (is_mt7915(&dev->mt76)) {
		offset = FIELD_GET(MT_HIF_REMAP_L2_OFFSET, addr);
		base = FIELD_GET(MT_HIF_REMAP_L2_BASE, addr);

		dev->bus_ops->rmw(&dev->mt76, MT_HIF_REMAP_L2,
				  MT_HIF_REMAP_L2_MASK,
				  FIELD_PREP(MT_HIF_REMAP_L2_MASK, base));

		/* use read to push write */
		dev->bus_ops->rr(&dev->mt76, MT_HIF_REMAP_L2);
	} else {
		u32 ofs = is_mt7986(&dev->mt76) ? 0x400000 : 0;

		offset = FIELD_GET(MT_HIF_REMAP_L2_OFFSET_MT7916, addr);
		base = FIELD_GET(MT_HIF_REMAP_L2_BASE_MT7916, addr);

		dev->bus_ops->rmw(&dev->mt76, MT_HIF_REMAP_L2_MT7916 + ofs,
				  MT_HIF_REMAP_L2_MASK_MT7916,
				  FIELD_PREP(MT_HIF_REMAP_L2_MASK_MT7916, base));

		/* use read to push write */
		dev->bus_ops->rr(&dev->mt76, MT_HIF_REMAP_L2_MT7916 + ofs);

		offset += (MT_HIF_REMAP_BASE_L2_MT7916 + ofs);
	}

	return offset;
}

static u32 __mt7915_reg_addr(struct mt7915_dev *dev, u32 addr)
{
	int i;

	if (addr < 0x100000)
		return addr;

	if (!dev->reg.map) {
		dev_err(dev->mt76.dev, "err: reg_map is null\n");
		return addr;
	}

	for (i = 0; i < dev->reg.map_size; i++) {
		u32 ofs;

		if (addr < dev->reg.map[i].phys)
			continue;

		ofs = addr - dev->reg.map[i].phys;
		if (ofs > dev->reg.map[i].size)
			continue;

		return dev->reg.map[i].maps + ofs;
	}

	if ((addr >= MT_INFRA_BASE && addr < MT_WFSYS0_PHY_START) ||
	    (addr >= MT_WFSYS0_PHY_START && addr < MT_WFSYS1_PHY_START) ||
	    (addr >= MT_WFSYS1_PHY_START && addr <= MT_WFSYS1_PHY_END))
		return mt7915_reg_map_l1(dev, addr);

	if (dev_is_pci(dev->mt76.dev) &&
	    ((addr >= MT_CBTOP1_PHY_START && addr <= MT_CBTOP1_PHY_END) ||
	     (addr >= MT_CBTOP2_PHY_START && addr <= MT_CBTOP2_PHY_END)))
		return mt7915_reg_map_l1(dev, addr);

	/* CONN_INFRA: covert to phyiscal addr and use layer 1 remap */
	if (addr >= MT_INFRA_MCU_START && addr <= MT_INFRA_MCU_END) {
		addr = addr - MT_INFRA_MCU_START + MT_INFRA_BASE;
		return mt7915_reg_map_l1(dev, addr);
	}

	return mt7915_reg_map_l2(dev, addr);
}

static u32 mt7915_rr(struct mt76_dev *mdev, u32 offset)
{
	struct mt7915_dev *dev = container_of(mdev, struct mt7915_dev, mt76);
	u32 addr = __mt7915_reg_addr(dev, offset);

	return dev->bus_ops->rr(mdev, addr);
}

static void mt7915_wr(struct mt76_dev *mdev, u32 offset, u32 val)
{
	struct mt7915_dev *dev = container_of(mdev, struct mt7915_dev, mt76);
	u32 addr = __mt7915_reg_addr(dev, offset);

	dev->bus_ops->wr(mdev, addr, val);
}

static u32 mt7915_rmw(struct mt76_dev *mdev, u32 offset, u32 mask, u32 val)
{
	struct mt7915_dev *dev = container_of(mdev, struct mt7915_dev, mt76);
	u32 addr = __mt7915_reg_addr(dev, offset);

	return dev->bus_ops->rmw(mdev, addr, mask, val);
}

static int mt7915_mmio_init(struct mt76_dev *mdev,
			    void __iomem *mem_base,
			    u32 device_id)
{
	struct mt76_bus_ops *bus_ops;
	struct mt7915_dev *dev;

	dev = container_of(mdev, struct mt7915_dev, mt76);
	mt76_mmio_init(&dev->mt76, mem_base);

	switch (device_id) {
	case 0x7915:
		dev->reg.reg_rev = mt7915_reg;
		dev->reg.offs_rev = mt7915_offs;
		dev->reg.map = mt7915_reg_map;
		dev->reg.map_size = ARRAY_SIZE(mt7915_reg_map);
		break;
	case 0x7906:
		dev->reg.reg_rev = mt7916_reg;
		dev->reg.offs_rev = mt7916_offs;
		dev->reg.map = mt7916_reg_map;
		dev->reg.map_size = ARRAY_SIZE(mt7916_reg_map);
		break;
	case 0x7986:
		dev->reg.reg_rev = mt7986_reg;
		dev->reg.offs_rev = mt7916_offs;
		dev->reg.map = mt7986_reg_map;
		dev->reg.map_size = ARRAY_SIZE(mt7986_reg_map);
		break;
	default:
		return -EINVAL;
	}

	dev->bus_ops = dev->mt76.bus;
	bus_ops = devm_kmemdup(dev->mt76.dev, dev->bus_ops, sizeof(*bus_ops),
			       GFP_KERNEL);
	if (!bus_ops)
		return -ENOMEM;

	bus_ops->rr = mt7915_rr;
	bus_ops->wr = mt7915_wr;
	bus_ops->rmw = mt7915_rmw;
	dev->mt76.bus = bus_ops;

	mdev->rev = (device_id << 16) |
		    (mt76_rr(dev, MT_HW_REV) & 0xff);
	dev_dbg(mdev->dev, "ASIC revision: %04x\n", mdev->rev);

	return 0;
}

void mt7915_dual_hif_set_irq_mask(struct mt7915_dev *dev,
				  bool write_reg,
				  u32 clear, u32 set)
{
	struct mt76_dev *mdev = &dev->mt76;
	unsigned long flags;

	spin_lock_irqsave(&mdev->mmio.irq_lock, flags);

	mdev->mmio.irqmask &= ~clear;
	mdev->mmio.irqmask |= set;

	if (write_reg) {
		mt76_wr(dev, MT_INT_MASK_CSR, mdev->mmio.irqmask);
		mt76_wr(dev, MT_INT1_MASK_CSR, mdev->mmio.irqmask);
	}

	spin_unlock_irqrestore(&mdev->mmio.irq_lock, flags);
}

static void mt7915_rx_poll_complete(struct mt76_dev *mdev,
				    enum mt76_rxq_id q)
{
	struct mt7915_dev *dev = container_of(mdev, struct mt7915_dev, mt76);

	mt7915_irq_enable(dev, MT_INT_RX(q));
}

/* TODO: support 2/4/6/8 MSI-X vectors */
static void mt7915_irq_tasklet(struct tasklet_struct *t)
{
	struct mt7915_dev *dev = from_tasklet(dev, t, irq_tasklet);
	struct mtk_wed_device *wed = &dev->mt76.mmio.wed;
	u32 intr, intr1, mask;

	if (mtk_wed_device_active(wed)) {
		mtk_wed_device_irq_set_mask(wed, 0);
		intr = mtk_wed_device_irq_get(wed, dev->mt76.mmio.irqmask);
	} else {
		mt76_wr(dev, MT_INT_MASK_CSR, 0);
		if (dev->hif2)
			mt76_wr(dev, MT_INT1_MASK_CSR, 0);

		intr = mt76_rr(dev, MT_INT_SOURCE_CSR);
		intr &= dev->mt76.mmio.irqmask;
		mt76_wr(dev, MT_INT_SOURCE_CSR, intr);
	}

	if (dev->hif2) {
		intr1 = mt76_rr(dev, MT_INT1_SOURCE_CSR);
		intr1 &= dev->mt76.mmio.irqmask;
		mt76_wr(dev, MT_INT1_SOURCE_CSR, intr1);

		intr |= intr1;
	}

	trace_dev_irq(&dev->mt76, intr, dev->mt76.mmio.irqmask);

	mask = intr & MT_INT_RX_DONE_ALL;
	if (intr & MT_INT_TX_DONE_MCU)
		mask |= MT_INT_TX_DONE_MCU;

	mt7915_irq_disable(dev, mask);

	if (intr & MT_INT_TX_DONE_MCU)
		napi_schedule(&dev->mt76.tx_napi);

	if (intr & MT_INT_RX(MT_RXQ_MAIN))
		napi_schedule(&dev->mt76.napi[MT_RXQ_MAIN]);

	if (intr & MT_INT_RX(MT_RXQ_BAND1))
		napi_schedule(&dev->mt76.napi[MT_RXQ_BAND1]);

	if (intr & MT_INT_RX(MT_RXQ_MCU))
		napi_schedule(&dev->mt76.napi[MT_RXQ_MCU]);

	if (intr & MT_INT_RX(MT_RXQ_MCU_WA))
		napi_schedule(&dev->mt76.napi[MT_RXQ_MCU_WA]);

	if (!is_mt7915(&dev->mt76) &&
	    (intr & MT_INT_RX(MT_RXQ_MAIN_WA)))
		napi_schedule(&dev->mt76.napi[MT_RXQ_MAIN_WA]);

	if (intr & MT_INT_RX(MT_RXQ_BAND1_WA))
		napi_schedule(&dev->mt76.napi[MT_RXQ_BAND1_WA]);

	if (intr & MT_INT_MCU_CMD) {
		u32 val = mt76_rr(dev, MT_MCU_CMD);

		mt76_wr(dev, MT_MCU_CMD, val);
		if (val & MT_MCU_CMD_ERROR_MASK) {
			dev->reset_state = val;
			queue_work(dev->mt76.wq, &dev->reset_work);
			wake_up(&dev->reset_wait);
		}
	}
}

irqreturn_t mt7915_irq_handler(int irq, void *dev_instance)
{
	struct mt7915_dev *dev = dev_instance;
	struct mtk_wed_device *wed = &dev->mt76.mmio.wed;

	if (mtk_wed_device_active(wed)) {
		mtk_wed_device_irq_set_mask(wed, 0);
	} else {
		mt76_wr(dev, MT_INT_MASK_CSR, 0);
		if (dev->hif2)
			mt76_wr(dev, MT_INT1_MASK_CSR, 0);
	}

	if (!test_bit(MT76_STATE_INITIALIZED, &dev->mphy.state))
		return IRQ_NONE;

	tasklet_schedule(&dev->irq_tasklet);

	return IRQ_HANDLED;
}

struct mt7915_dev *mt7915_mmio_probe(struct device *pdev,
				     void __iomem *mem_base, u32 device_id)
{
	static const struct mt76_driver_ops drv_ops = {
		/* txwi_size = txd size + txp size */
		.txwi_size = MT_TXD_SIZE + sizeof(struct mt76_connac_fw_txp),
		.drv_flags = MT_DRV_TXWI_NO_FREE | MT_DRV_HW_MGMT_TXQ,
		.survey_flags = SURVEY_INFO_TIME_TX |
				SURVEY_INFO_TIME_RX |
				SURVEY_INFO_TIME_BSS_RX,
		.token_size = MT7915_TOKEN_SIZE,
		.tx_prepare_skb = mt7915_tx_prepare_skb,
		.tx_complete_skb = mt76_connac_tx_complete_skb,
		.rx_skb = mt7915_queue_rx_skb,
		.rx_check = mt7915_rx_check,
		.rx_poll_complete = mt7915_rx_poll_complete,
		.sta_ps = mt7915_sta_ps,
		.sta_add = mt7915_mac_sta_add,
		.sta_remove = mt7915_mac_sta_remove,
		.update_survey = mt7915_update_channel,
	};
	struct mt7915_dev *dev;
	struct mt76_dev *mdev;
	int ret;

	mdev = mt76_alloc_device(pdev, sizeof(*dev), &mt7915_ops, &drv_ops);
	if (!mdev)
		return ERR_PTR(-ENOMEM);

	dev = container_of(mdev, struct mt7915_dev, mt76);

	ret = mt7915_mmio_init(mdev, mem_base, device_id);
	if (ret)
		goto error;

	tasklet_setup(&dev->irq_tasklet, mt7915_irq_tasklet);

	return dev;

error:
	mt76_free_device(&dev->mt76);

	return ERR_PTR(ret);
}

static int __init mt7915_init(void)
{
	int ret;

	ret = pci_register_driver(&mt7915_hif_driver);
	if (ret)
		return ret;

	ret = pci_register_driver(&mt7915_pci_driver);
	if (ret)
		goto error_pci;

	if (IS_ENABLED(CONFIG_MT7986_WMAC)) {
		ret = platform_driver_register(&mt7986_wmac_driver);
		if (ret)
			goto error_wmac;
	}

	return 0;

error_wmac:
	pci_unregister_driver(&mt7915_pci_driver);
error_pci:
	pci_unregister_driver(&mt7915_hif_driver);

	return ret;
}

static void __exit mt7915_exit(void)
{
	if (IS_ENABLED(CONFIG_MT7986_WMAC))
		platform_driver_unregister(&mt7986_wmac_driver);

	pci_unregister_driver(&mt7915_pci_driver);
	pci_unregister_driver(&mt7915_hif_driver);
}

module_init(mt7915_init);
module_exit(mt7915_exit);
MODULE_LICENSE("Dual BSD/GPL");
