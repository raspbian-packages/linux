/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Intel Corporation */

#ifndef _IDPF_LAN_PF_REGS_H_
#define _IDPF_LAN_PF_REGS_H_

/* Receive queues */
#define PF_QRX_BASE			0x00000000
#define PF_QRX_TAIL(_QRX)		(PF_QRX_BASE + (((_QRX) * 0x1000)))
#define PF_QRX_BUFFQ_BASE		0x03000000
#define PF_QRX_BUFFQ_TAIL(_QRX)		(PF_QRX_BUFFQ_BASE + (((_QRX) * 0x1000)))

/* Transmit queues */
#define PF_QTX_BASE			0x05000000
#define PF_QTX_COMM_DBELL(_DBQM)	(PF_QTX_BASE + ((_DBQM) * 0x1000))

/* Control(PF Mailbox) Queue */
#define PF_FW_BASE			0x08400000

#define PF_FW_ARQBAL			(PF_FW_BASE)
#define PF_FW_ARQBAH			(PF_FW_BASE + 0x4)
#define PF_FW_ARQLEN			(PF_FW_BASE + 0x8)
#define PF_FW_ARQLEN_ARQLEN_S		0
#define PF_FW_ARQLEN_ARQLEN_M		GENMASK(12, 0)
#define PF_FW_ARQLEN_ARQVFE_S		28
#define PF_FW_ARQLEN_ARQVFE_M		BIT(PF_FW_ARQLEN_ARQVFE_S)
#define PF_FW_ARQLEN_ARQOVFL_S		29
#define PF_FW_ARQLEN_ARQOVFL_M		BIT(PF_FW_ARQLEN_ARQOVFL_S)
#define PF_FW_ARQLEN_ARQCRIT_S		30
#define PF_FW_ARQLEN_ARQCRIT_M		BIT(PF_FW_ARQLEN_ARQCRIT_S)
#define PF_FW_ARQLEN_ARQENABLE_S	31
#define PF_FW_ARQLEN_ARQENABLE_M	BIT(PF_FW_ARQLEN_ARQENABLE_S)
#define PF_FW_ARQH			(PF_FW_BASE + 0xC)
#define PF_FW_ARQH_ARQH_S		0
#define PF_FW_ARQH_ARQH_M		GENMASK(12, 0)
#define PF_FW_ARQT			(PF_FW_BASE + 0x10)

#define PF_FW_ATQBAL			(PF_FW_BASE + 0x14)
#define PF_FW_ATQBAH			(PF_FW_BASE + 0x18)
#define PF_FW_ATQLEN			(PF_FW_BASE + 0x1C)
#define PF_FW_ATQLEN_ATQLEN_S		0
#define PF_FW_ATQLEN_ATQLEN_M		GENMASK(9, 0)
#define PF_FW_ATQLEN_ATQVFE_S		28
#define PF_FW_ATQLEN_ATQVFE_M		BIT(PF_FW_ATQLEN_ATQVFE_S)
#define PF_FW_ATQLEN_ATQOVFL_S		29
#define PF_FW_ATQLEN_ATQOVFL_M		BIT(PF_FW_ATQLEN_ATQOVFL_S)
#define PF_FW_ATQLEN_ATQCRIT_S		30
#define PF_FW_ATQLEN_ATQCRIT_M		BIT(PF_FW_ATQLEN_ATQCRIT_S)
#define PF_FW_ATQLEN_ATQENABLE_S	31
#define PF_FW_ATQLEN_ATQENABLE_M	BIT(PF_FW_ATQLEN_ATQENABLE_S)
#define PF_FW_ATQH			(PF_FW_BASE + 0x20)
#define PF_FW_ATQH_ATQH_S		0
#define PF_FW_ATQH_ATQH_M		GENMASK(9, 0)
#define PF_FW_ATQT			(PF_FW_BASE + 0x24)

/* Interrupts */
#define PF_GLINT_BASE			0x08900000
#define PF_GLINT_DYN_CTL(_INT)		(PF_GLINT_BASE + ((_INT) * 0x1000))
#define PF_GLINT_DYN_CTL_INTENA_S	0
#define PF_GLINT_DYN_CTL_INTENA_M	BIT(PF_GLINT_DYN_CTL_INTENA_S)
#define PF_GLINT_DYN_CTL_CLEARPBA_S	1
#define PF_GLINT_DYN_CTL_CLEARPBA_M	BIT(PF_GLINT_DYN_CTL_CLEARPBA_S)
#define PF_GLINT_DYN_CTL_SWINT_TRIG_S	2
#define PF_GLINT_DYN_CTL_SWINT_TRIG_M	BIT(PF_GLINT_DYN_CTL_SWINT_TRIG_S)
#define PF_GLINT_DYN_CTL_ITR_INDX_S	3
#define PF_GLINT_DYN_CTL_ITR_INDX_M	GENMASK(4, 3)
#define PF_GLINT_DYN_CTL_INTERVAL_S	5
#define PF_GLINT_DYN_CTL_INTERVAL_M	BIT(PF_GLINT_DYN_CTL_INTERVAL_S)
#define PF_GLINT_DYN_CTL_SW_ITR_INDX_ENA_S	24
#define PF_GLINT_DYN_CTL_SW_ITR_INDX_ENA_M BIT(PF_GLINT_DYN_CTL_SW_ITR_INDX_ENA_S)
#define PF_GLINT_DYN_CTL_SW_ITR_INDX_S	25
#define PF_GLINT_DYN_CTL_SW_ITR_INDX_M	BIT(PF_GLINT_DYN_CTL_SW_ITR_INDX_S)
#define PF_GLINT_DYN_CTL_WB_ON_ITR_S	30
#define PF_GLINT_DYN_CTL_WB_ON_ITR_M	BIT(PF_GLINT_DYN_CTL_WB_ON_ITR_S)
#define PF_GLINT_DYN_CTL_INTENA_MSK_S	31
#define PF_GLINT_DYN_CTL_INTENA_MSK_M	BIT(PF_GLINT_DYN_CTL_INTENA_MSK_S)
/* _ITR is ITR index, _INT is interrupt index, _itrn_indx_spacing is
 * spacing b/w itrn registers of the same vector.
 */
#define PF_GLINT_ITR_ADDR(_ITR, _reg_start, _itrn_indx_spacing)	\
	((_reg_start) + ((_ITR) * (_itrn_indx_spacing)))
/* For PF, itrn_indx_spacing is 4 and itrn_reg_spacing is 0x1000 */
#define PF_GLINT_ITR(_ITR, _INT)	\
	(PF_GLINT_BASE + (((_ITR) + 1) * 4) + ((_INT) * 0x1000))
#define PF_GLINT_ITR_MAX_INDEX		2
#define PF_GLINT_ITR_INTERVAL_S		0
#define PF_GLINT_ITR_INTERVAL_M		GENMASK(11, 0)

/* Generic registers */
#define PF_INT_DIR_OICR_ENA		0x08406000
#define PF_INT_DIR_OICR_ENA_S		0
#define PF_INT_DIR_OICR_ENA_M		GENMASK(31, 0)
#define PF_INT_DIR_OICR			0x08406004
#define PF_INT_DIR_OICR_TSYN_EVNT	0
#define PF_INT_DIR_OICR_PHY_TS_0	BIT(1)
#define PF_INT_DIR_OICR_PHY_TS_1	BIT(2)
#define PF_INT_DIR_OICR_CAUSE		0x08406008
#define PF_INT_DIR_OICR_CAUSE_CAUSE_S	0
#define PF_INT_DIR_OICR_CAUSE_CAUSE_M	GENMASK(31, 0)
#define PF_INT_PBA_CLEAR		0x0840600C

#define PF_FUNC_RID			0x08406010
#define PF_FUNC_RID_FUNCTION_NUMBER_S	0
#define PF_FUNC_RID_FUNCTION_NUMBER_M	GENMASK(2, 0)
#define PF_FUNC_RID_DEVICE_NUMBER_S	3
#define PF_FUNC_RID_DEVICE_NUMBER_M	GENMASK(7, 3)
#define PF_FUNC_RID_BUS_NUMBER_S	8
#define PF_FUNC_RID_BUS_NUMBER_M	GENMASK(15, 8)

/* Reset registers */
#define PFGEN_RTRIG			0x08407000
#define PFGEN_RTRIG_CORER_S		0
#define PFGEN_RTRIG_CORER_M		BIT(0)
#define PFGEN_RTRIG_LINKR_S		1
#define PFGEN_RTRIG_LINKR_M		BIT(1)
#define PFGEN_RTRIG_IMCR_S		2
#define PFGEN_RTRIG_IMCR_M		BIT(2)
#define PFGEN_RSTAT			0x08407008 /* PFR Status */
#define PFGEN_RSTAT_PFR_STATE_S		0
#define PFGEN_RSTAT_PFR_STATE_M		GENMASK(1, 0)
#define PFGEN_CTRL			0x0840700C
#define PFGEN_CTRL_PFSWR		BIT(0)

#endif
