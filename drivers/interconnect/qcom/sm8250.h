/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Qualcomm #define SM8250 interconnect IDs
 *
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */

#ifndef __DRIVERS_INTERCONNECT_QCOM_SM8250_H
#define __DRIVERS_INTERCONNECT_QCOM_SM8250_H

#define SM8250_A1NOC_SNOC_MAS			0
#define SM8250_A1NOC_SNOC_SLV			1
#define SM8250_A2NOC_SNOC_MAS			2
#define SM8250_A2NOC_SNOC_SLV			3
#define SM8250_MASTER_A1NOC_CFG			4
#define SM8250_MASTER_A2NOC_CFG			5
#define SM8250_MASTER_AMPSS_M0			6
#define SM8250_MASTER_ANOC_PCIE_GEM_NOC		7
#define SM8250_MASTER_CAMNOC_HF			8
#define SM8250_MASTER_CAMNOC_ICP		9
#define SM8250_MASTER_CAMNOC_SF			10
#define SM8250_MASTER_CNOC_A2NOC		11
#define SM8250_MASTER_CNOC_DC_NOC		12
#define SM8250_MASTER_CNOC_MNOC_CFG		13
#define SM8250_MASTER_COMPUTE_NOC		14
#define SM8250_MASTER_CRYPTO_CORE_0		15
#define SM8250_MASTER_GEM_NOC_CFG		16
#define SM8250_MASTER_GEM_NOC_PCIE_SNOC		17
#define SM8250_MASTER_GEM_NOC_SNOC		18
#define SM8250_MASTER_GIC			19
#define SM8250_MASTER_GPU_TCU			20
#define SM8250_MASTER_GRAPHICS_3D		21
#define SM8250_MASTER_IPA			22
/* 23 was used by MASTER_IPA_CORE, now represented as RPMh clock */
#define SM8250_MASTER_LLCC			24
#define SM8250_MASTER_MDP_PORT0			25
#define SM8250_MASTER_MDP_PORT1			26
#define SM8250_MASTER_MNOC_HF_MEM_NOC		27
#define SM8250_MASTER_MNOC_SF_MEM_NOC		28
#define SM8250_MASTER_NPU			29
#define SM8250_MASTER_NPU_CDP			30
#define SM8250_MASTER_NPU_NOC_CFG		31
#define SM8250_MASTER_NPU_SYS			32
#define SM8250_MASTER_PCIE			33
#define SM8250_MASTER_PCIE_1			34
#define SM8250_MASTER_PCIE_2			35
#define SM8250_MASTER_PIMEM			36
#define SM8250_MASTER_QDSS_BAM			37
#define SM8250_MASTER_QDSS_DAP			38
#define SM8250_MASTER_QDSS_ETR			39
#define SM8250_MASTER_QSPI_0			40
#define SM8250_MASTER_QUP_0			41
#define SM8250_MASTER_QUP_1			42
#define SM8250_MASTER_QUP_2			43
#define SM8250_MASTER_ROTATOR			44
#define SM8250_MASTER_SDCC_2			45
#define SM8250_MASTER_SDCC_4			46
#define SM8250_MASTER_SNOC_CFG			47
#define SM8250_MASTER_SNOC_GC_MEM_NOC		48
#define SM8250_MASTER_SNOC_SF_MEM_NOC		49
#define SM8250_MASTER_SYS_TCU			50
#define SM8250_MASTER_TSIF			51
#define SM8250_MASTER_UFS_CARD			52
#define SM8250_MASTER_UFS_MEM			53
#define SM8250_MASTER_USB3			54
#define SM8250_MASTER_USB3_1			55
#define SM8250_MASTER_VIDEO_P0			56
#define SM8250_MASTER_VIDEO_P1			57
#define SM8250_MASTER_VIDEO_PROC		58
#define SM8250_SLAVE_A1NOC_CFG			59
#define SM8250_SLAVE_A2NOC_CFG			60
#define SM8250_SLAVE_AHB2PHY_NORTH		61
#define SM8250_SLAVE_AHB2PHY_SOUTH		62
#define SM8250_SLAVE_ANOC_PCIE_GEM_NOC		63
#define SM8250_SLAVE_ANOC_PCIE_GEM_NOC_1	64
#define SM8250_SLAVE_AOSS			65
#define SM8250_SLAVE_APPSS			66
#define SM8250_SLAVE_CAMERA_CFG			67
#define SM8250_SLAVE_CDSP_CFG			68
#define SM8250_SLAVE_CDSP_MEM_NOC		69
#define SM8250_SLAVE_CLK_CTL			70
#define SM8250_SLAVE_CNOC_A2NOC			71
#define SM8250_SLAVE_CNOC_DDRSS			72
#define SM8250_SLAVE_CNOC_MNOC_CFG		73
#define SM8250_SLAVE_CRYPTO_0_CFG		74
#define SM8250_SLAVE_CX_RDPM			75
#define SM8250_SLAVE_DCC_CFG			76
#define SM8250_SLAVE_DISPLAY_CFG		77
#define SM8250_SLAVE_EBI_CH0			78
#define SM8250_SLAVE_GEM_NOC_CFG		79
#define SM8250_SLAVE_GEM_NOC_SNOC		80
#define SM8250_SLAVE_GRAPHICS_3D_CFG		81
#define SM8250_SLAVE_IMEM_CFG			82
#define SM8250_SLAVE_IPA_CFG			83
/* 84 was used by SLAVE_IPA_CORE, now represented as RPMh clock */
#define SM8250_SLAVE_IPC_ROUTER_CFG		85
#define SM8250_SLAVE_ISENSE_CFG			86
#define SM8250_SLAVE_LLCC			87
#define SM8250_SLAVE_LLCC_CFG			88
#define SM8250_SLAVE_LPASS			89
#define SM8250_SLAVE_MEM_NOC_PCIE_SNOC		90
#define SM8250_SLAVE_MNOC_HF_MEM_NOC		91
#define SM8250_SLAVE_MNOC_SF_MEM_NOC		92
#define SM8250_SLAVE_NPU_CAL_DP0		93
#define SM8250_SLAVE_NPU_CAL_DP1		94
#define SM8250_SLAVE_NPU_CFG			95
#define SM8250_SLAVE_NPU_COMPUTE_NOC		96
#define SM8250_SLAVE_NPU_CP			97
#define SM8250_SLAVE_NPU_DPM			98
#define SM8250_SLAVE_NPU_INT_DMA_BWMON_CFG	99
#define SM8250_SLAVE_NPU_LLM_CFG		100
#define SM8250_SLAVE_NPU_TCM			101
#define SM8250_SLAVE_OCIMEM			102
#define SM8250_SLAVE_PCIE_0			103
#define SM8250_SLAVE_PCIE_0_CFG			104
#define SM8250_SLAVE_PCIE_1			105
#define SM8250_SLAVE_PCIE_1_CFG			106
#define SM8250_SLAVE_PCIE_2			107
#define SM8250_SLAVE_PCIE_2_CFG			108
#define SM8250_SLAVE_PDM			109
#define SM8250_SLAVE_PIMEM			110
#define SM8250_SLAVE_PIMEM_CFG			111
#define SM8250_SLAVE_PRNG			112
#define SM8250_SLAVE_QDSS_CFG			113
#define SM8250_SLAVE_QDSS_STM			114
#define SM8250_SLAVE_QSPI_0			115
#define SM8250_SLAVE_QUP_0			116
#define SM8250_SLAVE_QUP_1			117
#define SM8250_SLAVE_QUP_2			118
#define SM8250_SLAVE_RBCPR_CX_CFG		119
#define SM8250_SLAVE_RBCPR_MMCX_CFG		120
#define SM8250_SLAVE_RBCPR_MX_CFG		121
#define SM8250_SLAVE_SDCC_2			122
#define SM8250_SLAVE_SDCC_4			123
#define SM8250_SLAVE_SERVICE_A1NOC		124
#define SM8250_SLAVE_SERVICE_A2NOC		125
#define SM8250_SLAVE_SERVICE_CNOC		126
#define SM8250_SLAVE_SERVICE_GEM_NOC		127
#define SM8250_SLAVE_SERVICE_GEM_NOC_1		128
#define SM8250_SLAVE_SERVICE_GEM_NOC_2		129
#define SM8250_SLAVE_SERVICE_MNOC		130
#define SM8250_SLAVE_SERVICE_NPU_NOC		131
#define SM8250_SLAVE_SERVICE_SNOC		132
#define SM8250_SLAVE_SNOC_CFG			133
#define SM8250_SLAVE_SNOC_GEM_NOC_GC		134
#define SM8250_SLAVE_SNOC_GEM_NOC_SF		135
#define SM8250_SLAVE_TCSR			136
#define SM8250_SLAVE_TCU			137
#define SM8250_SLAVE_TLMM_NORTH			138
#define SM8250_SLAVE_TLMM_SOUTH			139
#define SM8250_SLAVE_TLMM_WEST			140
#define SM8250_SLAVE_TSIF			141
#define SM8250_SLAVE_UFS_CARD_CFG		142
#define SM8250_SLAVE_UFS_MEM_CFG		143
#define SM8250_SLAVE_USB3			144
#define SM8250_SLAVE_USB3_1			145
#define SM8250_SLAVE_VENUS_CFG			146
#define SM8250_SLAVE_VSENSE_CTRL_CFG		147
#define SM8250_SNOC_CNOC_MAS			148
#define SM8250_SNOC_CNOC_SLV			149

#endif
