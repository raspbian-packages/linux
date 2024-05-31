/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Qualcomm #define SC8180X interconnect IDs
 *
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */

#ifndef __DRIVERS_INTERCONNECT_QCOM_SC8180X_H
#define __DRIVERS_INTERCONNECT_QCOM_SC8180X_H

#define SC8180X_MASTER_A1NOC_CFG		1
#define SC8180X_MASTER_UFS_CARD			2
#define SC8180X_MASTER_UFS_GEN4			3
#define SC8180X_MASTER_UFS_MEM			4
#define SC8180X_MASTER_USB3			5
#define SC8180X_MASTER_USB3_1			6
#define SC8180X_MASTER_USB3_2			7
#define SC8180X_MASTER_A2NOC_CFG		8
#define SC8180X_MASTER_QDSS_BAM			9
#define SC8180X_MASTER_QSPI_0			10
#define SC8180X_MASTER_QSPI_1			11
#define SC8180X_MASTER_QUP_0			12
#define SC8180X_MASTER_QUP_1			13
#define SC8180X_MASTER_QUP_2			14
#define SC8180X_MASTER_SENSORS_AHB		15
#define SC8180X_MASTER_CRYPTO_CORE_0		16
#define SC8180X_MASTER_IPA			17
#define SC8180X_MASTER_EMAC			18
#define SC8180X_MASTER_PCIE			19
#define SC8180X_MASTER_PCIE_1			20
#define SC8180X_MASTER_PCIE_2			21
#define SC8180X_MASTER_PCIE_3			22
#define SC8180X_MASTER_QDSS_ETR			23
#define SC8180X_MASTER_SDCC_2			24
#define SC8180X_MASTER_SDCC_4			25
#define SC8180X_MASTER_CAMNOC_HF0_UNCOMP	26
#define SC8180X_MASTER_CAMNOC_HF1_UNCOMP	27
#define SC8180X_MASTER_CAMNOC_SF_UNCOMP		28
#define SC8180X_MASTER_NPU			29
#define SC8180X_SNOC_CNOC_MAS			30
#define SC8180X_MASTER_CNOC_DC_NOC		31
#define SC8180X_MASTER_AMPSS_M0			32
#define SC8180X_MASTER_GPU_TCU			33
#define SC8180X_MASTER_SYS_TCU			34
#define SC8180X_MASTER_GEM_NOC_CFG		35
#define SC8180X_MASTER_COMPUTE_NOC		36
#define SC8180X_MASTER_GRAPHICS_3D		37
#define SC8180X_MASTER_MNOC_HF_MEM_NOC		38
#define SC8180X_MASTER_MNOC_SF_MEM_NOC		39
#define SC8180X_MASTER_GEM_NOC_PCIE_SNOC	40
#define SC8180X_MASTER_SNOC_GC_MEM_NOC		41
#define SC8180X_MASTER_SNOC_SF_MEM_NOC		42
#define SC8180X_MASTER_ECC			43
/* 44 was used by MASTER_IPA_CORE, now represented as RPMh clock */
#define SC8180X_MASTER_LLCC			45
#define SC8180X_MASTER_CNOC_MNOC_CFG		46
#define SC8180X_MASTER_CAMNOC_HF0		47
#define SC8180X_MASTER_CAMNOC_HF1		48
#define SC8180X_MASTER_CAMNOC_SF		49
#define SC8180X_MASTER_MDP_PORT0		50
#define SC8180X_MASTER_MDP_PORT1		51
#define SC8180X_MASTER_ROTATOR			52
#define SC8180X_MASTER_VIDEO_P0			53
#define SC8180X_MASTER_VIDEO_P1			54
#define SC8180X_MASTER_VIDEO_PROC		55
#define SC8180X_MASTER_SNOC_CFG			56
#define SC8180X_A1NOC_SNOC_MAS			57
#define SC8180X_A2NOC_SNOC_MAS			58
#define SC8180X_MASTER_GEM_NOC_SNOC		59
#define SC8180X_MASTER_PIMEM			60
#define SC8180X_MASTER_GIC			61
#define SC8180X_MASTER_MNOC_HF_MEM_NOC_DISPLAY	62
#define SC8180X_MASTER_MNOC_SF_MEM_NOC_DISPLAY	63
#define SC8180X_MASTER_LLCC_DISPLAY		64
#define SC8180X_MASTER_MDP_PORT0_DISPLAY	65
#define SC8180X_MASTER_MDP_PORT1_DISPLAY	66
#define SC8180X_MASTER_ROTATOR_DISPLAY		67
#define SC8180X_A1NOC_SNOC_SLV			68
#define SC8180X_SLAVE_SERVICE_A1NOC		69
#define SC8180X_A2NOC_SNOC_SLV			70
#define SC8180X_SLAVE_ANOC_PCIE_GEM_NOC		71
#define SC8180X_SLAVE_SERVICE_A2NOC		72
#define SC8180X_SLAVE_CAMNOC_UNCOMP		73
#define SC8180X_SLAVE_CDSP_MEM_NOC		74
#define SC8180X_SLAVE_A1NOC_CFG			75
#define SC8180X_SLAVE_A2NOC_CFG			76
#define SC8180X_SLAVE_AHB2PHY_CENTER		77
#define SC8180X_SLAVE_AHB2PHY_EAST		78
#define SC8180X_SLAVE_AHB2PHY_WEST		79
#define SC8180X_SLAVE_AHB2PHY_SOUTH		80
#define SC8180X_SLAVE_AOP			81
#define SC8180X_SLAVE_AOSS			82
#define SC8180X_SLAVE_CAMERA_CFG		83
#define SC8180X_SLAVE_CLK_CTL			84
#define SC8180X_SLAVE_CDSP_CFG			85
#define SC8180X_SLAVE_RBCPR_CX_CFG		86
#define SC8180X_SLAVE_RBCPR_MMCX_CFG		87
#define SC8180X_SLAVE_RBCPR_MX_CFG		88
#define SC8180X_SLAVE_CRYPTO_0_CFG		89
#define SC8180X_SLAVE_CNOC_DDRSS		90
#define SC8180X_SLAVE_DISPLAY_CFG		91
#define SC8180X_SLAVE_EMAC_CFG			92
#define SC8180X_SLAVE_GLM			93
#define SC8180X_SLAVE_GRAPHICS_3D_CFG		94
#define SC8180X_SLAVE_IMEM_CFG			95
#define SC8180X_SLAVE_IPA_CFG			96
#define SC8180X_SLAVE_CNOC_MNOC_CFG		97
#define SC8180X_SLAVE_NPU_CFG			98
#define SC8180X_SLAVE_PCIE_0_CFG		99
#define SC8180X_SLAVE_PCIE_1_CFG		100
#define SC8180X_SLAVE_PCIE_2_CFG		101
#define SC8180X_SLAVE_PCIE_3_CFG		102
#define SC8180X_SLAVE_PDM			103
#define SC8180X_SLAVE_PIMEM_CFG			104
#define SC8180X_SLAVE_PRNG			105
#define SC8180X_SLAVE_QDSS_CFG			106
#define SC8180X_SLAVE_QSPI_0			107
#define SC8180X_SLAVE_QSPI_1			108
#define SC8180X_SLAVE_QUP_1			109
#define SC8180X_SLAVE_QUP_2			110
#define SC8180X_SLAVE_QUP_0			111
#define SC8180X_SLAVE_SDCC_2			112
#define SC8180X_SLAVE_SDCC_4			113
#define SC8180X_SLAVE_SECURITY			114
#define SC8180X_SLAVE_SNOC_CFG			115
#define SC8180X_SLAVE_SPSS_CFG			116
#define SC8180X_SLAVE_TCSR			117
#define SC8180X_SLAVE_TLMM_EAST			118
#define SC8180X_SLAVE_TLMM_SOUTH		119
#define SC8180X_SLAVE_TLMM_WEST			120
#define SC8180X_SLAVE_TSIF			121
#define SC8180X_SLAVE_UFS_CARD_CFG		122
#define SC8180X_SLAVE_UFS_MEM_0_CFG		123
#define SC8180X_SLAVE_UFS_MEM_1_CFG		124
#define SC8180X_SLAVE_USB3			125
#define SC8180X_SLAVE_USB3_1			126
#define SC8180X_SLAVE_USB3_2			127
#define SC8180X_SLAVE_VENUS_CFG			128
#define SC8180X_SLAVE_VSENSE_CTRL_CFG		129
#define SC8180X_SLAVE_SERVICE_CNOC		130
#define SC8180X_SLAVE_GEM_NOC_CFG		131
#define SC8180X_SLAVE_LLCC_CFG			132
#define SC8180X_SLAVE_MSS_PROC_MS_MPU_CFG	133
#define SC8180X_SLAVE_ECC			134
#define SC8180X_SLAVE_GEM_NOC_SNOC		135
#define SC8180X_SLAVE_LLCC			136
#define SC8180X_SLAVE_SERVICE_GEM_NOC		137
#define SC8180X_SLAVE_SERVICE_GEM_NOC_1		138
/* 139 was used by SLAVE_IPA_CORE, now represented as RPMh clock */
#define SC8180X_SLAVE_EBI_CH0			140
#define SC8180X_SLAVE_MNOC_SF_MEM_NOC		141
#define SC8180X_SLAVE_MNOC_HF_MEM_NOC		142
#define SC8180X_SLAVE_SERVICE_MNOC		143
#define SC8180X_SLAVE_APPSS			144
#define SC8180X_SNOC_CNOC_SLV			145
#define SC8180X_SLAVE_SNOC_GEM_NOC_GC		146
#define SC8180X_SLAVE_SNOC_GEM_NOC_SF		147
#define SC8180X_SLAVE_OCIMEM			148
#define SC8180X_SLAVE_PIMEM			149
#define SC8180X_SLAVE_SERVICE_SNOC		150
#define SC8180X_SLAVE_PCIE_0			151
#define SC8180X_SLAVE_PCIE_1			152
#define SC8180X_SLAVE_PCIE_2			153
#define SC8180X_SLAVE_PCIE_3			154
#define SC8180X_SLAVE_QDSS_STM			155
#define SC8180X_SLAVE_TCU			156
#define SC8180X_SLAVE_LLCC_DISPLAY		157
#define SC8180X_SLAVE_EBI_CH0_DISPLAY		158
#define SC8180X_SLAVE_MNOC_SF_MEM_NOC_DISPLAY	159
#define SC8180X_SLAVE_MNOC_HF_MEM_NOC_DISPLAY	160

#define SC8180X_MASTER_QUP_CORE_0		163
#define SC8180X_MASTER_QUP_CORE_1		164
#define SC8180X_MASTER_QUP_CORE_2		165
#define SC8180X_SLAVE_QUP_CORE_0		166
#define SC8180X_SLAVE_QUP_CORE_1		167
#define SC8180X_SLAVE_QUP_CORE_2		168

#endif
