/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Qualcomm #define SM6350 interconnect IDs
 *
 * Copyright (C) 2022 Luca Weiss <luca.weiss@fairphone.com>
 */

#ifndef __DRIVERS_INTERCONNECT_QCOM_SM6350_H
#define __DRIVERS_INTERCONNECT_QCOM_SM6350_H

#define SM6350_A1NOC_SNOC_MAS			0
#define SM6350_A1NOC_SNOC_SLV			1
#define SM6350_A2NOC_SNOC_MAS			2
#define SM6350_A2NOC_SNOC_SLV			3
#define SM6350_MASTER_A1NOC_CFG			4
#define SM6350_MASTER_A2NOC_CFG			5
#define SM6350_MASTER_AMPSS_M0			6
#define SM6350_MASTER_CAMNOC_HF			7
#define SM6350_MASTER_CAMNOC_HF0_UNCOMP		8
#define SM6350_MASTER_CAMNOC_ICP		9
#define SM6350_MASTER_CAMNOC_ICP_UNCOMP		10
#define SM6350_MASTER_CAMNOC_SF			11
#define SM6350_MASTER_CAMNOC_SF_UNCOMP		12
#define SM6350_MASTER_CNOC_DC_NOC		13
#define SM6350_MASTER_CNOC_MNOC_CFG		14
#define SM6350_MASTER_COMPUTE_NOC		15
#define SM6350_MASTER_CRYPTO_CORE_0		16
#define SM6350_MASTER_EMMC			17
#define SM6350_MASTER_GEM_NOC_CFG		18
#define SM6350_MASTER_GEM_NOC_SNOC		19
#define SM6350_MASTER_GIC			20
#define SM6350_MASTER_GRAPHICS_3D		21
#define SM6350_MASTER_IPA			22
#define SM6350_MASTER_LLCC			23
#define SM6350_MASTER_MDP_PORT0			24
#define SM6350_MASTER_MNOC_HF_MEM_NOC		25
#define SM6350_MASTER_MNOC_SF_MEM_NOC		26
#define SM6350_MASTER_NPU			27
#define SM6350_MASTER_NPU_NOC_CFG		28
#define SM6350_MASTER_NPU_PROC			29
#define SM6350_MASTER_NPU_SYS			30
#define SM6350_MASTER_PIMEM			31
#define SM6350_MASTER_QDSS_BAM			32
#define SM6350_MASTER_QDSS_DAP			33
#define SM6350_MASTER_QDSS_ETR			34
#define SM6350_MASTER_QUP_0			35
#define SM6350_MASTER_QUP_1			36
#define SM6350_MASTER_QUP_CORE_0		37
#define SM6350_MASTER_QUP_CORE_1		38
#define SM6350_MASTER_SDCC_2			39
#define SM6350_MASTER_SNOC_CFG			40
#define SM6350_MASTER_SNOC_GC_MEM_NOC		41
#define SM6350_MASTER_SNOC_SF_MEM_NOC		42
#define SM6350_MASTER_SYS_TCU			43
#define SM6350_MASTER_UFS_MEM			44
#define SM6350_MASTER_USB3			45
#define SM6350_MASTER_VIDEO_P0			46
#define SM6350_MASTER_VIDEO_PROC		47
#define SM6350_SLAVE_A1NOC_CFG			48
#define SM6350_SLAVE_A2NOC_CFG			49
#define SM6350_SLAVE_AHB2PHY			50
#define SM6350_SLAVE_AHB2PHY_2			51
#define SM6350_SLAVE_AOSS			52
#define SM6350_SLAVE_APPSS			53
#define SM6350_SLAVE_BOOT_ROM			54
#define SM6350_SLAVE_CAMERA_CFG			55
#define SM6350_SLAVE_CAMERA_NRT_THROTTLE_CFG	56
#define SM6350_SLAVE_CAMERA_RT_THROTTLE_CFG	57
#define SM6350_SLAVE_CAMNOC_UNCOMP		58
#define SM6350_SLAVE_CDSP_GEM_NOC		59
#define SM6350_SLAVE_CLK_CTL			60
#define SM6350_SLAVE_CNOC_DDRSS			61
#define SM6350_SLAVE_CNOC_MNOC_CFG		62
#define SM6350_SLAVE_CNOC_MSS			63
#define SM6350_SLAVE_CRYPTO_0_CFG		64
#define SM6350_SLAVE_DCC_CFG			65
#define SM6350_SLAVE_DISPLAY_CFG		66
#define SM6350_SLAVE_DISPLAY_THROTTLE_CFG	67
#define SM6350_SLAVE_EBI_CH0			68
#define SM6350_SLAVE_EMMC_CFG			69
#define SM6350_SLAVE_GEM_NOC_CFG		70
#define SM6350_SLAVE_GEM_NOC_SNOC		71
#define SM6350_SLAVE_GLM			72
#define SM6350_SLAVE_GRAPHICS_3D_CFG		73
#define SM6350_SLAVE_IMEM_CFG			74
#define SM6350_SLAVE_IPA_CFG			75
#define SM6350_SLAVE_ISENSE_CFG			76
#define SM6350_SLAVE_LLCC			77
#define SM6350_SLAVE_LLCC_CFG			78
#define SM6350_SLAVE_MCDMA_MS_MPU_CFG		79
#define SM6350_SLAVE_MNOC_HF_MEM_NOC		80
#define SM6350_SLAVE_MNOC_SF_MEM_NOC		81
#define SM6350_SLAVE_MSS_PROC_MS_MPU_CFG	82
#define SM6350_SLAVE_NPU_CAL_DP0		83
#define SM6350_SLAVE_NPU_CFG			84
#define SM6350_SLAVE_NPU_COMPUTE_NOC		85
#define SM6350_SLAVE_NPU_CP			86
#define SM6350_SLAVE_NPU_DPM			87
#define SM6350_SLAVE_NPU_INT_DMA_BWMON_CFG	88
#define SM6350_SLAVE_NPU_LLM_CFG		89
#define SM6350_SLAVE_NPU_TCM			90
#define SM6350_SLAVE_OCIMEM			91
#define SM6350_SLAVE_PDM			92
#define SM6350_SLAVE_PIMEM			93
#define SM6350_SLAVE_PIMEM_CFG			94
#define SM6350_SLAVE_PRNG			95
#define SM6350_SLAVE_QDSS_CFG			96
#define SM6350_SLAVE_QDSS_STM			97
#define SM6350_SLAVE_QM_CFG			98
#define SM6350_SLAVE_QM_MPU_CFG			99
#define SM6350_SLAVE_QUP_0			100
#define SM6350_SLAVE_QUP_1			101
#define SM6350_SLAVE_QUP_CORE_0			102
#define SM6350_SLAVE_QUP_CORE_1			103
#define SM6350_SLAVE_RBCPR_CX_CFG		104
#define SM6350_SLAVE_RBCPR_MX_CFG		105
#define SM6350_SLAVE_SDCC_2			106
#define SM6350_SLAVE_SECURITY			107
#define SM6350_SLAVE_SERVICE_A1NOC		108
#define SM6350_SLAVE_SERVICE_A2NOC		109
#define SM6350_SLAVE_SERVICE_CNOC		110
#define SM6350_SLAVE_SERVICE_GEM_NOC		111
#define SM6350_SLAVE_SERVICE_MNOC		112
#define SM6350_SLAVE_SERVICE_NPU_NOC		113
#define SM6350_SLAVE_SERVICE_SNOC		114
#define SM6350_SLAVE_SNOC_CFG			115
#define SM6350_SLAVE_SNOC_GEM_NOC_GC		116
#define SM6350_SLAVE_SNOC_GEM_NOC_SF		117
#define SM6350_SLAVE_TCSR			118
#define SM6350_SLAVE_TCU			119
#define SM6350_SLAVE_UFS_MEM_CFG		120
#define SM6350_SLAVE_USB3			121
#define SM6350_SLAVE_VENUS_CFG			122
#define SM6350_SLAVE_VENUS_THROTTLE_CFG		123
#define SM6350_SLAVE_VSENSE_CTRL_CFG		124
#define SM6350_SNOC_CNOC_MAS			125
#define SM6350_SNOC_CNOC_SLV			126

#endif
