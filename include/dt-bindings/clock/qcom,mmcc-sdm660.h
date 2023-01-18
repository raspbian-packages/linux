/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */

#ifndef _DT_BINDINGS_CLK_MSM_MMCC_660_H
#define _DT_BINDINGS_CLK_MSM_MMCC_660_H

#define AHB_CLK_SRC							0
#define BYTE0_CLK_SRC						1
#define BYTE1_CLK_SRC						2
#define CAMSS_GP0_CLK_SRC					3
#define CAMSS_GP1_CLK_SRC					4
#define CCI_CLK_SRC							5
#define CPP_CLK_SRC							6
#define CSI0_CLK_SRC						7
#define CSI0PHYTIMER_CLK_SRC				8
#define CSI1_CLK_SRC						9
#define CSI1PHYTIMER_CLK_SRC				10
#define CSI2_CLK_SRC						11
#define CSI2PHYTIMER_CLK_SRC				12
#define CSI3_CLK_SRC						13
#define CSIPHY_CLK_SRC						14
#define DP_AUX_CLK_SRC						15
#define DP_CRYPTO_CLK_SRC					16
#define DP_GTC_CLK_SRC						17
#define DP_LINK_CLK_SRC						18
#define DP_PIXEL_CLK_SRC					19
#define ESC0_CLK_SRC						20
#define ESC1_CLK_SRC						21
#define JPEG0_CLK_SRC						22
#define MCLK0_CLK_SRC						23
#define MCLK1_CLK_SRC						24
#define MCLK2_CLK_SRC						25
#define MCLK3_CLK_SRC						26
#define MDP_CLK_SRC							27
#define MMPLL0_PLL							28
#define MMPLL10_PLL							29
#define MMPLL1_PLL							30
#define MMPLL3_PLL							31
#define MMPLL4_PLL							32
#define MMPLL5_PLL							33
#define MMPLL6_PLL							34
#define MMPLL7_PLL							35
#define MMPLL8_PLL							36
#define BIMC_SMMU_AHB_CLK					37
#define BIMC_SMMU_AXI_CLK					38
#define CAMSS_AHB_CLK						39
#define CAMSS_CCI_AHB_CLK					40
#define CAMSS_CCI_CLK						41
#define CAMSS_CPHY_CSID0_CLK				42
#define CAMSS_CPHY_CSID1_CLK				43
#define CAMSS_CPHY_CSID2_CLK				44
#define CAMSS_CPHY_CSID3_CLK				45
#define CAMSS_CPP_AHB_CLK					46
#define CAMSS_CPP_AXI_CLK					47
#define CAMSS_CPP_CLK						48
#define CAMSS_CPP_VBIF_AHB_CLK				49
#define CAMSS_CSI0_AHB_CLK					50
#define CAMSS_CSI0_CLK						51
#define CAMSS_CSI0PHYTIMER_CLK				52
#define CAMSS_CSI0PIX_CLK					53
#define CAMSS_CSI0RDI_CLK					54
#define CAMSS_CSI1_AHB_CLK					55
#define CAMSS_CSI1_CLK						56
#define CAMSS_CSI1PHYTIMER_CLK				57
#define CAMSS_CSI1PIX_CLK					58
#define CAMSS_CSI1RDI_CLK					59
#define CAMSS_CSI2_AHB_CLK					60
#define CAMSS_CSI2_CLK						61
#define CAMSS_CSI2PHYTIMER_CLK				62
#define CAMSS_CSI2PIX_CLK					63
#define CAMSS_CSI2RDI_CLK					64
#define CAMSS_CSI3_AHB_CLK					65
#define CAMSS_CSI3_CLK						66
#define CAMSS_CSI3PIX_CLK					67
#define CAMSS_CSI3RDI_CLK					68
#define CAMSS_CSI_VFE0_CLK					69
#define CAMSS_CSI_VFE1_CLK					70
#define CAMSS_CSIPHY0_CLK					71
#define CAMSS_CSIPHY1_CLK					72
#define CAMSS_CSIPHY2_CLK					73
#define CAMSS_GP0_CLK						74
#define CAMSS_GP1_CLK						75
#define CAMSS_ISPIF_AHB_CLK					76
#define CAMSS_JPEG0_CLK						77
#define CAMSS_JPEG_AHB_CLK					78
#define CAMSS_JPEG_AXI_CLK					79
#define CAMSS_MCLK0_CLK						80
#define CAMSS_MCLK1_CLK						81
#define CAMSS_MCLK2_CLK						82
#define CAMSS_MCLK3_CLK						83
#define CAMSS_MICRO_AHB_CLK					84
#define CAMSS_TOP_AHB_CLK					85
#define CAMSS_VFE0_AHB_CLK					86
#define CAMSS_VFE0_CLK						87
#define CAMSS_VFE0_STREAM_CLK				88
#define CAMSS_VFE1_AHB_CLK					89
#define CAMSS_VFE1_CLK						90
#define CAMSS_VFE1_STREAM_CLK				91
#define CAMSS_VFE_VBIF_AHB_CLK				92
#define CAMSS_VFE_VBIF_AXI_CLK				93
#define CSIPHY_AHB2CRIF_CLK					94
#define CXO_CLK								95
#define MDSS_AHB_CLK						96
#define MDSS_AXI_CLK						97
#define MDSS_BYTE0_CLK						98
#define MDSS_BYTE0_INTF_CLK					99
#define MDSS_BYTE0_INTF_DIV_CLK				100
#define MDSS_BYTE1_CLK						101
#define MDSS_BYTE1_INTF_CLK					102
#define MDSS_DP_AUX_CLK						103
#define MDSS_DP_CRYPTO_CLK					104
#define MDSS_DP_GTC_CLK						105
#define MDSS_DP_LINK_CLK					106
#define MDSS_DP_LINK_INTF_CLK				107
#define MDSS_DP_PIXEL_CLK					108
#define MDSS_ESC0_CLK						109
#define MDSS_ESC1_CLK						110
#define MDSS_HDMI_DP_AHB_CLK				111
#define MDSS_MDP_CLK						112
#define MDSS_PCLK0_CLK						113
#define MDSS_PCLK1_CLK						114
#define MDSS_ROT_CLK						115
#define MDSS_VSYNC_CLK						116
#define MISC_AHB_CLK						117
#define MISC_CXO_CLK						118
#define MNOC_AHB_CLK						119
#define SNOC_DVM_AXI_CLK					120
#define THROTTLE_CAMSS_AHB_CLK				121
#define THROTTLE_CAMSS_AXI_CLK				122
#define THROTTLE_MDSS_AHB_CLK				123
#define THROTTLE_MDSS_AXI_CLK				124
#define THROTTLE_VIDEO_AHB_CLK				125
#define THROTTLE_VIDEO_AXI_CLK				126
#define VIDEO_AHB_CLK						127
#define VIDEO_AXI_CLK						128
#define VIDEO_CORE_CLK						129
#define VIDEO_SUBCORE0_CLK					130
#define PCLK0_CLK_SRC						131
#define PCLK1_CLK_SRC						132
#define ROT_CLK_SRC							133
#define VFE0_CLK_SRC						134
#define VFE1_CLK_SRC						135
#define VIDEO_CORE_CLK_SRC					136
#define VSYNC_CLK_SRC						137
#define MDSS_BYTE1_INTF_DIV_CLK				138
#define AXI_CLK_SRC							139

#define VENUS_GDSC								0
#define VENUS_CORE0_GDSC						1
#define MDSS_GDSC								2
#define CAMSS_TOP_GDSC							3
#define CAMSS_VFE0_GDSC							4
#define CAMSS_VFE1_GDSC							5
#define CAMSS_CPP_GDSC							6
#define BIMC_SMMU_GDSC							7

#define CAMSS_MICRO_BCR				 0

#endif

