/* SPDX-License-Identifier: (GPL-2.0+ OR MIT) */
/*
 * Copyright (c) 2019 Rockchip Electronics Co. Ltd.
 * Author: Finley Xiao <finley.xiao@rock-chips.com>
 */

#ifndef _DT_BINDINGS_CLK_ROCKCHIP_RV1126_H
#define _DT_BINDINGS_CLK_ROCKCHIP_RV1126_H

/* pmucru-clocks indices */

/* pll clocks */
#define PLL_GPLL		1

/* sclk (special clocks) */
#define CLK_OSC0_DIV32K		2
#define CLK_RTC32K		3
#define CLK_WIFI_DIV		4
#define CLK_WIFI_OSC0		5
#define CLK_WIFI		6
#define CLK_PMU			7
#define SCLK_UART1_DIV		8
#define SCLK_UART1_FRACDIV	9
#define SCLK_UART1_MUX		10
#define SCLK_UART1		11
#define CLK_I2C0		12
#define CLK_I2C2		13
#define CLK_CAPTURE_PWM0	14
#define CLK_PWM0		15
#define CLK_CAPTURE_PWM1	16
#define CLK_PWM1		17
#define CLK_SPI0		18
#define DBCLK_GPIO0		19
#define CLK_PMUPVTM		20
#define CLK_CORE_PMUPVTM	21
#define CLK_REF12M		22
#define CLK_USBPHY_OTG_REF	23
#define CLK_USBPHY_HOST_REF	24
#define CLK_REF24M		25
#define CLK_MIPIDSIPHY_REF	26

/* pclk */
#define PCLK_PDPMU		30
#define PCLK_PMU		31
#define PCLK_UART1		32
#define PCLK_I2C0		33
#define PCLK_I2C2		34
#define PCLK_PWM0		35
#define PCLK_PWM1		36
#define PCLK_SPI0		37
#define PCLK_GPIO0		38
#define PCLK_PMUSGRF		39
#define PCLK_PMUGRF		40
#define PCLK_PMUCRU		41
#define PCLK_CHIPVEROTP		42
#define PCLK_PDPMU_NIU		43
#define PCLK_PMUPVTM		44
#define PCLK_SCRKEYGEN		45

#define CLKPMU_NR_CLKS		(PCLK_SCRKEYGEN + 1)

/* cru-clocks indices */

/* pll clocks */
#define PLL_APLL		1
#define PLL_DPLL		2
#define PLL_CPLL		3
#define PLL_HPLL		4

/* sclk (special clocks) */
#define ARMCLK			5
#define USB480M			6
#define CLK_CORE_CPUPVTM	7
#define CLK_CPUPVTM		8
#define CLK_SCR1		9
#define CLK_SCR1_CORE		10
#define CLK_SCR1_RTC		11
#define CLK_SCR1_JTAG		12
#define SCLK_UART0_DIV		13
#define SCLK_UART0_FRAC		14
#define SCLK_UART0_MUX		15
#define SCLK_UART0		16
#define SCLK_UART2_DIV		17
#define SCLK_UART2_FRAC		18
#define SCLK_UART2_MUX		19
#define SCLK_UART2		20
#define SCLK_UART3_DIV		21
#define SCLK_UART3_FRAC		22
#define SCLK_UART3_MUX		23
#define SCLK_UART3		24
#define SCLK_UART4_DIV		25
#define SCLK_UART4_FRAC		26
#define SCLK_UART4_MUX		27
#define SCLK_UART4		28
#define SCLK_UART5_DIV		29
#define SCLK_UART5_FRAC		30
#define SCLK_UART5_MUX		31
#define SCLK_UART5		32
#define CLK_I2C1		33
#define CLK_I2C3		34
#define CLK_I2C4		35
#define CLK_I2C5		36
#define CLK_SPI1		37
#define CLK_CAPTURE_PWM2	38
#define CLK_PWM2		39
#define DBCLK_GPIO1		40
#define DBCLK_GPIO2		41
#define DBCLK_GPIO3		42
#define DBCLK_GPIO4		43
#define CLK_SARADC		44
#define CLK_TIMER0		45
#define CLK_TIMER1		46
#define CLK_TIMER2		47
#define CLK_TIMER3		48
#define CLK_TIMER4		49
#define CLK_TIMER5		50
#define CLK_CAN			51
#define CLK_NPU_TSADC		52
#define CLK_NPU_TSADCPHY	53
#define CLK_CPU_TSADC		54
#define CLK_CPU_TSADCPHY	55
#define CLK_CRYPTO_CORE		56
#define CLK_CRYPTO_PKA		57
#define MCLK_I2S0_TX_DIV	58
#define MCLK_I2S0_TX_FRACDIV	59
#define MCLK_I2S0_TX_MUX	60
#define MCLK_I2S0_TX		61
#define MCLK_I2S0_RX_DIV	62
#define MCLK_I2S0_RX_FRACDIV	63
#define MCLK_I2S0_RX_MUX	64
#define MCLK_I2S0_RX		65
#define MCLK_I2S0_TX_OUT2IO	66
#define MCLK_I2S0_RX_OUT2IO	67
#define MCLK_I2S1_DIV		68
#define MCLK_I2S1_FRACDIV	69
#define MCLK_I2S1_MUX		70
#define MCLK_I2S1		71
#define MCLK_I2S1_OUT2IO	72
#define MCLK_I2S2_DIV		73
#define MCLK_I2S2_FRACDIV	74
#define MCLK_I2S2_MUX		75
#define MCLK_I2S2		76
#define MCLK_I2S2_OUT2IO	77
#define MCLK_PDM		78
#define SCLK_ADUPWM_DIV		79
#define SCLK_AUDPWM_FRACDIV	80
#define SCLK_AUDPWM_MUX		81
#define	SCLK_AUDPWM		82
#define CLK_ACDCDIG_ADC		83
#define CLK_ACDCDIG_DAC		84
#define CLK_ACDCDIG_I2C		85
#define CLK_VENC_CORE		86
#define CLK_VDEC_CORE		87
#define CLK_VDEC_CA		88
#define CLK_VDEC_HEVC_CA	89
#define CLK_RGA_CORE		90
#define CLK_IEP_CORE		91
#define CLK_ISP_DIV		92
#define CLK_ISP_NP5		93
#define CLK_ISP_NUX		94
#define CLK_ISP			95
#define CLK_CIF_OUT_DIV		96
#define CLK_CIF_OUT_FRACDIV	97
#define CLK_CIF_OUT_MUX		98
#define CLK_CIF_OUT		99
#define CLK_MIPICSI_OUT_DIV	100
#define CLK_MIPICSI_OUT_FRACDIV	101
#define CLK_MIPICSI_OUT_MUX	102
#define CLK_MIPICSI_OUT		103
#define CLK_ISPP_DIV		104
#define CLK_ISPP_NP5		105
#define CLK_ISPP_NUX		106
#define CLK_ISPP		107
#define CLK_SDMMC		108
#define SCLK_SDMMC_DRV		109
#define SCLK_SDMMC_SAMPLE	110
#define CLK_SDIO		111
#define SCLK_SDIO_DRV		112
#define SCLK_SDIO_SAMPLE	113
#define CLK_EMMC		114
#define SCLK_EMMC_DRV		115
#define SCLK_EMMC_SAMPLE	116
#define CLK_NANDC		117
#define SCLK_SFC		118
#define CLK_USBHOST_UTMI_OHCI	119
#define CLK_USBOTG_REF		120
#define CLK_GMAC_DIV		121
#define CLK_GMAC_RGMII_M0	122
#define CLK_GMAC_SRC_M0		123
#define CLK_GMAC_RGMII_M1	124
#define CLK_GMAC_SRC_M1		125
#define CLK_GMAC_SRC		126
#define CLK_GMAC_REF		127
#define CLK_GMAC_TX_SRC		128
#define CLK_GMAC_TX_DIV5	129
#define CLK_GMAC_TX_DIV50	130
#define RGMII_MODE_CLK		131
#define CLK_GMAC_RX_SRC		132
#define CLK_GMAC_RX_DIV2	133
#define CLK_GMAC_RX_DIV20	134
#define RMII_MODE_CLK		135
#define CLK_GMAC_TX_RX		136
#define CLK_GMAC_PTPREF		137
#define CLK_GMAC_ETHERNET_OUT	138
#define CLK_DDRPHY		139
#define CLK_DDR_MON		140
#define TMCLK_DDR_MON		141
#define CLK_NPU_DIV		142
#define CLK_NPU_NP5		143
#define CLK_CORE_NPU		144
#define CLK_CORE_NPUPVTM	145
#define CLK_NPUPVTM		146
#define SCLK_DDRCLK		147
#define CLK_OTP			148

/* dclk */
#define DCLK_DECOM		150
#define DCLK_VOP_DIV		151
#define DCLK_VOP_FRACDIV	152
#define DCLK_VOP_MUX		153
#define DCLK_VOP		154
#define DCLK_CIF		155
#define DCLK_CIFLITE		156

/* aclk */
#define ACLK_PDBUS		160
#define ACLK_DMAC		161
#define ACLK_DCF		162
#define ACLK_SPINLOCK		163
#define ACLK_DECOM		164
#define ACLK_PDCRYPTO		165
#define ACLK_CRYPTO		166
#define ACLK_PDVEPU		167
#define ACLK_VENC		168
#define ACLK_PDVDEC		169
#define ACLK_PDJPEG		170
#define ACLK_VDEC		171
#define ACLK_JPEG		172
#define ACLK_PDVO		173
#define ACLK_RGA		174
#define ACLK_VOP		175
#define ACLK_IEP		176
#define ACLK_PDVI_DIV		177
#define ACLK_PDVI_NP5		178
#define ACLK_PDVI		179
#define ACLK_ISP		180
#define ACLK_CIF		181
#define ACLK_CIFLITE		182
#define ACLK_PDISPP_DIV		183
#define ACLK_PDISPP_NP5		184
#define ACLK_PDISPP		185
#define ACLK_ISPP		186
#define ACLK_PDPHP		187
#define ACLK_PDUSB		188
#define ACLK_USBOTG		189
#define ACLK_PDGMAC		190
#define ACLK_GMAC		191
#define ACLK_PDNPU_DIV		192
#define ACLK_PDNPU_NP5		193
#define ACLK_PDNPU		194
#define ACLK_NPU		195

/* hclk */
#define HCLK_PDCORE_NIU		200
#define HCLK_PDUSB		201
#define HCLK_PDCRYPTO		202
#define HCLK_CRYPTO		203
#define HCLK_PDAUDIO		204
#define HCLK_I2S0		205
#define HCLK_I2S1		206
#define HCLK_I2S2		207
#define HCLK_PDM		208
#define HCLK_AUDPWM		209
#define HCLK_PDVEPU		210
#define HCLK_VENC		211
#define HCLK_PDVDEC		212
#define HCLK_PDJPEG		213
#define HCLK_VDEC		214
#define HCLK_JPEG		215
#define HCLK_PDVO		216
#define HCLK_RGA		217
#define HCLK_VOP		218
#define HCLK_IEP		219
#define HCLK_PDVI		220
#define HCLK_ISP		221
#define HCLK_CIF		222
#define HCLK_CIFLITE		223
#define HCLK_PDISPP		224
#define HCLK_ISPP		225
#define HCLK_PDPHP		226
#define HCLK_PDSDMMC		227
#define HCLK_SDMMC		228
#define HCLK_PDSDIO		229
#define HCLK_SDIO		230
#define HCLK_PDNVM		231
#define HCLK_EMMC		232
#define HCLK_NANDC		233
#define HCLK_SFC		234
#define HCLK_SFCXIP		235
#define HCLK_PDBUS		236
#define HCLK_USBHOST		237
#define HCLK_USBHOST_ARB	238
#define HCLK_PDNPU		239
#define HCLK_NPU		240

/* pclk */
#define PCLK_CPUPVTM		245
#define PCLK_PDBUS		246
#define PCLK_DCF		247
#define PCLK_WDT		248
#define PCLK_MAILBOX		249
#define PCLK_UART0		250
#define PCLK_UART2		251
#define PCLK_UART3		252
#define PCLK_UART4		253
#define PCLK_UART5		254
#define PCLK_I2C1		255
#define PCLK_I2C3		256
#define PCLK_I2C4		257
#define PCLK_I2C5		258
#define PCLK_SPI1		259
#define PCLK_PWM2		261
#define PCLK_GPIO1		262
#define PCLK_GPIO2		263
#define PCLK_GPIO3		264
#define PCLK_GPIO4		265
#define PCLK_SARADC		266
#define PCLK_TIMER		267
#define PCLK_DECOM		268
#define PCLK_CAN		269
#define PCLK_NPU_TSADC		270
#define PCLK_CPU_TSADC		271
#define PCLK_ACDCDIG		272
#define PCLK_PDVO		273
#define PCLK_DSIHOST		274
#define PCLK_PDVI		275
#define PCLK_CSIHOST		276
#define PCLK_PDGMAC		277
#define PCLK_GMAC		278
#define PCLK_PDDDR		279
#define PCLK_DDR_MON		280
#define PCLK_PDNPU		281
#define PCLK_NPUPVTM		282
#define PCLK_PDTOP		283
#define PCLK_TOPCRU		284
#define PCLK_TOPGRF		285
#define PCLK_CPUEMADET		286
#define PCLK_DDRPHY		287
#define PCLK_DSIPHY		289
#define PCLK_CSIPHY0		290
#define PCLK_CSIPHY1		291
#define PCLK_USBPHY_HOST	292
#define PCLK_USBPHY_OTG		293
#define PCLK_OTP		294

#define CLK_NR_CLKS		(PCLK_OTP + 1)

/* pmu soft-reset indices */

/* pmu_cru_softrst_con0 */
#define SRST_PDPMU_NIU_P	0
#define SRST_PMU_SGRF_P		1
#define SRST_PMU_SGRF_REMAP_P	2
#define SRST_I2C0_P		3
#define SRST_I2C0		4
#define SRST_I2C2_P		7
#define SRST_I2C2		8
#define SRST_UART1_P		9
#define SRST_UART1		10
#define SRST_PWM0_P		11
#define SRST_PWM0		12
#define SRST_PWM1_P		13
#define SRST_PWM1		14
#define SRST_DDR_FAIL_SAFE	15

/* pmu_cru_softrst_con1 */
#define SRST_GPIO0_P		17
#define SRST_GPIO0_DB		18
#define SRST_SPI0_P		19
#define SRST_SPI0		20
#define SRST_PMUGRF_P		21
#define SRST_CHIPVEROTP_P	22
#define SRST_PMUPVTM		24
#define SRST_PMUPVTM_P		25
#define SRST_PMUCRU_P		30

/* soft-reset indices */

/* cru_softrst_con0 */
#define SRST_CORE0_PO		0
#define SRST_CORE1_PO		1
#define SRST_CORE2_PO		2
#define SRST_CORE3_PO		3
#define SRST_CORE0		4
#define SRST_CORE1		5
#define SRST_CORE2		6
#define SRST_CORE3		7
#define SRST_CORE0_DBG		8
#define SRST_CORE1_DBG		9
#define SRST_CORE2_DBG		10
#define SRST_CORE3_DBG		11
#define SRST_NL2		12
#define SRST_CORE_NIU_A		13
#define SRST_DBG_DAPLITE_P	14
#define SRST_DAPLITE_P		15

/* cru_softrst_con1 */
#define SRST_PDBUS_NIU1_A	16
#define SRST_PDBUS_NIU1_H	17
#define SRST_PDBUS_NIU1_P	18
#define SRST_PDBUS_NIU2_A	19
#define SRST_PDBUS_NIU2_H	20
#define SRST_PDBUS_NIU3_A	21
#define SRST_PDBUS_NIU3_H	22
#define SRST_PDBUS_HOLD_NIU1_A	23
#define SRST_DBG_NIU_P		24
#define SRST_PDCORE_NIIU_H	25
#define SRST_MUC_NIU		26
#define SRST_DCF_A		29
#define SRST_DCF_P		30
#define SRST_SYSTEM_SRAM_A	31

/* cru_softrst_con2 */
#define SRST_I2C1_P		32
#define SRST_I2C1		33
#define SRST_I2C3_P		34
#define SRST_I2C3		35
#define SRST_I2C4_P		36
#define SRST_I2C4		37
#define SRST_I2C5_P		38
#define SRST_I2C5		39
#define SRST_SPI1_P		40
#define SRST_SPI1		41
#define SRST_MCU_CORE		42
#define SRST_PWM2_P		44
#define SRST_PWM2		45
#define SRST_SPINLOCK_A		46

/* cru_softrst_con3 */
#define SRST_UART0_P		48
#define SRST_UART0		49
#define SRST_UART2_P		50
#define SRST_UART2		51
#define SRST_UART3_P		52
#define SRST_UART3		53
#define SRST_UART4_P		54
#define SRST_UART4		55
#define SRST_UART5_P		56
#define SRST_UART5		57
#define SRST_WDT_P		58
#define SRST_SARADC_P		59
#define SRST_GRF_P		61
#define SRST_TIMER_P		62
#define SRST_MAILBOX_P		63

/* cru_softrst_con4 */
#define SRST_TIMER0		64
#define SRST_TIMER1		65
#define SRST_TIMER2		66
#define SRST_TIMER3		67
#define SRST_TIMER4		68
#define SRST_TIMER5		69
#define SRST_INTMUX_P		70
#define SRST_GPIO1_P		72
#define SRST_GPIO1_DB		73
#define SRST_GPIO2_P		74
#define SRST_GPIO2_DB		75
#define SRST_GPIO3_P		76
#define SRST_GPIO3_DB		77
#define SRST_GPIO4_P		78
#define SRST_GPIO4_DB		79

/* cru_softrst_con5 */
#define SRST_CAN_P		80
#define SRST_CAN		81
#define SRST_DECOM_A		85
#define SRST_DECOM_P		86
#define SRST_DECOM_D		87
#define SRST_PDCRYPTO_NIU_A	88
#define SRST_PDCRYPTO_NIU_H	89
#define SRST_CRYPTO_A		90
#define SRST_CRYPTO_H		91
#define SRST_CRYPTO_CORE	92
#define SRST_CRYPTO_PKA		93
#define SRST_SGRF_P		95

/* cru_softrst_con6 */
#define SRST_PDAUDIO_NIU_H	96
#define SRST_PDAUDIO_NIU_P	97
#define SRST_I2S0_H		98
#define SRST_I2S0_TX_M		99
#define SRST_I2S0_RX_M		100
#define SRST_I2S1_H		101
#define SRST_I2S1_M		102
#define SRST_I2S2_H		103
#define SRST_I2S2_M		104
#define SRST_PDM_H		105
#define SRST_PDM_M		106
#define SRST_AUDPWM_H		107
#define SRST_AUDPWM		108
#define SRST_ACDCDIG_P		109
#define SRST_ACDCDIG		110

/* cru_softrst_con7 */
#define SRST_PDVEPU_NIU_A	112
#define SRST_PDVEPU_NIU_H	113
#define SRST_VENC_A		114
#define SRST_VENC_H		115
#define SRST_VENC_CORE		116
#define SRST_PDVDEC_NIU_A	117
#define SRST_PDVDEC_NIU_H	118
#define SRST_VDEC_A		119
#define SRST_VDEC_H		120
#define SRST_VDEC_CORE		121
#define SRST_VDEC_CA		122
#define SRST_VDEC_HEVC_CA	123
#define SRST_PDJPEG_NIU_A	124
#define SRST_PDJPEG_NIU_H	125
#define SRST_JPEG_A		126
#define SRST_JPEG_H		127

/* cru_softrst_con8 */
#define SRST_PDVO_NIU_A		128
#define SRST_PDVO_NIU_H		129
#define SRST_PDVO_NIU_P		130
#define SRST_RGA_A		131
#define SRST_RGA_H		132
#define SRST_RGA_CORE		133
#define SRST_VOP_A		134
#define SRST_VOP_H		135
#define SRST_VOP_D		136
#define SRST_TXBYTEHS_DSIHOST	137
#define SRST_DSIHOST_P		138
#define SRST_IEP_A		139
#define SRST_IEP_H		140
#define SRST_IEP_CORE		141
#define SRST_ISP_RX_P		142

/* cru_softrst_con9 */
#define SRST_PDVI_NIU_A		144
#define SRST_PDVI_NIU_H		145
#define SRST_PDVI_NIU_P		146
#define SRST_ISP		147
#define SRST_CIF_A		148
#define SRST_CIF_H		149
#define SRST_CIF_D		150
#define SRST_CIF_P		151
#define SRST_CIF_I		152
#define SRST_CIF_RX_P		153
#define SRST_PDISPP_NIU_A	154
#define SRST_PDISPP_NIU_H	155
#define SRST_ISPP_A		156
#define SRST_ISPP_H		157
#define SRST_ISPP		158
#define SRST_CSIHOST_P		159

/* cru_softrst_con10 */
#define SRST_PDPHPMID_NIU_A	160
#define SRST_PDPHPMID_NIU_H	161
#define SRST_PDNVM_NIU_H	163
#define SRST_SDMMC_H		164
#define SRST_SDIO_H		165
#define SRST_EMMC_H		166
#define SRST_SFC_H		167
#define SRST_SFCXIP_H		168
#define SRST_SFC		169
#define SRST_NANDC_H		170
#define SRST_NANDC		171
#define SRST_PDSDMMC_H		173
#define SRST_PDSDIO_H		174

/* cru_softrst_con11 */
#define SRST_PDUSB_NIU_A	176
#define SRST_PDUSB_NIU_H	177
#define SRST_USBHOST_H		178
#define SRST_USBHOST_ARB_H	179
#define SRST_USBHOST_UTMI	180
#define SRST_USBOTG_A		181
#define SRST_USBPHY_OTG_P	182
#define SRST_USBPHY_HOST_P	183
#define SRST_USBPHYPOR_OTG	184
#define SRST_USBPHYPOR_HOST	185
#define SRST_PDGMAC_NIU_A	188
#define SRST_PDGMAC_NIU_P	189
#define SRST_GMAC_A		190

/* cru_softrst_con12 */
#define SRST_DDR_DFICTL_P	193
#define SRST_DDR_MON_P		194
#define SRST_DDR_STANDBY_P	195
#define SRST_DDR_GRF_P		196
#define SRST_DDR_MSCH_P		197
#define SRST_DDR_SPLIT_A	198
#define SRST_DDR_MSCH		199
#define SRST_DDR_DFICTL		202
#define SRST_DDR_STANDBY	203
#define SRST_NPUMCU_NIU		205
#define SRST_DDRPHY_P		206
#define SRST_DDRPHY		207

/* cru_softrst_con13 */
#define SRST_PDNPU_NIU_A	208
#define SRST_PDNPU_NIU_H	209
#define SRST_PDNPU_NIU_P	210
#define SRST_NPU_A		211
#define SRST_NPU_H		212
#define SRST_NPU		213
#define SRST_NPUPVTM_P		214
#define SRST_NPUPVTM		215
#define SRST_NPU_TSADC_P	216
#define SRST_NPU_TSADC		217
#define SRST_NPU_TSADCPHY	218
#define SRST_CIFLITE_A		220
#define SRST_CIFLITE_H		221
#define SRST_CIFLITE_D		222
#define SRST_CIFLITE_RX_P	223

/* cru_softrst_con14 */
#define SRST_TOPNIU_P		224
#define SRST_TOPCRU_P		225
#define SRST_TOPGRF_P		226
#define SRST_CPUEMADET_P	227
#define SRST_CSIPHY0_P		228
#define SRST_CSIPHY1_P		229
#define SRST_DSIPHY_P		230
#define SRST_CPU_TSADC_P	232
#define SRST_CPU_TSADC		233
#define SRST_CPU_TSADCPHY	234
#define SRST_CPUPVTM_P		235
#define SRST_CPUPVTM		236

#endif
