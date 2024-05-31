/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2010-2015 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * Exynos - Power management unit definition
 *
 * Notice:
 * This is not a list of all Exynos Power Management Unit SFRs.
 * There are too many of them, not mentioning subtle differences
 * between SoCs. For now, put here only the used registers.
 */

#ifndef __LINUX_SOC_EXYNOS_REGS_PMU_H
#define __LINUX_SOC_EXYNOS_REGS_PMU_H __FILE__

#define S5P_CENTRAL_SEQ_CONFIGURATION		0x0200

#define S5P_CENTRAL_LOWPWR_CFG			(1 << 16)

#define S5P_CENTRAL_SEQ_OPTION			0x0208

#define S5P_USE_STANDBY_WFI0			(1 << 16)
#define S5P_USE_STANDBY_WFI1			(1 << 17)
#define S5P_USE_STANDBY_WFI2			(1 << 19)
#define S5P_USE_STANDBY_WFI3			(1 << 20)
#define S5P_USE_STANDBY_WFE0			(1 << 24)
#define S5P_USE_STANDBY_WFE1			(1 << 25)
#define S5P_USE_STANDBY_WFE2			(1 << 27)
#define S5P_USE_STANDBY_WFE3			(1 << 28)

#define S5P_USE_STANDBY_WFI_ALL \
	(S5P_USE_STANDBY_WFI0 | S5P_USE_STANDBY_WFI1 | \
	 S5P_USE_STANDBY_WFI2 | S5P_USE_STANDBY_WFI3 | \
	 S5P_USE_STANDBY_WFE0 | S5P_USE_STANDBY_WFE1 | \
	 S5P_USE_STANDBY_WFE2 | S5P_USE_STANDBY_WFE3)

#define S5P_USE_DELAYED_RESET_ASSERTION		BIT(12)

#define EXYNOS_CORE_PO_RESET(n)			((1 << 4) << n)
#define EXYNOS_WAKEUP_FROM_LOWPWR		(1 << 28)
#define EXYNOS_SWRESET				0x0400

#define S5P_WAKEUP_STAT				0x0600
/* Value for EXYNOS_EINT_WAKEUP_MASK disabling all external wakeup interrupts */
#define EXYNOS_EINT_WAKEUP_MASK_DISABLED	0xffffffff
#define EXYNOS_EINT_WAKEUP_MASK			0x0604
#define S5P_WAKEUP_MASK				0x0608
#define S5P_WAKEUP_MASK2				0x0614

/* MIPI_PHYn_CONTROL, valid for Exynos3250, Exynos4, Exynos5250 and Exynos5433 */
#define EXYNOS4_MIPI_PHY_CONTROL(n)		(0x0710 + (n) * 4)
/* Phy enable bit, common for all phy registers, not only MIPI */
#define EXYNOS4_PHY_ENABLE			(1 << 0)
#define EXYNOS4_MIPI_PHY_SRESETN		(1 << 1)
#define EXYNOS4_MIPI_PHY_MRESETN		(1 << 2)
#define EXYNOS4_MIPI_PHY_RESET_MASK		(3 << 1)

#define S5P_INFORM0				0x0800
#define S5P_INFORM1				0x0804
#define S5P_INFORM5				0x0814
#define S5P_INFORM6				0x0818
#define S5P_INFORM7				0x081C
#define S5P_PMU_SPARE2				0x0908
#define S5P_PMU_SPARE3				0x090C

#define EXYNOS_IROM_DATA2			0x0988
#define S5P_ARM_CORE0_LOWPWR			0x1000
#define S5P_DIS_IRQ_CORE0			0x1004
#define S5P_DIS_IRQ_CENTRAL0			0x1008
#define S5P_ARM_CORE1_LOWPWR			0x1010
#define S5P_DIS_IRQ_CORE1			0x1014
#define S5P_DIS_IRQ_CENTRAL1			0x1018
#define S5P_ARM_COMMON_LOWPWR			0x1080
#define S5P_L2_0_LOWPWR				0x10C0
#define S5P_L2_1_LOWPWR				0x10C4
#define S5P_CMU_ACLKSTOP_LOWPWR			0x1100
#define S5P_CMU_SCLKSTOP_LOWPWR			0x1104
#define S5P_CMU_RESET_LOWPWR			0x110C
#define S5P_APLL_SYSCLK_LOWPWR			0x1120
#define S5P_MPLL_SYSCLK_LOWPWR			0x1124
#define S5P_VPLL_SYSCLK_LOWPWR			0x1128
#define S5P_EPLL_SYSCLK_LOWPWR			0x112C
#define S5P_CMU_CLKSTOP_GPS_ALIVE_LOWPWR	0x1138
#define S5P_CMU_RESET_GPSALIVE_LOWPWR		0x113C
#define S5P_CMU_CLKSTOP_CAM_LOWPWR		0x1140
#define S5P_CMU_CLKSTOP_TV_LOWPWR		0x1144
#define S5P_CMU_CLKSTOP_MFC_LOWPWR		0x1148
#define S5P_CMU_CLKSTOP_G3D_LOWPWR		0x114C
#define S5P_CMU_CLKSTOP_LCD0_LOWPWR		0x1150
#define S5P_CMU_CLKSTOP_MAUDIO_LOWPWR		0x1158
#define S5P_CMU_CLKSTOP_GPS_LOWPWR		0x115C
#define S5P_CMU_RESET_CAM_LOWPWR		0x1160
#define S5P_CMU_RESET_TV_LOWPWR			0x1164
#define S5P_CMU_RESET_MFC_LOWPWR		0x1168
#define S5P_CMU_RESET_G3D_LOWPWR		0x116C
#define S5P_CMU_RESET_LCD0_LOWPWR		0x1170
#define S5P_CMU_RESET_MAUDIO_LOWPWR		0x1178
#define S5P_CMU_RESET_GPS_LOWPWR		0x117C
#define S5P_TOP_BUS_LOWPWR			0x1180
#define S5P_TOP_RETENTION_LOWPWR		0x1184
#define S5P_TOP_PWR_LOWPWR			0x1188
#define S5P_LOGIC_RESET_LOWPWR			0x11A0
#define S5P_ONENAND_MEM_LOWPWR			0x11C0
#define S5P_G2D_ACP_MEM_LOWPWR			0x11C8
#define S5P_USBOTG_MEM_LOWPWR			0x11CC
#define S5P_HSMMC_MEM_LOWPWR			0x11D0
#define S5P_CSSYS_MEM_LOWPWR			0x11D4
#define S5P_SECSS_MEM_LOWPWR			0x11D8
#define S5P_PAD_RETENTION_DRAM_LOWPWR		0x1200
#define S5P_PAD_RETENTION_MAUDIO_LOWPWR		0x1204
#define S5P_PAD_RETENTION_GPIO_LOWPWR		0x1220
#define S5P_PAD_RETENTION_UART_LOWPWR		0x1224
#define S5P_PAD_RETENTION_MMCA_LOWPWR		0x1228
#define S5P_PAD_RETENTION_MMCB_LOWPWR		0x122C
#define S5P_PAD_RETENTION_EBIA_LOWPWR		0x1230
#define S5P_PAD_RETENTION_EBIB_LOWPWR		0x1234
#define S5P_PAD_RETENTION_ISOLATION_LOWPWR	0x1240
#define S5P_PAD_RETENTION_ALV_SEL_LOWPWR	0x1260
#define S5P_XUSBXTI_LOWPWR			0x1280
#define S5P_XXTI_LOWPWR				0x1284
#define S5P_EXT_REGULATOR_LOWPWR		0x12C0
#define S5P_GPIO_MODE_LOWPWR			0x1300
#define S5P_GPIO_MODE_MAUDIO_LOWPWR		0x1340
#define S5P_CAM_LOWPWR				0x1380
#define S5P_TV_LOWPWR				0x1384
#define S5P_MFC_LOWPWR				0x1388
#define S5P_G3D_LOWPWR				0x138C
#define S5P_LCD0_LOWPWR				0x1390
#define S5P_MAUDIO_LOWPWR			0x1398
#define S5P_GPS_LOWPWR				0x139C
#define S5P_GPS_ALIVE_LOWPWR			0x13A0

#define EXYNOS_ARM_CORE0_CONFIGURATION		0x2000
#define EXYNOS_ARM_CORE_CONFIGURATION(_nr)	\
			(EXYNOS_ARM_CORE0_CONFIGURATION + (0x80 * (_nr)))
#define EXYNOS_ARM_CORE_STATUS(_nr)		\
			(EXYNOS_ARM_CORE_CONFIGURATION(_nr) + 0x4)
#define EXYNOS_ARM_CORE_OPTION(_nr)		\
			(EXYNOS_ARM_CORE_CONFIGURATION(_nr) + 0x8)

#define EXYNOS_ARM_COMMON_CONFIGURATION		0x2500
#define EXYNOS_COMMON_CONFIGURATION(_nr)	\
			(EXYNOS_ARM_COMMON_CONFIGURATION + (0x80 * (_nr)))
#define EXYNOS_COMMON_STATUS(_nr)		\
			(EXYNOS_COMMON_CONFIGURATION(_nr) + 0x4)
#define EXYNOS_COMMON_OPTION(_nr)		\
			(EXYNOS_COMMON_CONFIGURATION(_nr) + 0x8)

#define EXYNOS_ARM_L2_CONFIGURATION		0x2600
#define EXYNOS_L2_CONFIGURATION(_nr)		\
			(EXYNOS_ARM_L2_CONFIGURATION + ((_nr) * 0x80))
#define EXYNOS_L2_STATUS(_nr)			\
			(EXYNOS_L2_CONFIGURATION(_nr) + 0x4)
#define EXYNOS_L2_OPTION(_nr)			\
			(EXYNOS_L2_CONFIGURATION(_nr) + 0x8)

#define EXYNOS_L2_USE_RETENTION			BIT(4)

#define S5P_PAD_RET_MAUDIO_OPTION		0x3028
#define S5P_PAD_RET_MMC2_OPTION			0x30c8
#define S5P_PAD_RET_GPIO_OPTION			0x3108
#define S5P_PAD_RET_UART_OPTION			0x3128
#define S5P_PAD_RET_MMCA_OPTION			0x3148
#define S5P_PAD_RET_MMCB_OPTION			0x3168
#define S5P_PAD_RET_EBIA_OPTION			0x3188
#define S5P_PAD_RET_EBIB_OPTION			0x31A8
#define S5P_PAD_RET_SPI_OPTION			0x31c8

#define S5P_PS_HOLD_CONTROL			0x330C
#define S5P_PS_HOLD_EN				(1 << 31)
#define S5P_PS_HOLD_OUTPUT_HIGH			(3 << 8)

#define S5P_CAM_OPTION				0x3C08
#define S5P_MFC_OPTION				0x3C48
#define S5P_G3D_OPTION				0x3C68
#define S5P_LCD0_OPTION				0x3C88
#define S5P_LCD1_OPTION				0x3CA8
#define S5P_ISP_OPTION				S5P_LCD1_OPTION

#define S5P_CORE_LOCAL_PWR_EN			0x3
#define S5P_CORE_WAKEUP_FROM_LOCAL_CFG		(0x3 << 8)
#define S5P_CORE_AUTOWAKEUP_EN			(1 << 31)

/* Only for S5Pv210 */
#define S5PV210_EINT_WAKEUP_MASK	0xC004

/* Only for Exynos4210 */
#define S5P_CMU_CLKSTOP_LCD1_LOWPWR	0x1154
#define S5P_CMU_RESET_LCD1_LOWPWR	0x1174
#define S5P_MODIMIF_MEM_LOWPWR		0x11C4
#define S5P_PCIE_MEM_LOWPWR		0x11E0
#define S5P_SATA_MEM_LOWPWR		0x11E4
#define S5P_LCD1_LOWPWR			0x1394

/* Only for Exynos4x12 */
#define S5P_ISP_ARM_LOWPWR			0x1050
#define S5P_DIS_IRQ_ISP_ARM_LOCAL_LOWPWR	0x1054
#define S5P_DIS_IRQ_ISP_ARM_CENTRAL_LOWPWR	0x1058
#define S5P_CMU_ACLKSTOP_COREBLK_LOWPWR		0x1110
#define S5P_CMU_SCLKSTOP_COREBLK_LOWPWR		0x1114
#define S5P_CMU_RESET_COREBLK_LOWPWR		0x111C
#define S5P_MPLLUSER_SYSCLK_LOWPWR		0x1130
#define S5P_CMU_CLKSTOP_ISP_LOWPWR		0x1154
#define S5P_CMU_RESET_ISP_LOWPWR		0x1174
#define S5P_TOP_BUS_COREBLK_LOWPWR		0x1190
#define S5P_TOP_RETENTION_COREBLK_LOWPWR	0x1194
#define S5P_TOP_PWR_COREBLK_LOWPWR		0x1198
#define S5P_OSCCLK_GATE_LOWPWR			0x11A4
#define S5P_LOGIC_RESET_COREBLK_LOWPWR		0x11B0
#define S5P_OSCCLK_GATE_COREBLK_LOWPWR		0x11B4
#define S5P_HSI_MEM_LOWPWR			0x11C4
#define S5P_ROTATOR_MEM_LOWPWR			0x11DC
#define S5P_PAD_RETENTION_GPIO_COREBLK_LOWPWR	0x123C
#define S5P_PAD_ISOLATION_COREBLK_LOWPWR	0x1250
#define S5P_GPIO_MODE_COREBLK_LOWPWR		0x1320
#define S5P_TOP_ASB_RESET_LOWPWR		0x1344
#define S5P_TOP_ASB_ISOLATION_LOWPWR		0x1348
#define S5P_ISP_LOWPWR				0x1394
#define S5P_DRAM_FREQ_DOWN_LOWPWR		0x13B0
#define S5P_DDRPHY_DLLOFF_LOWPWR		0x13B4
#define S5P_CMU_SYSCLK_ISP_LOWPWR		0x13B8
#define S5P_CMU_SYSCLK_GPS_LOWPWR		0x13BC
#define S5P_LPDDR_PHY_DLL_LOCK_LOWPWR		0x13C0

#define S5P_ARM_L2_0_OPTION			0x2608
#define S5P_ARM_L2_1_OPTION			0x2628
#define S5P_ONENAND_MEM_OPTION			0x2E08
#define S5P_HSI_MEM_OPTION			0x2E28
#define S5P_G2D_ACP_MEM_OPTION			0x2E48
#define S5P_USBOTG_MEM_OPTION			0x2E68
#define S5P_HSMMC_MEM_OPTION			0x2E88
#define S5P_CSSYS_MEM_OPTION			0x2EA8
#define S5P_SECSS_MEM_OPTION			0x2EC8
#define S5P_ROTATOR_MEM_OPTION			0x2F48

/* Only for Exynos4412 */
#define S5P_ARM_CORE2_LOWPWR			0x1020
#define S5P_DIS_IRQ_CORE2			0x1024
#define S5P_DIS_IRQ_CENTRAL2			0x1028
#define S5P_ARM_CORE3_LOWPWR			0x1030
#define S5P_DIS_IRQ_CORE3			0x1034
#define S5P_DIS_IRQ_CENTRAL3			0x1038

/* Only for Exynos3XXX */
#define EXYNOS3_ARM_CORE0_SYS_PWR_REG			0x1000
#define EXYNOS3_DIS_IRQ_ARM_CORE0_LOCAL_SYS_PWR_REG	0x1004
#define EXYNOS3_DIS_IRQ_ARM_CORE0_CENTRAL_SYS_PWR_REG	0x1008
#define EXYNOS3_ARM_CORE1_SYS_PWR_REG			0x1010
#define EXYNOS3_DIS_IRQ_ARM_CORE1_LOCAL_SYS_PWR_REG	0x1014
#define EXYNOS3_DIS_IRQ_ARM_CORE1_CENTRAL_SYS_PWR_REG	0x1018
#define EXYNOS3_ISP_ARM_SYS_PWR_REG			0x1050
#define EXYNOS3_DIS_IRQ_ISP_ARM_LOCAL_SYS_PWR_REG	0x1054
#define EXYNOS3_DIS_IRQ_ISP_ARM_CENTRAL_SYS_PWR_REG	0x1058
#define EXYNOS3_ARM_COMMON_SYS_PWR_REG			0x1080
#define EXYNOS3_ARM_L2_SYS_PWR_REG			0x10C0
#define EXYNOS3_CMU_ACLKSTOP_SYS_PWR_REG		0x1100
#define EXYNOS3_CMU_SCLKSTOP_SYS_PWR_REG		0x1104
#define EXYNOS3_CMU_RESET_SYS_PWR_REG			0x110C
#define EXYNOS3_CMU_ACLKSTOP_COREBLK_SYS_PWR_REG	0x1110
#define EXYNOS3_CMU_SCLKSTOP_COREBLK_SYS_PWR_REG	0x1114
#define EXYNOS3_CMU_RESET_COREBLK_SYS_PWR_REG		0x111C
#define EXYNOS3_APLL_SYSCLK_SYS_PWR_REG			0x1120
#define EXYNOS3_MPLL_SYSCLK_SYS_PWR_REG			0x1124
#define EXYNOS3_VPLL_SYSCLK_SYS_PWR_REG			0x1128
#define EXYNOS3_EPLL_SYSCLK_SYS_PWR_REG			0x112C
#define EXYNOS3_MPLLUSER_SYSCLK_SYS_PWR_REG		0x1130
#define EXYNOS3_BPLLUSER_SYSCLK_SYS_PWR_REG		0x1134
#define EXYNOS3_EPLLUSER_SYSCLK_SYS_PWR_REG		0x1138
#define EXYNOS3_CMU_CLKSTOP_CAM_SYS_PWR_REG		0x1140
#define EXYNOS3_CMU_CLKSTOP_MFC_SYS_PWR_REG		0x1148
#define EXYNOS3_CMU_CLKSTOP_G3D_SYS_PWR_REG		0x114C
#define EXYNOS3_CMU_CLKSTOP_LCD0_SYS_PWR_REG		0x1150
#define EXYNOS3_CMU_CLKSTOP_ISP_SYS_PWR_REG		0x1154
#define EXYNOS3_CMU_CLKSTOP_MAUDIO_SYS_PWR_REG		0x1158
#define EXYNOS3_CMU_RESET_CAM_SYS_PWR_REG		0x1160
#define EXYNOS3_CMU_RESET_MFC_SYS_PWR_REG		0x1168
#define EXYNOS3_CMU_RESET_G3D_SYS_PWR_REG		0x116C
#define EXYNOS3_CMU_RESET_LCD0_SYS_PWR_REG		0x1170
#define EXYNOS3_CMU_RESET_ISP_SYS_PWR_REG		0x1174
#define EXYNOS3_CMU_RESET_MAUDIO_SYS_PWR_REG		0x1178
#define EXYNOS3_TOP_BUS_SYS_PWR_REG			0x1180
#define EXYNOS3_TOP_RETENTION_SYS_PWR_REG		0x1184
#define EXYNOS3_TOP_PWR_SYS_PWR_REG			0x1188
#define EXYNOS3_TOP_BUS_COREBLK_SYS_PWR_REG		0x1190
#define EXYNOS3_TOP_RETENTION_COREBLK_SYS_PWR_REG	0x1194
#define EXYNOS3_TOP_PWR_COREBLK_SYS_PWR_REG		0x1198
#define EXYNOS3_LOGIC_RESET_SYS_PWR_REG			0x11A0
#define EXYNOS3_OSCCLK_GATE_SYS_PWR_REG			0x11A4
#define EXYNOS3_LOGIC_RESET_COREBLK_SYS_PWR_REG		0x11B0
#define EXYNOS3_OSCCLK_GATE_COREBLK_SYS_PWR_REG		0x11B4
#define EXYNOS3_PAD_RETENTION_DRAM_SYS_PWR_REG		0x1200
#define EXYNOS3_PAD_RETENTION_MAUDIO_SYS_PWR_REG	0x1204
#define EXYNOS3_PAD_RETENTION_SPI_SYS_PWR_REG		0x1208
#define EXYNOS3_PAD_RETENTION_MMC2_SYS_PWR_REG		0x1218
#define EXYNOS3_PAD_RETENTION_GPIO_SYS_PWR_REG		0x1220
#define EXYNOS3_PAD_RETENTION_UART_SYS_PWR_REG		0x1224
#define EXYNOS3_PAD_RETENTION_MMC0_SYS_PWR_REG		0x1228
#define EXYNOS3_PAD_RETENTION_MMC1_SYS_PWR_REG		0x122C
#define EXYNOS3_PAD_RETENTION_EBIA_SYS_PWR_REG		0x1230
#define EXYNOS3_PAD_RETENTION_EBIB_SYS_PWR_REG		0x1234
#define EXYNOS3_PAD_RETENTION_JTAG_SYS_PWR_REG		0x1238
#define EXYNOS3_PAD_ISOLATION_SYS_PWR_REG		0x1240
#define EXYNOS3_PAD_ALV_SEL_SYS_PWR_REG			0x1260
#define EXYNOS3_XUSBXTI_SYS_PWR_REG			0x1280
#define EXYNOS3_XXTI_SYS_PWR_REG			0x1284
#define EXYNOS3_EXT_REGULATOR_SYS_PWR_REG		0x12C0
#define EXYNOS3_EXT_REGULATOR_COREBLK_SYS_PWR_REG	0x12C4
#define EXYNOS3_GPIO_MODE_SYS_PWR_REG			0x1300
#define EXYNOS3_GPIO_MODE_MAUDIO_SYS_PWR_REG		0x1340
#define EXYNOS3_TOP_ASB_RESET_SYS_PWR_REG		0x1344
#define EXYNOS3_TOP_ASB_ISOLATION_SYS_PWR_REG		0x1348
#define EXYNOS3_TOP_ASB_RESET_COREBLK_SYS_PWR_REG	0x1350
#define EXYNOS3_TOP_ASB_ISOLATION_COREBLK_SYS_PWR_REG	0x1354
#define EXYNOS3_CAM_SYS_PWR_REG				0x1380
#define EXYNOS3_MFC_SYS_PWR_REG				0x1388
#define EXYNOS3_G3D_SYS_PWR_REG				0x138C
#define EXYNOS3_LCD0_SYS_PWR_REG			0x1390
#define EXYNOS3_ISP_SYS_PWR_REG				0x1394
#define EXYNOS3_MAUDIO_SYS_PWR_REG			0x1398
#define EXYNOS3_DRAM_FREQ_DOWN_SYS_PWR_REG		0x13B0
#define EXYNOS3_DDRPHY_DLLOFF_SYS_PWR_REG		0x13B4
#define EXYNOS3_CMU_SYSCLK_ISP_SYS_PWR_REG		0x13B8
#define EXYNOS3_LPDDR_PHY_DLL_LOCK_SYS_PWR_REG		0x13C0
#define EXYNOS3_BPLL_SYSCLK_SYS_PWR_REG			0x13C4
#define EXYNOS3_UPLL_SYSCLK_SYS_PWR_REG			0x13C8

#define EXYNOS3_ARM_CORE0_OPTION			0x2008
#define EXYNOS3_ARM_CORE_OPTION(_nr)	\
			(EXYNOS3_ARM_CORE0_OPTION + ((_nr) * 0x80))

#define EXYNOS3_ARM_COMMON_OPTION			0x2408
#define EXYNOS3_ARM_L2_OPTION				0x2608
#define EXYNOS3_TOP_PWR_OPTION				0x2C48
#define EXYNOS3_CORE_TOP_PWR_OPTION			0x2CA8
#define EXYNOS3_XUSBXTI_DURATION			0x341C
#define EXYNOS3_XXTI_DURATION				0x343C
#define EXYNOS3_EXT_REGULATOR_DURATION			0x361C
#define EXYNOS3_EXT_REGULATOR_COREBLK_DURATION		0x363C
#define XUSBXTI_DURATION				0x00000BB8
#define XXTI_DURATION					XUSBXTI_DURATION
#define EXT_REGULATOR_DURATION				0x00001D4C
#define EXT_REGULATOR_COREBLK_DURATION			EXT_REGULATOR_DURATION

/* for XXX_OPTION */
#define EXYNOS3_OPTION_USE_SC_COUNTER			(1 << 0)
#define EXYNOS3_OPTION_USE_SC_FEEDBACK			(1 << 1)
#define EXYNOS3_OPTION_SKIP_DEACTIVATE_ACEACP_IN_PWDN	(1 << 7)

/* For Exynos5 */

#define EXYNOS5_AUTO_WDTRESET_DISABLE				0x0408
#define EXYNOS5_MASK_WDTRESET_REQUEST				0x040C
#define EXYNOS5_USBDRD_PHY_CONTROL				0x0704
#define EXYNOS5_DPTX_PHY_CONTROL				0x0720

#define EXYNOS5_USE_RETENTION			BIT(4)
#define EXYNOS5_SYS_WDTRESET					(1 << 20)

#define EXYNOS5_ARM_CORE0_SYS_PWR_REG				0x1000
#define EXYNOS5_DIS_IRQ_ARM_CORE0_LOCAL_SYS_PWR_REG		0x1004
#define EXYNOS5_DIS_IRQ_ARM_CORE0_CENTRAL_SYS_PWR_REG		0x1008
#define EXYNOS5_ARM_CORE1_SYS_PWR_REG				0x1010
#define EXYNOS5_DIS_IRQ_ARM_CORE1_LOCAL_SYS_PWR_REG		0x1014
#define EXYNOS5_DIS_IRQ_ARM_CORE1_CENTRAL_SYS_PWR_REG		0x1018
#define EXYNOS5_FSYS_ARM_SYS_PWR_REG				0x1040
#define EXYNOS5_DIS_IRQ_FSYS_ARM_CENTRAL_SYS_PWR_REG		0x1048
#define EXYNOS5_ISP_ARM_SYS_PWR_REG				0x1050
#define EXYNOS5_DIS_IRQ_ISP_ARM_LOCAL_SYS_PWR_REG		0x1054
#define EXYNOS5_DIS_IRQ_ISP_ARM_CENTRAL_SYS_PWR_REG		0x1058
#define EXYNOS5_ARM_COMMON_SYS_PWR_REG				0x1080
#define EXYNOS5_ARM_L2_SYS_PWR_REG				0x10C0
#define EXYNOS5_CMU_ACLKSTOP_SYS_PWR_REG			0x1100
#define EXYNOS5_CMU_SCLKSTOP_SYS_PWR_REG			0x1104
#define EXYNOS5_CMU_RESET_SYS_PWR_REG				0x110C
#define EXYNOS5_CMU_ACLKSTOP_SYSMEM_SYS_PWR_REG			0x1120
#define EXYNOS5_CMU_SCLKSTOP_SYSMEM_SYS_PWR_REG			0x1124
#define EXYNOS5_CMU_RESET_SYSMEM_SYS_PWR_REG			0x112C
#define EXYNOS5_DRAM_FREQ_DOWN_SYS_PWR_REG			0x1130
#define EXYNOS5_DDRPHY_DLLOFF_SYS_PWR_REG			0x1134
#define EXYNOS5_DDRPHY_DLLLOCK_SYS_PWR_REG			0x1138
#define EXYNOS5_APLL_SYSCLK_SYS_PWR_REG				0x1140
#define EXYNOS5_MPLL_SYSCLK_SYS_PWR_REG				0x1144
#define EXYNOS5_VPLL_SYSCLK_SYS_PWR_REG				0x1148
#define EXYNOS5_EPLL_SYSCLK_SYS_PWR_REG				0x114C
#define EXYNOS5_BPLL_SYSCLK_SYS_PWR_REG				0x1150
#define EXYNOS5_CPLL_SYSCLK_SYS_PWR_REG				0x1154
#define EXYNOS5_MPLLUSER_SYSCLK_SYS_PWR_REG			0x1164
#define EXYNOS5_BPLLUSER_SYSCLK_SYS_PWR_REG			0x1170
#define EXYNOS5_TOP_BUS_SYS_PWR_REG				0x1180
#define EXYNOS5_TOP_RETENTION_SYS_PWR_REG			0x1184
#define EXYNOS5_TOP_PWR_SYS_PWR_REG				0x1188
#define EXYNOS5_TOP_BUS_SYSMEM_SYS_PWR_REG			0x1190
#define EXYNOS5_TOP_RETENTION_SYSMEM_SYS_PWR_REG		0x1194
#define EXYNOS5_TOP_PWR_SYSMEM_SYS_PWR_REG			0x1198
#define EXYNOS5_LOGIC_RESET_SYS_PWR_REG				0x11A0
#define EXYNOS5_OSCCLK_GATE_SYS_PWR_REG				0x11A4
#define EXYNOS5_LOGIC_RESET_SYSMEM_SYS_PWR_REG			0x11B0
#define EXYNOS5_OSCCLK_GATE_SYSMEM_SYS_PWR_REG			0x11B4
#define EXYNOS5_USBOTG_MEM_SYS_PWR_REG				0x11C0
#define EXYNOS5_G2D_MEM_SYS_PWR_REG				0x11C8
#define EXYNOS5_USBDRD_MEM_SYS_PWR_REG				0x11CC
#define EXYNOS5_SDMMC_MEM_SYS_PWR_REG				0x11D0
#define EXYNOS5_CSSYS_MEM_SYS_PWR_REG				0x11D4
#define EXYNOS5_SECSS_MEM_SYS_PWR_REG				0x11D8
#define EXYNOS5_ROTATOR_MEM_SYS_PWR_REG				0x11DC
#define EXYNOS5_INTRAM_MEM_SYS_PWR_REG				0x11E0
#define EXYNOS5_INTROM_MEM_SYS_PWR_REG				0x11E4
#define EXYNOS5_JPEG_MEM_SYS_PWR_REG				0x11E8
#define EXYNOS5_HSI_MEM_SYS_PWR_REG				0x11EC
#define EXYNOS5_MCUIOP_MEM_SYS_PWR_REG				0x11F4
#define EXYNOS5_SATA_MEM_SYS_PWR_REG				0x11FC
#define EXYNOS5_PAD_RETENTION_DRAM_SYS_PWR_REG			0x1200
#define EXYNOS5_PAD_RETENTION_MAU_SYS_PWR_REG			0x1204
#define EXYNOS5_PAD_RETENTION_GPIO_SYS_PWR_REG			0x1220
#define EXYNOS5_PAD_RETENTION_UART_SYS_PWR_REG			0x1224
#define EXYNOS5_PAD_RETENTION_MMCA_SYS_PWR_REG			0x1228
#define EXYNOS5_PAD_RETENTION_MMCB_SYS_PWR_REG			0x122C
#define EXYNOS5_PAD_RETENTION_EBIA_SYS_PWR_REG			0x1230
#define EXYNOS5_PAD_RETENTION_EBIB_SYS_PWR_REG			0x1234
#define EXYNOS5_PAD_RETENTION_SPI_SYS_PWR_REG			0x1238
#define EXYNOS5_PAD_RETENTION_GPIO_SYSMEM_SYS_PWR_REG		0x123C
#define EXYNOS5_PAD_ISOLATION_SYS_PWR_REG			0x1240
#define EXYNOS5_PAD_ISOLATION_SYSMEM_SYS_PWR_REG		0x1250
#define EXYNOS5_PAD_ALV_SEL_SYS_PWR_REG				0x1260
#define EXYNOS5_XUSBXTI_SYS_PWR_REG				0x1280
#define EXYNOS5_XXTI_SYS_PWR_REG				0x1284
#define EXYNOS5_EXT_REGULATOR_SYS_PWR_REG			0x12C0
#define EXYNOS5_GPIO_MODE_SYS_PWR_REG				0x1300
#define EXYNOS5_GPIO_MODE_SYSMEM_SYS_PWR_REG			0x1320
#define EXYNOS5_GPIO_MODE_MAU_SYS_PWR_REG			0x1340
#define EXYNOS5_TOP_ASB_RESET_SYS_PWR_REG			0x1344
#define EXYNOS5_TOP_ASB_ISOLATION_SYS_PWR_REG			0x1348
#define EXYNOS5_GSCL_SYS_PWR_REG				0x1400
#define EXYNOS5_ISP_SYS_PWR_REG					0x1404
#define EXYNOS5_MFC_SYS_PWR_REG					0x1408
#define EXYNOS5_G3D_SYS_PWR_REG					0x140C
#define EXYNOS5_DISP1_SYS_PWR_REG				0x1414
#define EXYNOS5_MAU_SYS_PWR_REG					0x1418
#define EXYNOS5_CMU_CLKSTOP_GSCL_SYS_PWR_REG			0x1480
#define EXYNOS5_CMU_CLKSTOP_ISP_SYS_PWR_REG			0x1484
#define EXYNOS5_CMU_CLKSTOP_MFC_SYS_PWR_REG			0x1488
#define EXYNOS5_CMU_CLKSTOP_G3D_SYS_PWR_REG			0x148C
#define EXYNOS5_CMU_CLKSTOP_DISP1_SYS_PWR_REG			0x1494
#define EXYNOS5_CMU_CLKSTOP_MAU_SYS_PWR_REG			0x1498
#define EXYNOS5_CMU_SYSCLK_GSCL_SYS_PWR_REG			0x14C0
#define EXYNOS5_CMU_SYSCLK_ISP_SYS_PWR_REG			0x14C4
#define EXYNOS5_CMU_SYSCLK_MFC_SYS_PWR_REG			0x14C8
#define EXYNOS5_CMU_SYSCLK_G3D_SYS_PWR_REG			0x14CC
#define EXYNOS5_CMU_SYSCLK_DISP1_SYS_PWR_REG			0x14D4
#define EXYNOS5_CMU_SYSCLK_MAU_SYS_PWR_REG			0x14D8
#define EXYNOS5_CMU_RESET_GSCL_SYS_PWR_REG			0x1580
#define EXYNOS5_CMU_RESET_ISP_SYS_PWR_REG			0x1584
#define EXYNOS5_CMU_RESET_MFC_SYS_PWR_REG			0x1588
#define EXYNOS5_CMU_RESET_G3D_SYS_PWR_REG			0x158C
#define EXYNOS5_CMU_RESET_DISP1_SYS_PWR_REG			0x1594
#define EXYNOS5_CMU_RESET_MAU_SYS_PWR_REG			0x1598

#define EXYNOS5_ARM_CORE0_OPTION				0x2008
#define EXYNOS5_ARM_CORE1_OPTION				0x2088
#define EXYNOS5_FSYS_ARM_OPTION					0x2208
#define EXYNOS5_ISP_ARM_OPTION					0x2288
#define EXYNOS5_ARM_COMMON_OPTION				0x2408
#define EXYNOS5_ARM_L2_OPTION					0x2608
#define EXYNOS5_TOP_PWR_OPTION					0x2C48
#define EXYNOS5_TOP_PWR_SYSMEM_OPTION				0x2CC8
#define EXYNOS5_JPEG_MEM_OPTION					0x2F48
#define EXYNOS5_GSCL_OPTION					0x4008
#define EXYNOS5_ISP_OPTION					0x4028
#define EXYNOS5_MFC_OPTION					0x4048
#define EXYNOS5_G3D_OPTION					0x4068
#define EXYNOS5_DISP1_OPTION					0x40A8
#define EXYNOS5_MAU_OPTION					0x40C8

#define EXYNOS5_USE_SC_FEEDBACK					(1 << 1)
#define EXYNOS5_USE_SC_COUNTER					(1 << 0)

#define EXYNOS5_SKIP_DEACTIVATE_ACEACP_IN_PWDN			(1 << 7)

#define EXYNOS5_OPTION_USE_STANDBYWFE				(1 << 24)
#define EXYNOS5_OPTION_USE_STANDBYWFI				(1 << 16)

#define EXYNOS5_OPTION_USE_RETENTION				(1 << 4)

#define EXYNOS5420_SWRESET_KFC_SEL				0x3

/* Only for Exynos5420 */
#define EXYNOS5420_L2RSTDISABLE_VALUE				BIT(3)

#define EXYNOS5420_LPI_MASK					0x0004
#define EXYNOS5420_LPI_MASK1					0x0008
#define EXYNOS5420_UFS						BIT(8)
#define EXYNOS5420_ATB_KFC					BIT(13)
#define EXYNOS5420_ATB_ISP_ARM					BIT(19)
#define EXYNOS5420_EMULATION					BIT(31)

#define EXYNOS5420_ARM_INTR_SPREAD_ENABLE			0x0100
#define EXYNOS5420_ARM_INTR_SPREAD_USE_STANDBYWFI		0x0104
#define EXYNOS5420_UP_SCHEDULER					0x0120
#define SPREAD_ENABLE						0xF
#define SPREAD_USE_STANDWFI					0xF

#define EXYNOS5420_KFC_CORE_RESET0				BIT(8)
#define EXYNOS5420_KFC_ETM_RESET0				BIT(20)

#define EXYNOS5420_KFC_CORE_RESET(_nr)				\
	((EXYNOS5420_KFC_CORE_RESET0 | EXYNOS5420_KFC_ETM_RESET0) << (_nr))

#define EXYNOS5420_USBDRD1_PHY_CONTROL				0x0708
#define EXYNOS5420_MIPI_PHY_CONTROL(n)				(0x0714 + (n) * 4)
#define EXYNOS5420_DPTX_PHY_CONTROL				0x0728
#define EXYNOS5420_ARM_CORE2_SYS_PWR_REG			0x1020
#define EXYNOS5420_DIS_IRQ_ARM_CORE2_LOCAL_SYS_PWR_REG		0x1024
#define EXYNOS5420_DIS_IRQ_ARM_CORE2_CENTRAL_SYS_PWR_REG	0x1028
#define EXYNOS5420_ARM_CORE3_SYS_PWR_REG			0x1030
#define EXYNOS5420_DIS_IRQ_ARM_CORE3_LOCAL_SYS_PWR_REG		0x1034
#define EXYNOS5420_DIS_IRQ_ARM_CORE3_CENTRAL_SYS_PWR_REG	0x1038
#define EXYNOS5420_KFC_CORE0_SYS_PWR_REG			0x1040
#define EXYNOS5420_DIS_IRQ_KFC_CORE0_LOCAL_SYS_PWR_REG		0x1044
#define EXYNOS5420_DIS_IRQ_KFC_CORE0_CENTRAL_SYS_PWR_REG	0x1048
#define EXYNOS5420_KFC_CORE1_SYS_PWR_REG			0x1050
#define EXYNOS5420_DIS_IRQ_KFC_CORE1_LOCAL_SYS_PWR_REG		0x1054
#define EXYNOS5420_DIS_IRQ_KFC_CORE1_CENTRAL_SYS_PWR_REG	0x1058
#define EXYNOS5420_KFC_CORE2_SYS_PWR_REG			0x1060
#define EXYNOS5420_DIS_IRQ_KFC_CORE2_LOCAL_SYS_PWR_REG		0x1064
#define EXYNOS5420_DIS_IRQ_KFC_CORE2_CENTRAL_SYS_PWR_REG	0x1068
#define EXYNOS5420_KFC_CORE3_SYS_PWR_REG			0x1070
#define EXYNOS5420_DIS_IRQ_KFC_CORE3_LOCAL_SYS_PWR_REG		0x1074
#define EXYNOS5420_DIS_IRQ_KFC_CORE3_CENTRAL_SYS_PWR_REG	0x1078
#define EXYNOS5420_ISP_ARM_SYS_PWR_REG				0x1090
#define EXYNOS5420_DIS_IRQ_ISP_ARM_LOCAL_SYS_PWR_REG		0x1094
#define EXYNOS5420_DIS_IRQ_ISP_ARM_CENTRAL_SYS_PWR_REG		0x1098
#define EXYNOS5420_ARM_COMMON_SYS_PWR_REG			0x10A0
#define EXYNOS5420_KFC_COMMON_SYS_PWR_REG			0x10B0
#define EXYNOS5420_KFC_L2_SYS_PWR_REG				0x10D0
#define EXYNOS5420_DPLL_SYSCLK_SYS_PWR_REG			0x1158
#define EXYNOS5420_IPLL_SYSCLK_SYS_PWR_REG			0x115C
#define EXYNOS5420_KPLL_SYSCLK_SYS_PWR_REG			0x1160
#define EXYNOS5420_RPLL_SYSCLK_SYS_PWR_REG                      0x1174
#define EXYNOS5420_SPLL_SYSCLK_SYS_PWR_REG                      0x1178
#define EXYNOS5420_INTRAM_MEM_SYS_PWR_REG                       0x11B8
#define EXYNOS5420_INTROM_MEM_SYS_PWR_REG                       0x11BC
#define EXYNOS5420_PAD_RETENTION_JTAG_SYS_PWR_REG		0x1208
#define EXYNOS5420_PAD_RETENTION_DRAM_SYS_PWR_REG		0x1210
#define EXYNOS5420_PAD_RETENTION_UART_SYS_PWR_REG		0x1214
#define EXYNOS5420_PAD_RETENTION_MMC0_SYS_PWR_REG		0x1218
#define EXYNOS5420_PAD_RETENTION_MMC1_SYS_PWR_REG		0x121C
#define EXYNOS5420_PAD_RETENTION_MMC2_SYS_PWR_REG		0x1220
#define EXYNOS5420_PAD_RETENTION_HSI_SYS_PWR_REG		0x1224
#define EXYNOS5420_PAD_RETENTION_EBIA_SYS_PWR_REG		0x1228
#define EXYNOS5420_PAD_RETENTION_EBIB_SYS_PWR_REG		0x122C
#define EXYNOS5420_PAD_RETENTION_SPI_SYS_PWR_REG		0x1230
#define EXYNOS5420_PAD_RETENTION_DRAM_COREBLK_SYS_PWR_REG	0x1234
#define EXYNOS5420_DISP1_SYS_PWR_REG				0x1410
#define EXYNOS5420_MAU_SYS_PWR_REG				0x1414
#define EXYNOS5420_G2D_SYS_PWR_REG				0x1418
#define EXYNOS5420_MSC_SYS_PWR_REG				0x141C
#define EXYNOS5420_FSYS_SYS_PWR_REG				0x1420
#define EXYNOS5420_FSYS2_SYS_PWR_REG				0x1424
#define EXYNOS5420_PSGEN_SYS_PWR_REG				0x1428
#define EXYNOS5420_PERIC_SYS_PWR_REG				0x142C
#define EXYNOS5420_WCORE_SYS_PWR_REG				0x1430
#define EXYNOS5420_CMU_CLKSTOP_DISP1_SYS_PWR_REG		0x1490
#define EXYNOS5420_CMU_CLKSTOP_MAU_SYS_PWR_REG			0x1494
#define EXYNOS5420_CMU_CLKSTOP_G2D_SYS_PWR_REG			0x1498
#define EXYNOS5420_CMU_CLKSTOP_MSC_SYS_PWR_REG			0x149C
#define EXYNOS5420_CMU_CLKSTOP_FSYS_SYS_PWR_REG			0x14A0
#define EXYNOS5420_CMU_CLKSTOP_FSYS2_SYS_PWR_REG		0x14A4
#define EXYNOS5420_CMU_CLKSTOP_PSGEN_SYS_PWR_REG		0x14A8
#define EXYNOS5420_CMU_CLKSTOP_PERIC_SYS_PWR_REG		0x14AC
#define EXYNOS5420_CMU_CLKSTOP_WCORE_SYS_PWR_REG		0x14B0
#define EXYNOS5420_CMU_SYSCLK_TOPPWR_SYS_PWR_REG		0x14BC
#define EXYNOS5420_CMU_SYSCLK_DISP1_SYS_PWR_REG			0x14D0
#define EXYNOS5420_CMU_SYSCLK_MAU_SYS_PWR_REG			0x14D4
#define EXYNOS5420_CMU_SYSCLK_G2D_SYS_PWR_REG			0x14D8
#define EXYNOS5420_CMU_SYSCLK_MSC_SYS_PWR_REG			0x14DC
#define EXYNOS5420_CMU_SYSCLK_FSYS_SYS_PWR_REG			0x14E0
#define EXYNOS5420_CMU_SYSCLK_FSYS2_SYS_PWR_REG			0x14E4
#define EXYNOS5420_CMU_SYSCLK_PSGEN_SYS_PWR_REG			0x14E8
#define EXYNOS5420_CMU_SYSCLK_PERIC_SYS_PWR_REG			0x14EC
#define EXYNOS5420_CMU_SYSCLK_WCORE_SYS_PWR_REG			0x14F0
#define EXYNOS5420_CMU_SYSCLK_SYSMEM_TOPPWR_SYS_PWR_REG		0x14F4
#define EXYNOS5420_CMU_RESET_FSYS2_SYS_PWR_REG			0x1570
#define EXYNOS5420_CMU_RESET_PSGEN_SYS_PWR_REG			0x1574
#define EXYNOS5420_CMU_RESET_PERIC_SYS_PWR_REG			0x1578
#define EXYNOS5420_CMU_RESET_WCORE_SYS_PWR_REG			0x157C
#define EXYNOS5420_CMU_RESET_DISP1_SYS_PWR_REG			0x1590
#define EXYNOS5420_CMU_RESET_MAU_SYS_PWR_REG			0x1594
#define EXYNOS5420_CMU_RESET_G2D_SYS_PWR_REG			0x1598
#define EXYNOS5420_CMU_RESET_MSC_SYS_PWR_REG			0x159C
#define EXYNOS5420_CMU_RESET_FSYS_SYS_PWR_REG			0x15A0
#define EXYNOS5420_SFR_AXI_CGDIS1				0x15E4
#define EXYNOS5420_ARM_COMMON_OPTION				0x2508
#define EXYNOS5420_KFC_COMMON_OPTION				0x2588
#define EXYNOS5420_LOGIC_RESET_DURATION3			0x2D1C

#define EXYNOS5420_PAD_RET_GPIO_OPTION				0x30C8
#define EXYNOS5420_PAD_RET_UART_OPTION				0x30E8
#define EXYNOS5420_PAD_RET_MMCA_OPTION				0x3108
#define EXYNOS5420_PAD_RET_MMCB_OPTION				0x3128
#define EXYNOS5420_PAD_RET_MMCC_OPTION				0x3148
#define EXYNOS5420_PAD_RET_HSI_OPTION				0x3168
#define EXYNOS5420_PAD_RET_SPI_OPTION				0x31C8
#define EXYNOS5420_PAD_RET_DRAM_COREBLK_OPTION			0x31E8
#define EXYNOS_PAD_RET_DRAM_OPTION				0x3008
#define EXYNOS_PAD_RET_MAUDIO_OPTION				0x3028
#define EXYNOS_PAD_RET_JTAG_OPTION				0x3048
#define EXYNOS_PAD_RET_EBIA_OPTION				0x3188
#define EXYNOS_PAD_RET_EBIB_OPTION				0x31A8

#define EXYNOS5420_FSYS2_OPTION					0x4168
#define EXYNOS5420_PSGEN_OPTION					0x4188

#define EXYNOS5420_ARM_USE_STANDBY_WFI0				BIT(4)
#define EXYNOS5420_ARM_USE_STANDBY_WFI1				BIT(5)
#define EXYNOS5420_ARM_USE_STANDBY_WFI2				BIT(6)
#define EXYNOS5420_ARM_USE_STANDBY_WFI3				BIT(7)
#define EXYNOS5420_KFC_USE_STANDBY_WFI0				BIT(8)
#define EXYNOS5420_KFC_USE_STANDBY_WFI1				BIT(9)
#define EXYNOS5420_KFC_USE_STANDBY_WFI2				BIT(10)
#define EXYNOS5420_KFC_USE_STANDBY_WFI3				BIT(11)
#define EXYNOS5420_ARM_USE_STANDBY_WFE0				BIT(16)
#define EXYNOS5420_ARM_USE_STANDBY_WFE1				BIT(17)
#define EXYNOS5420_ARM_USE_STANDBY_WFE2				BIT(18)
#define EXYNOS5420_ARM_USE_STANDBY_WFE3				BIT(19)
#define EXYNOS5420_KFC_USE_STANDBY_WFE0				BIT(20)
#define EXYNOS5420_KFC_USE_STANDBY_WFE1				BIT(21)
#define EXYNOS5420_KFC_USE_STANDBY_WFE2				BIT(22)
#define EXYNOS5420_KFC_USE_STANDBY_WFE3				BIT(23)

#define DUR_WAIT_RESET				0xF

#define EXYNOS5420_USE_STANDBY_WFI_ALL	(EXYNOS5420_ARM_USE_STANDBY_WFI0    \
					 | EXYNOS5420_ARM_USE_STANDBY_WFI1  \
					 | EXYNOS5420_ARM_USE_STANDBY_WFI2  \
					 | EXYNOS5420_ARM_USE_STANDBY_WFI3  \
					 | EXYNOS5420_KFC_USE_STANDBY_WFI0  \
					 | EXYNOS5420_KFC_USE_STANDBY_WFI1  \
					 | EXYNOS5420_KFC_USE_STANDBY_WFI2  \
					 | EXYNOS5420_KFC_USE_STANDBY_WFI3)

/* For Exynos5433 */
#define EXYNOS5433_EINT_WAKEUP_MASK				(0x060C)
#define EXYNOS5433_USBHOST30_PHY_CONTROL			(0x0728)
#define EXYNOS5433_PAD_RETENTION_AUD_OPTION			(0x3028)
#define EXYNOS5433_PAD_RETENTION_MMC2_OPTION			(0x30C8)
#define EXYNOS5433_PAD_RETENTION_TOP_OPTION			(0x3108)
#define EXYNOS5433_PAD_RETENTION_UART_OPTION			(0x3128)
#define EXYNOS5433_PAD_RETENTION_MMC0_OPTION			(0x3148)
#define EXYNOS5433_PAD_RETENTION_MMC1_OPTION			(0x3168)
#define EXYNOS5433_PAD_RETENTION_EBIA_OPTION			(0x3188)
#define EXYNOS5433_PAD_RETENTION_EBIB_OPTION			(0x31A8)
#define EXYNOS5433_PAD_RETENTION_SPI_OPTION			(0x31C8)
#define EXYNOS5433_PAD_RETENTION_MIF_OPTION			(0x31E8)
#define EXYNOS5433_PAD_RETENTION_USBXTI_OPTION			(0x3228)
#define EXYNOS5433_PAD_RETENTION_BOOTLDO_OPTION			(0x3248)
#define EXYNOS5433_PAD_RETENTION_UFS_OPTION			(0x3268)
#define EXYNOS5433_PAD_RETENTION_FSYSGENIO_OPTION		(0x32A8)

#endif /* __LINUX_SOC_EXYNOS_REGS_PMU_H */
