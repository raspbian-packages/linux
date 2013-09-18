/* linux/arch/arm/mach-exynos/include/mach/map.h
 *
 * Copyright (c) 2010-2011 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com/
 *
 * EXYNOS4 - Memory map definitions
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#ifndef __ASM_ARCH_MAP_H
#define __ASM_ARCH_MAP_H __FILE__

#include <plat/map-base.h>

/*
 * EXYNOS4 UART offset is 0x10000 but the older S5P SoCs are 0x400.
 * So need to define it, and here is to avoid redefinition warning.
 */
#define S3C_UART_OFFSET			(0x10000)

#include <plat/map-s5p.h>

#define EXYNOS4_PA_SYSRAM0		0x02025000
#define EXYNOS4_PA_SYSRAM1		0x02020000

#define EXYNOS4_PA_FIMC0		0x11800000
#define EXYNOS4_PA_FIMC1		0x11810000
#define EXYNOS4_PA_FIMC2		0x11820000
#define EXYNOS4_PA_FIMC3		0x11830000

#define EXYNOS4_PA_I2S0			0x03830000
#define EXYNOS4_PA_I2S1			0xE3100000
#define EXYNOS4_PA_I2S2			0xE2A00000

#define EXYNOS4_PA_PCM0			0x03840000
#define EXYNOS4_PA_PCM1			0x13980000
#define EXYNOS4_PA_PCM2			0x13990000

#define EXYNOS4_PA_SROM_BANK(x)		(0x04000000 + ((x) * 0x01000000))

#define EXYNOS4_PA_ONENAND		0x0C000000
#define EXYNOS4_PA_ONENAND_DMA		0x0C600000

#define EXYNOS4_PA_CHIPID		0x10000000

#define EXYNOS4_PA_SYSCON		0x10010000
#define EXYNOS4_PA_PMU			0x10020000
#define EXYNOS4_PA_CMU			0x10030000

#define EXYNOS4_PA_SYSTIMER		0x10050000
#define EXYNOS4_PA_WATCHDOG		0x10060000
#define EXYNOS4_PA_RTC			0x10070000

#define EXYNOS4_PA_KEYPAD		0x100A0000

#define EXYNOS4_PA_DMC0			0x10400000

#define EXYNOS4_PA_COMBINER		0x10440000

#define EXYNOS4_PA_GIC_CPU		0x10480000
#define EXYNOS4_PA_GIC_DIST		0x10490000

#define EXYNOS4_PA_COREPERI		0x10500000
#define EXYNOS4_PA_TWD			0x10500600
#define EXYNOS4_PA_L2CC			0x10502000

#define EXYNOS4_PA_MDMA			0x10810000
#define EXYNOS4_PA_PDMA0		0x12680000
#define EXYNOS4_PA_PDMA1		0x12690000

#define EXYNOS4_PA_SYSMMU_MDMA		0x10A40000
#define EXYNOS4_PA_SYSMMU_SSS		0x10A50000
#define EXYNOS4_PA_SYSMMU_FIMC0		0x11A20000
#define EXYNOS4_PA_SYSMMU_FIMC1		0x11A30000
#define EXYNOS4_PA_SYSMMU_FIMC2		0x11A40000
#define EXYNOS4_PA_SYSMMU_FIMC3		0x11A50000
#define EXYNOS4_PA_SYSMMU_JPEG		0x11A60000
#define EXYNOS4_PA_SYSMMU_FIMD0		0x11E20000
#define EXYNOS4_PA_SYSMMU_FIMD1		0x12220000
#define EXYNOS4_PA_SYSMMU_PCIe		0x12620000
#define EXYNOS4_PA_SYSMMU_G2D		0x12A20000
#define EXYNOS4_PA_SYSMMU_ROTATOR	0x12A30000
#define EXYNOS4_PA_SYSMMU_MDMA2		0x12A40000
#define EXYNOS4_PA_SYSMMU_TV		0x12E20000
#define EXYNOS4_PA_SYSMMU_MFC_L		0x13620000
#define EXYNOS4_PA_SYSMMU_MFC_R		0x13630000

#define EXYNOS4_PA_GPIO1		0x11400000
#define EXYNOS4_PA_GPIO2		0x11000000
#define EXYNOS4_PA_GPIO3		0x03860000

#define EXYNOS4_PA_MIPI_CSIS0		0x11880000
#define EXYNOS4_PA_MIPI_CSIS1		0x11890000

#define EXYNOS4_PA_FIMD0		0x11C00000

#define EXYNOS4_PA_HSMMC(x)		(0x12510000 + ((x) * 0x10000))
#define EXYNOS4_PA_DWMCI		0x12550000

#define EXYNOS4_PA_SATA			0x12560000
#define EXYNOS4_PA_SATAPHY		0x125D0000
#define EXYNOS4_PA_SATAPHY_CTRL		0x126B0000

#define EXYNOS4_PA_SROMC		0x12570000

#define EXYNOS4_PA_EHCI			0x12580000
#define EXYNOS4_PA_HSPHY		0x125B0000
#define EXYNOS4_PA_MFC			0x13400000

#define EXYNOS4_PA_UART			0x13800000

#define EXYNOS4_PA_VP			0x12C00000
#define EXYNOS4_PA_MIXER		0x12C10000
#define EXYNOS4_PA_SDO			0x12C20000
#define EXYNOS4_PA_HDMI			0x12D00000
#define EXYNOS4_PA_IIC_HDMIPHY		0x138E0000

#define EXYNOS4_PA_IIC(x)		(0x13860000 + ((x) * 0x10000))

#define EXYNOS4_PA_ADC			0x13910000
#define EXYNOS4_PA_ADC1			0x13911000

#define EXYNOS4_PA_AC97			0x139A0000

#define EXYNOS4_PA_SPDIF		0x139B0000

#define EXYNOS4_PA_TIMER		0x139D0000

#define EXYNOS4_PA_SDRAM		0x40000000

/* Compatibiltiy Defines */

#define S3C_PA_HSMMC0			EXYNOS4_PA_HSMMC(0)
#define S3C_PA_HSMMC1			EXYNOS4_PA_HSMMC(1)
#define S3C_PA_HSMMC2			EXYNOS4_PA_HSMMC(2)
#define S3C_PA_HSMMC3			EXYNOS4_PA_HSMMC(3)
#define S3C_PA_IIC			EXYNOS4_PA_IIC(0)
#define S3C_PA_IIC1			EXYNOS4_PA_IIC(1)
#define S3C_PA_IIC2			EXYNOS4_PA_IIC(2)
#define S3C_PA_IIC3			EXYNOS4_PA_IIC(3)
#define S3C_PA_IIC4			EXYNOS4_PA_IIC(4)
#define S3C_PA_IIC5			EXYNOS4_PA_IIC(5)
#define S3C_PA_IIC6			EXYNOS4_PA_IIC(6)
#define S3C_PA_IIC7			EXYNOS4_PA_IIC(7)
#define S3C_PA_RTC			EXYNOS4_PA_RTC
#define S3C_PA_WDT			EXYNOS4_PA_WATCHDOG
#define S3C_PA_UART			EXYNOS4_PA_UART

#define S5P_PA_CHIPID			EXYNOS4_PA_CHIPID
#define S5P_PA_EHCI			EXYNOS4_PA_EHCI
#define S5P_PA_FIMC0			EXYNOS4_PA_FIMC0
#define S5P_PA_FIMC1			EXYNOS4_PA_FIMC1
#define S5P_PA_FIMC2			EXYNOS4_PA_FIMC2
#define S5P_PA_FIMC3			EXYNOS4_PA_FIMC3
#define S5P_PA_FIMD0			EXYNOS4_PA_FIMD0
#define S5P_PA_HDMI			EXYNOS4_PA_HDMI
#define S5P_PA_IIC_HDMIPHY		EXYNOS4_PA_IIC_HDMIPHY
#define S5P_PA_MFC			EXYNOS4_PA_MFC
#define S5P_PA_MIPI_CSIS0		EXYNOS4_PA_MIPI_CSIS0
#define S5P_PA_MIPI_CSIS1		EXYNOS4_PA_MIPI_CSIS1
#define S5P_PA_MIXER			EXYNOS4_PA_MIXER
#define S5P_PA_ONENAND			EXYNOS4_PA_ONENAND
#define S5P_PA_ONENAND_DMA		EXYNOS4_PA_ONENAND_DMA
#define S5P_PA_SDO			EXYNOS4_PA_SDO
#define S5P_PA_SDRAM			EXYNOS4_PA_SDRAM
#define S5P_PA_SROMC			EXYNOS4_PA_SROMC
#define S5P_PA_SYSCON			EXYNOS4_PA_SYSCON
#define S5P_PA_TIMER			EXYNOS4_PA_TIMER
#define S5P_PA_VP			EXYNOS4_PA_VP

#define SAMSUNG_PA_ADC			EXYNOS4_PA_ADC
#define SAMSUNG_PA_ADC1			EXYNOS4_PA_ADC1
#define SAMSUNG_PA_KEYPAD		EXYNOS4_PA_KEYPAD

#define EXYNOS_PA_COMBINER		EXYNOS4_PA_COMBINER
#define EXYNOS_PA_GIC_CPU		EXYNOS4_PA_GIC_CPU
#define EXYNOS_PA_GIC_DIST		EXYNOS4_PA_GIC_DIST
#define EXYNOS_PA_PMU			EXYNOS4_PA_PMU
#define EXYNOS_PA_SYSTIMER		EXYNOS4_PA_SYSTIMER

/* Compatibility UART */

#define S3C_VA_UARTx(x)			(S3C_VA_UART + ((x) * S3C_UART_OFFSET))

#define S5P_PA_UART(x)			(S3C_PA_UART + ((x) * S3C_UART_OFFSET))
#define S5P_PA_UART0			S5P_PA_UART(0)
#define S5P_PA_UART1			S5P_PA_UART(1)
#define S5P_PA_UART2			S5P_PA_UART(2)
#define S5P_PA_UART3			S5P_PA_UART(3)
#define S5P_PA_UART4			S5P_PA_UART(4)

#define S5P_SZ_UART			SZ_256

#endif /* __ASM_ARCH_MAP_H */
