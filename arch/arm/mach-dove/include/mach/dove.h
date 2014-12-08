/*
 * arch/arm/mach-dove/include/mach/dove.h
 *
 * Generic definitions for Marvell Dove 88AP510 SoC
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef __ASM_ARCH_DOVE_H
#define __ASM_ARCH_DOVE_H

/*
 * Marvell Dove address maps.
 *
 * phys		virt		size
 * c8000000	fdb00000	1M	Cryptographic SRAM
 * e0000000	@runtime	128M	PCIe-0 Memory space
 * e8000000	@runtime	128M	PCIe-1 Memory space
 * f1000000	fde00000	8M	on-chip south-bridge registers
 * f1800000	fe600000	8M	on-chip north-bridge registers
 * f2000000	fee00000	1M	PCIe-0 I/O space
 * f2100000	fef00000	1M	PCIe-1 I/O space
 */

#define DOVE_CESA_PHYS_BASE		0xc8000000
#define DOVE_CESA_VIRT_BASE		IOMEM(0xfdb00000)
#define DOVE_CESA_SIZE			SZ_1M

#define DOVE_PCIE0_MEM_PHYS_BASE	0xe0000000
#define DOVE_PCIE0_MEM_SIZE		SZ_128M

#define DOVE_PCIE1_MEM_PHYS_BASE	0xe8000000
#define DOVE_PCIE1_MEM_SIZE		SZ_128M

#define DOVE_BOOTROM_PHYS_BASE		0xf8000000
#define DOVE_BOOTROM_SIZE		SZ_128M

#define DOVE_SCRATCHPAD_PHYS_BASE	0xf0000000
#define DOVE_SCRATCHPAD_VIRT_BASE	IOMEM(0xfdd00000)
#define DOVE_SCRATCHPAD_SIZE		SZ_1M

#define DOVE_SB_REGS_PHYS_BASE		0xf1000000
#define DOVE_SB_REGS_VIRT_BASE		IOMEM(0xfde00000)
#define DOVE_SB_REGS_SIZE		SZ_8M

#define DOVE_NB_REGS_PHYS_BASE		0xf1800000
#define DOVE_NB_REGS_VIRT_BASE		IOMEM(0xfe600000)
#define DOVE_NB_REGS_SIZE		SZ_8M

#define DOVE_PCIE0_IO_PHYS_BASE		0xf2000000
#define DOVE_PCIE0_IO_BUS_BASE		0x00000000
#define DOVE_PCIE0_IO_SIZE		SZ_64K

#define DOVE_PCIE1_IO_PHYS_BASE		0xf2100000
#define DOVE_PCIE1_IO_BUS_BASE		0x00010000
#define DOVE_PCIE1_IO_SIZE		SZ_64K

/*
 * Dove Core Registers Map
 */

/* SPI, I2C, UART */
#define DOVE_I2C_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0x11000)
#define DOVE_UART0_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0x12000)
#define DOVE_UART0_VIRT_BASE	(DOVE_SB_REGS_VIRT_BASE + 0x12000)
#define DOVE_UART1_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0x12100)
#define DOVE_UART1_VIRT_BASE	(DOVE_SB_REGS_VIRT_BASE + 0x12100)
#define DOVE_UART2_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0x12200)
#define DOVE_UART2_VIRT_BASE	(DOVE_SB_REGS_VIRT_BASE + 0x12200)
#define DOVE_UART3_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0x12300)
#define DOVE_UART3_VIRT_BASE	(DOVE_SB_REGS_VIRT_BASE + 0x12300)
#define DOVE_SPI0_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0x10600)
#define DOVE_SPI1_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0x14600)

/* North-South Bridge */
#define BRIDGE_VIRT_BASE	(DOVE_SB_REGS_VIRT_BASE + 0x20000)
#define BRIDGE_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0x20000)
#define  BRIDGE_WINS_BASE       (BRIDGE_PHYS_BASE)
#define  BRIDGE_WINS_SZ         (0x80)

/* Cryptographic Engine */
#define DOVE_CRYPT_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0x30000)

/* PCIe 0 */
#define DOVE_PCIE0_VIRT_BASE	(DOVE_SB_REGS_VIRT_BASE + 0x40000)

/* USB */
#define DOVE_USB0_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0x50000)
#define DOVE_USB1_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0x51000)

/* XOR 0 Engine */
#define DOVE_XOR0_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0x60800)
#define DOVE_XOR0_VIRT_BASE	(DOVE_SB_REGS_VIRT_BASE + 0x60800)
#define DOVE_XOR0_HIGH_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0x60A00)
#define DOVE_XOR0_HIGH_VIRT_BASE	(DOVE_SB_REGS_VIRT_BASE + 0x60A00)

/* XOR 1 Engine */
#define DOVE_XOR1_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0x60900)
#define DOVE_XOR1_VIRT_BASE	(DOVE_SB_REGS_VIRT_BASE + 0x60900)
#define DOVE_XOR1_HIGH_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0x60B00)
#define DOVE_XOR1_HIGH_VIRT_BASE	(DOVE_SB_REGS_VIRT_BASE + 0x60B00)

/* Gigabit Ethernet */
#define DOVE_GE00_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0x70000)

/* PCIe 1 */
#define DOVE_PCIE1_VIRT_BASE	(DOVE_SB_REGS_VIRT_BASE + 0x80000)

/* CAFE */
#define DOVE_SDIO0_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0x92000)
#define DOVE_SDIO1_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0x90000)
#define DOVE_CAM_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0x94000)
#define DOVE_CAFE_WIN_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0x98000)

/* SATA */
#define DOVE_SATA_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0xa0000)

/* I2S/SPDIF */
#define DOVE_AUD0_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0xb0000)
#define DOVE_AUD1_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0xb4000)

/* NAND Flash Controller */
#define DOVE_NFC_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0xc0000)

/* MPP, GPIO, Reset Sampling */
#define DOVE_MPP_VIRT_BASE	(DOVE_SB_REGS_VIRT_BASE + 0xd0200)
#define DOVE_PMU_MPP_GENERAL_CTRL (DOVE_MPP_VIRT_BASE + 0x10)
#define DOVE_RESET_SAMPLE_LO	(DOVE_MPP_VIRT_BASE + 0x014)
#define DOVE_RESET_SAMPLE_HI	(DOVE_MPP_VIRT_BASE + 0x018)
#define DOVE_GPIO_LO_VIRT_BASE	(DOVE_SB_REGS_VIRT_BASE + 0xd0400)
#define DOVE_GPIO_HI_VIRT_BASE	(DOVE_SB_REGS_VIRT_BASE + 0xd0420)
#define DOVE_GPIO2_VIRT_BASE    (DOVE_SB_REGS_VIRT_BASE + 0xe8400)
#define DOVE_MPP_GENERAL_VIRT_BASE	(DOVE_SB_REGS_VIRT_BASE + 0xe803c)
#define  DOVE_AU1_SPDIFO_GPIO_EN	(1 << 1)
#define  DOVE_NAND_GPIO_EN		(1 << 0)
#define DOVE_MPP_CTRL4_VIRT_BASE	(DOVE_GPIO_LO_VIRT_BASE + 0x40)
#define  DOVE_SPI_GPIO_SEL		(1 << 5)
#define  DOVE_UART1_GPIO_SEL		(1 << 4)
#define  DOVE_AU1_GPIO_SEL		(1 << 3)
#define  DOVE_CAM_GPIO_SEL		(1 << 2)
#define  DOVE_SD1_GPIO_SEL		(1 << 1)
#define  DOVE_SD0_GPIO_SEL		(1 << 0)

/* Power Management */
#define DOVE_PMU_VIRT_BASE	(DOVE_SB_REGS_VIRT_BASE + 0xd0000)
#define DOVE_PMU_SIG_CTRL	(DOVE_PMU_VIRT_BASE + 0x802c)

/* Real Time Clock */
#define DOVE_RTC_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0xd8500)

/* AC97 */
#define DOVE_AC97_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0xe0000)
#define DOVE_AC97_VIRT_BASE	(DOVE_SB_REGS_VIRT_BASE + 0xe0000)

/* Peripheral DMA */
#define DOVE_PDMA_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0xe4000)
#define DOVE_PDMA_VIRT_BASE	(DOVE_SB_REGS_VIRT_BASE + 0xe4000)

#define DOVE_GLOBAL_CONFIG_1	(DOVE_SB_REGS_VIRT_BASE + 0xe802C)
#define  DOVE_TWSI_ENABLE_OPTION1	(1 << 7)
#define DOVE_GLOBAL_CONFIG_2	(DOVE_SB_REGS_VIRT_BASE + 0xe8030)
#define  DOVE_TWSI_ENABLE_OPTION2	(1 << 20)
#define  DOVE_TWSI_ENABLE_OPTION3	(1 << 21)
#define  DOVE_TWSI_OPTION3_GPIO		(1 << 22)
#define DOVE_SSP_PHYS_BASE	(DOVE_SB_REGS_PHYS_BASE + 0xec000)
#define DOVE_SSP_CTRL_STATUS_1	(DOVE_SB_REGS_VIRT_BASE + 0xe8034)
#define  DOVE_SSP_ON_AU1		(1 << 0)
#define  DOVE_SSP_CLOCK_ENABLE		(1 << 1)
#define  DOVE_SSP_BPB_CLOCK_SRC_SSP	(1 << 11)
/* Memory Controller */
#define DOVE_MC_PHYS_BASE       (DOVE_NB_REGS_PHYS_BASE + 0x00000)
#define  DOVE_MC_WINS_BASE      (DOVE_MC_PHYS_BASE + 0x100)
#define  DOVE_MC_WINS_SZ        (0x8)
#define DOVE_MC_VIRT_BASE	(DOVE_NB_REGS_VIRT_BASE + 0x00000)

/* LCD Controller */
#define DOVE_LCD_PHYS_BASE	(DOVE_NB_REGS_PHYS_BASE + 0x10000)
#define DOVE_LCD1_PHYS_BASE	(DOVE_NB_REGS_PHYS_BASE + 0x20000)
#define DOVE_LCD2_PHYS_BASE	(DOVE_NB_REGS_PHYS_BASE + 0x10000)
#define DOVE_LCD_DCON_PHYS_BASE	(DOVE_NB_REGS_PHYS_BASE + 0x30000)

/* Graphic Engine */
#define DOVE_GPU_PHYS_BASE	(DOVE_NB_REGS_PHYS_BASE + 0x40000)

/* Video Engine */
#define DOVE_VPU_PHYS_BASE	(DOVE_NB_REGS_PHYS_BASE + 0x400000)

#endif
