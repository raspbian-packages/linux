/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Ralink RT3662/RT3883 SoC register definitions
 *
 * Copyright (C) 2011-2012 Gabor Juhos <juhosg@openwrt.org>
 */

#ifndef _RT3883_REGS_H_
#define _RT3883_REGS_H_

#include <linux/bitops.h>

#define RT3883_SDRAM_BASE	0x00000000
#define RT3883_SYSC_BASE	0x10000000
#define RT3883_TIMER_BASE	0x10000100
#define RT3883_INTC_BASE	0x10000200
#define RT3883_MEMC_BASE	0x10000300
#define RT3883_UART0_BASE	0x10000500
#define RT3883_PIO_BASE		0x10000600
#define RT3883_FSCC_BASE	0x10000700
#define RT3883_NANDC_BASE	0x10000810
#define RT3883_I2C_BASE		0x10000900
#define RT3883_I2S_BASE		0x10000a00
#define RT3883_SPI_BASE		0x10000b00
#define RT3883_UART1_BASE	0x10000c00
#define RT3883_PCM_BASE		0x10002000
#define RT3883_GDMA_BASE	0x10002800
#define RT3883_CODEC1_BASE	0x10003000
#define RT3883_CODEC2_BASE	0x10003800
#define RT3883_FE_BASE		0x10100000
#define RT3883_ROM_BASE		0x10118000
#define RT3883_USBDEV_BASE	0x10112000
#define RT3883_PCI_BASE		0x10140000
#define RT3883_WLAN_BASE	0x10180000
#define RT3883_USBHOST_BASE	0x101c0000
#define RT3883_BOOT_BASE	0x1c000000
#define RT3883_SRAM_BASE	0x1e000000
#define RT3883_PCIMEM_BASE	0x20000000

#define RT3883_EHCI_BASE	(RT3883_USBHOST_BASE)
#define RT3883_OHCI_BASE	(RT3883_USBHOST_BASE + 0x1000)

#define RT3883_SYSC_SIZE	0x100
#define RT3883_TIMER_SIZE	0x100
#define RT3883_INTC_SIZE	0x100
#define RT3883_MEMC_SIZE	0x100
#define RT3883_UART0_SIZE	0x100
#define RT3883_UART1_SIZE	0x100
#define RT3883_PIO_SIZE		0x100
#define RT3883_FSCC_SIZE	0x100
#define RT3883_NANDC_SIZE	0x0f0
#define RT3883_I2C_SIZE		0x100
#define RT3883_I2S_SIZE		0x100
#define RT3883_SPI_SIZE		0x100
#define RT3883_PCM_SIZE		0x800
#define RT3883_GDMA_SIZE	0x800
#define RT3883_CODEC1_SIZE	0x800
#define RT3883_CODEC2_SIZE	0x800
#define RT3883_FE_SIZE		0x10000
#define RT3883_ROM_SIZE		0x4000
#define RT3883_USBDEV_SIZE	0x4000
#define RT3883_PCI_SIZE		0x40000
#define RT3883_WLAN_SIZE	0x40000
#define RT3883_USBHOST_SIZE	0x40000
#define RT3883_BOOT_SIZE	(32 * 1024 * 1024)
#define RT3883_SRAM_SIZE	(32 * 1024 * 1024)

/* SYSC registers */
#define RT3883_SYSC_REG_CHIPID0_3	0x00	/* Chip ID 0 */
#define RT3883_SYSC_REG_CHIPID4_7	0x04	/* Chip ID 1 */
#define RT3883_SYSC_REG_REVID		0x0c	/* Chip Revision Identification */
#define RT3883_SYSC_REG_SYSCFG0		0x10	/* System Configuration 0 */
#define RT3883_SYSC_REG_SYSCFG1		0x14	/* System Configuration 1 */
#define RT3883_SYSC_REG_CLKCFG0		0x2c	/* Clock Configuration 0 */
#define RT3883_SYSC_REG_CLKCFG1		0x30	/* Clock Configuration 1 */
#define RT3883_SYSC_REG_RSTCTRL		0x34	/* Reset Control*/
#define RT3883_SYSC_REG_RSTSTAT		0x38	/* Reset Status*/
#define RT3883_SYSC_REG_USB_PS		0x5c	/* USB Power saving control */
#define RT3883_SYSC_REG_GPIO_MODE	0x60	/* GPIO Purpose Select */
#define RT3883_SYSC_REG_PCIE_CLK_GEN0	0x7c
#define RT3883_SYSC_REG_PCIE_CLK_GEN1	0x80
#define RT3883_SYSC_REG_PCIE_CLK_GEN2	0x84
#define RT3883_SYSC_REG_PMU		0x88
#define RT3883_SYSC_REG_PMU1		0x8c

#define RT3883_CHIP_NAME0		0x38335452
#define RT3883_CHIP_NAME1		0x20203338

#define RT3883_REVID_VER_ID_MASK	0x0f
#define RT3883_REVID_VER_ID_SHIFT	8
#define RT3883_REVID_ECO_ID_MASK	0x0f

#define RT3883_SYSCFG0_DRAM_TYPE_DDR2	BIT(17)
#define RT3883_SYSCFG0_CPUCLK_SHIFT	8
#define RT3883_SYSCFG0_CPUCLK_MASK	0x3
#define RT3883_SYSCFG0_CPUCLK_250	0x0
#define RT3883_SYSCFG0_CPUCLK_384	0x1
#define RT3883_SYSCFG0_CPUCLK_480	0x2
#define RT3883_SYSCFG0_CPUCLK_500	0x3

#define RT3883_SYSCFG1_USB0_HOST_MODE	BIT(10)
#define RT3883_SYSCFG1_PCIE_RC_MODE	BIT(8)
#define RT3883_SYSCFG1_PCI_HOST_MODE	BIT(7)
#define RT3883_SYSCFG1_PCI_66M_MODE	BIT(6)
#define RT3883_SYSCFG1_GPIO2_AS_WDT_OUT	BIT(2)

#define RT3883_CLKCFG1_PCIE_CLK_EN	BIT(21)
#define RT3883_CLKCFG1_UPHY1_CLK_EN	BIT(20)
#define RT3883_CLKCFG1_PCI_CLK_EN	BIT(19)
#define RT3883_CLKCFG1_UPHY0_CLK_EN	BIT(18)

#define RT3883_GPIO_MODE_UART0_SHIFT	2
#define RT3883_GPIO_MODE_UART0_MASK	0x7
#define RT3883_GPIO_MODE_UART0(x)	((x) << RT3883_GPIO_MODE_UART0_SHIFT)
#define RT3883_GPIO_MODE_UARTF		0x0
#define RT3883_GPIO_MODE_PCM_UARTF	0x1
#define RT3883_GPIO_MODE_PCM_I2S	0x2
#define RT3883_GPIO_MODE_I2S_UARTF	0x3
#define RT3883_GPIO_MODE_PCM_GPIO	0x4
#define RT3883_GPIO_MODE_GPIO_UARTF	0x5
#define RT3883_GPIO_MODE_GPIO_I2S	0x6
#define RT3883_GPIO_MODE_GPIO		0x7

#define RT3883_GPIO_MODE_I2C		0
#define RT3883_GPIO_MODE_SPI		1
#define RT3883_GPIO_MODE_UART1		5
#define RT3883_GPIO_MODE_JTAG		6
#define RT3883_GPIO_MODE_MDIO		7
#define RT3883_GPIO_MODE_GE1		9
#define RT3883_GPIO_MODE_GE2		10

#define RT3883_GPIO_MODE_PCI_SHIFT	11
#define RT3883_GPIO_MODE_PCI_MASK	0x7
#define RT3883_GPIO_MODE_PCI		(RT3883_GPIO_MODE_PCI_MASK << RT3883_GPIO_MODE_PCI_SHIFT)
#define RT3883_GPIO_MODE_LNA_A_SHIFT	16
#define RT3883_GPIO_MODE_LNA_A_MASK	0x3
#define _RT3883_GPIO_MODE_LNA_A(_x)	((_x) << RT3883_GPIO_MODE_LNA_A_SHIFT)
#define RT3883_GPIO_MODE_LNA_A_GPIO	0x3
#define RT3883_GPIO_MODE_LNA_A		_RT3883_GPIO_MODE_LNA_A(RT3883_GPIO_MODE_LNA_A_MASK)
#define RT3883_GPIO_MODE_LNA_G_SHIFT	18
#define RT3883_GPIO_MODE_LNA_G_MASK	0x3
#define _RT3883_GPIO_MODE_LNA_G(_x)	((_x) << RT3883_GPIO_MODE_LNA_G_SHIFT)
#define RT3883_GPIO_MODE_LNA_G_GPIO	0x3
#define RT3883_GPIO_MODE_LNA_G		_RT3883_GPIO_MODE_LNA_G(RT3883_GPIO_MODE_LNA_G_MASK)

#define RT3883_GPIO_I2C_SD		1
#define RT3883_GPIO_I2C_SCLK		2
#define RT3883_GPIO_SPI_CS0		3
#define RT3883_GPIO_SPI_CLK		4
#define RT3883_GPIO_SPI_MOSI		5
#define RT3883_GPIO_SPI_MISO		6
#define RT3883_GPIO_7			7
#define RT3883_GPIO_10			10
#define RT3883_GPIO_11			11
#define RT3883_GPIO_14			14
#define RT3883_GPIO_UART1_TXD		15
#define RT3883_GPIO_UART1_RXD		16
#define RT3883_GPIO_JTAG_TDO		17
#define RT3883_GPIO_JTAG_TDI		18
#define RT3883_GPIO_JTAG_TMS		19
#define RT3883_GPIO_JTAG_TCLK		20
#define RT3883_GPIO_JTAG_TRST_N		21
#define RT3883_GPIO_MDIO_MDC		22
#define RT3883_GPIO_MDIO_MDIO		23
#define RT3883_GPIO_LNA_PE_A0		32
#define RT3883_GPIO_LNA_PE_A1		33
#define RT3883_GPIO_LNA_PE_A2		34
#define RT3883_GPIO_LNA_PE_G0		35
#define RT3883_GPIO_LNA_PE_G1		36
#define RT3883_GPIO_LNA_PE_G2		37
#define RT3883_GPIO_PCI_AD0		40
#define RT3883_GPIO_PCI_AD31		71
#define RT3883_GPIO_GE2_TXD0		72
#define RT3883_GPIO_GE2_TXD1		73
#define RT3883_GPIO_GE2_TXD2		74
#define RT3883_GPIO_GE2_TXD3		75
#define RT3883_GPIO_GE2_TXEN		76
#define RT3883_GPIO_GE2_TXCLK		77
#define RT3883_GPIO_GE2_RXD0		78
#define RT3883_GPIO_GE2_RXD1		79
#define RT3883_GPIO_GE2_RXD2		80
#define RT3883_GPIO_GE2_RXD3		81
#define RT3883_GPIO_GE2_RXDV		82
#define RT3883_GPIO_GE2_RXCLK		83
#define RT3883_GPIO_GE1_TXD0		84
#define RT3883_GPIO_GE1_TXD1		85
#define RT3883_GPIO_GE1_TXD2		86
#define RT3883_GPIO_GE1_TXD3		87
#define RT3883_GPIO_GE1_TXEN		88
#define RT3883_GPIO_GE1_TXCLK		89
#define RT3883_GPIO_GE1_RXD0		90
#define RT3883_GPIO_GE1_RXD1		91
#define RT3883_GPIO_GE1_RXD2		92
#define RT3883_GPIO_GE1_RXD3		93
#define RT3883_GPIO_GE1_RXDV		94
#define RT3883_GPIO_GE1_RXCLK	95

#define RT3883_RSTCTRL_PCIE_PCI_PDM	BIT(27)
#define RT3883_RSTCTRL_FLASH		BIT(26)
#define RT3883_RSTCTRL_UDEV		BIT(25)
#define RT3883_RSTCTRL_PCI		BIT(24)
#define RT3883_RSTCTRL_PCIE		BIT(23)
#define RT3883_RSTCTRL_UHST		BIT(22)
#define RT3883_RSTCTRL_FE		BIT(21)
#define RT3883_RSTCTRL_WLAN		BIT(20)
#define RT3883_RSTCTRL_UART1		BIT(29)
#define RT3883_RSTCTRL_SPI		BIT(18)
#define RT3883_RSTCTRL_I2S		BIT(17)
#define RT3883_RSTCTRL_I2C		BIT(16)
#define RT3883_RSTCTRL_NAND		BIT(15)
#define RT3883_RSTCTRL_DMA		BIT(14)
#define RT3883_RSTCTRL_PIO		BIT(13)
#define RT3883_RSTCTRL_UART		BIT(12)
#define RT3883_RSTCTRL_PCM		BIT(11)
#define RT3883_RSTCTRL_MC		BIT(10)
#define RT3883_RSTCTRL_INTC		BIT(9)
#define RT3883_RSTCTRL_TIMER		BIT(8)
#define RT3883_RSTCTRL_SYS		BIT(0)

#define RT3883_INTC_INT_SYSCTL	BIT(0)
#define RT3883_INTC_INT_TIMER0	BIT(1)
#define RT3883_INTC_INT_TIMER1	BIT(2)
#define RT3883_INTC_INT_IA	BIT(3)
#define RT3883_INTC_INT_PCM	BIT(4)
#define RT3883_INTC_INT_UART0	BIT(5)
#define RT3883_INTC_INT_PIO	BIT(6)
#define RT3883_INTC_INT_DMA	BIT(7)
#define RT3883_INTC_INT_NAND	BIT(8)
#define RT3883_INTC_INT_PERFC	BIT(9)
#define RT3883_INTC_INT_I2S	BIT(10)
#define RT3883_INTC_INT_UART1	BIT(12)
#define RT3883_INTC_INT_UHST	BIT(18)
#define RT3883_INTC_INT_UDEV	BIT(19)

/* FLASH/SRAM/Codec Controller registers */
#define RT3883_FSCC_REG_FLASH_CFG0	0x00
#define RT3883_FSCC_REG_FLASH_CFG1	0x04
#define RT3883_FSCC_REG_CODEC_CFG0	0x40
#define RT3883_FSCC_REG_CODEC_CFG1	0x44

#define RT3883_FLASH_CFG_WIDTH_SHIFT	26
#define RT3883_FLASH_CFG_WIDTH_MASK	0x3
#define RT3883_FLASH_CFG_WIDTH_8BIT	0x0
#define RT3883_FLASH_CFG_WIDTH_16BIT	0x1
#define RT3883_FLASH_CFG_WIDTH_32BIT	0x2

#define RT3883_SDRAM_BASE		0x00000000
#define RT3883_MEM_SIZE_MIN		2
#define RT3883_MEM_SIZE_MAX		256

#endif /* _RT3883_REGS_H_ */
