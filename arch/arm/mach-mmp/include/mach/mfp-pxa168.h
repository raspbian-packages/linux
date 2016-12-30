#ifndef __ASM_MACH_MFP_PXA168_H
#define __ASM_MACH_MFP_PXA168_H

#include <mach/mfp.h>

#define MFP_DRIVE_VERY_SLOW	(0x0 << 13)
#define MFP_DRIVE_SLOW		(0x1 << 13)
#define MFP_DRIVE_MEDIUM	(0x2 << 13)
#define MFP_DRIVE_FAST		(0x3 << 13)

#undef MFP_CFG
#undef MFP_CFG_DRV

#define MFP_CFG(pin, af)		\
	(MFP_LPM_INPUT | MFP_PIN(MFP_PIN_##pin) | MFP_##af | MFP_DRIVE_MEDIUM)

#define MFP_CFG_DRV(pin, af, drv)	\
	(MFP_LPM_INPUT | MFP_PIN(MFP_PIN_##pin) | MFP_##af | MFP_DRIVE_##drv)

/* GPIO */
#define GPIO0_GPIO		MFP_CFG(GPIO0, AF5)
#define GPIO1_GPIO		MFP_CFG(GPIO1, AF5)
#define GPIO2_GPIO		MFP_CFG(GPIO2, AF5)
#define GPIO3_GPIO		MFP_CFG(GPIO3, AF5)
#define GPIO4_GPIO		MFP_CFG(GPIO4, AF5)
#define GPIO5_GPIO		MFP_CFG(GPIO5, AF5)
#define GPIO6_GPIO		MFP_CFG(GPIO6, AF5)
#define GPIO7_GPIO		MFP_CFG(GPIO7, AF5)
#define GPIO8_GPIO		MFP_CFG(GPIO8, AF5)
#define GPIO9_GPIO		MFP_CFG(GPIO9, AF5)
#define GPIO10_GPIO		MFP_CFG(GPIO10, AF5)
#define GPIO11_GPIO		MFP_CFG(GPIO11, AF5)
#define GPIO12_GPIO		MFP_CFG(GPIO12, AF5)
#define GPIO13_GPIO		MFP_CFG(GPIO13, AF5)
#define GPIO14_GPIO		MFP_CFG(GPIO14, AF5)
#define GPIO15_GPIO		MFP_CFG(GPIO15, AF5)
#define GPIO16_GPIO		MFP_CFG(GPIO16, AF0)
#define GPIO17_GPIO		MFP_CFG(GPIO17, AF5)
#define GPIO18_GPIO		MFP_CFG(GPIO18, AF0)
#define GPIO19_GPIO		MFP_CFG(GPIO19, AF5)
#define GPIO20_GPIO		MFP_CFG(GPIO20, AF0)
#define GPIO21_GPIO		MFP_CFG(GPIO21, AF5)
#define GPIO22_GPIO		MFP_CFG(GPIO22, AF5)
#define GPIO23_GPIO		MFP_CFG(GPIO23, AF5)
#define GPIO24_GPIO		MFP_CFG(GPIO24, AF5)
#define GPIO25_GPIO		MFP_CFG(GPIO25, AF5)
#define GPIO26_GPIO		MFP_CFG(GPIO26, AF0)
#define GPIO27_GPIO		MFP_CFG(GPIO27, AF5)
#define GPIO28_GPIO		MFP_CFG(GPIO28, AF5)
#define GPIO29_GPIO		MFP_CFG(GPIO29, AF5)
#define GPIO30_GPIO		MFP_CFG(GPIO30, AF5)
#define GPIO31_GPIO		MFP_CFG(GPIO31, AF5)
#define GPIO32_GPIO		MFP_CFG(GPIO32, AF5)
#define GPIO33_GPIO		MFP_CFG(GPIO33, AF5)
#define GPIO34_GPIO		MFP_CFG(GPIO34, AF0)
#define GPIO35_GPIO		MFP_CFG(GPIO35, AF0)
#define GPIO36_GPIO		MFP_CFG(GPIO36, AF0)
#define GPIO37_GPIO		MFP_CFG(GPIO37, AF0)
#define GPIO38_GPIO		MFP_CFG(GPIO38, AF0)
#define GPIO39_GPIO		MFP_CFG(GPIO39, AF0)
#define GPIO40_GPIO		MFP_CFG(GPIO40, AF0)
#define GPIO41_GPIO		MFP_CFG(GPIO41, AF0)
#define GPIO42_GPIO		MFP_CFG(GPIO42, AF0)
#define GPIO43_GPIO		MFP_CFG(GPIO43, AF0)
#define GPIO44_GPIO		MFP_CFG(GPIO44, AF0)
#define GPIO45_GPIO		MFP_CFG(GPIO45, AF0)
#define GPIO46_GPIO		MFP_CFG(GPIO46, AF0)
#define GPIO47_GPIO		MFP_CFG(GPIO47, AF0)
#define GPIO48_GPIO		MFP_CFG(GPIO48, AF0)
#define GPIO49_GPIO		MFP_CFG(GPIO49, AF0)
#define GPIO50_GPIO		MFP_CFG(GPIO50, AF0)
#define GPIO51_GPIO		MFP_CFG(GPIO51, AF0)
#define GPIO52_GPIO		MFP_CFG(GPIO52, AF0)
#define GPIO53_GPIO		MFP_CFG(GPIO53, AF0)
#define GPIO54_GPIO		MFP_CFG(GPIO54, AF0)
#define GPIO55_GPIO		MFP_CFG(GPIO55, AF0)
#define GPIO56_GPIO		MFP_CFG(GPIO56, AF0)
#define GPIO57_GPIO		MFP_CFG(GPIO57, AF0)
#define GPIO58_GPIO		MFP_CFG(GPIO58, AF0)
#define GPIO59_GPIO		MFP_CFG(GPIO59, AF0)
#define GPIO60_GPIO		MFP_CFG(GPIO60, AF0)
#define GPIO61_GPIO		MFP_CFG(GPIO61, AF0)
#define GPIO62_GPIO		MFP_CFG(GPIO62, AF0)
#define GPIO63_GPIO		MFP_CFG(GPIO63, AF0)
#define GPIO64_GPIO		MFP_CFG(GPIO64, AF0)
#define GPIO65_GPIO		MFP_CFG(GPIO65, AF0)
#define GPIO66_GPIO		MFP_CFG(GPIO66, AF0)
#define GPIO67_GPIO		MFP_CFG(GPIO67, AF0)
#define GPIO68_GPIO		MFP_CFG(GPIO68, AF0)
#define GPIO69_GPIO		MFP_CFG(GPIO69, AF0)
#define GPIO70_GPIO		MFP_CFG(GPIO70, AF0)
#define GPIO71_GPIO		MFP_CFG(GPIO71, AF0)
#define GPIO72_GPIO		MFP_CFG(GPIO72, AF0)
#define GPIO73_GPIO		MFP_CFG(GPIO73, AF0)
#define GPIO74_GPIO		MFP_CFG(GPIO74, AF0)
#define GPIO75_GPIO		MFP_CFG(GPIO75, AF0)
#define GPIO76_GPIO		MFP_CFG(GPIO76, AF0)
#define GPIO77_GPIO		MFP_CFG(GPIO77, AF0)
#define GPIO78_GPIO		MFP_CFG(GPIO78, AF0)
#define GPIO79_GPIO		MFP_CFG(GPIO79, AF0)
#define GPIO80_GPIO		MFP_CFG(GPIO80, AF0)
#define GPIO81_GPIO		MFP_CFG(GPIO81, AF0)
#define GPIO82_GPIO		MFP_CFG(GPIO82, AF0)
#define GPIO83_GPIO		MFP_CFG(GPIO83, AF0)
#define GPIO84_GPIO		MFP_CFG(GPIO84, AF0)
#define GPIO85_GPIO		MFP_CFG(GPIO85, AF0)
#define GPIO86_GPIO		MFP_CFG(GPIO86, AF0)
#define GPIO87_GPIO		MFP_CFG(GPIO87, AF0)
#define GPIO88_GPIO		MFP_CFG(GPIO88, AF0)
#define GPIO89_GPIO		MFP_CFG(GPIO89, AF0)
#define GPIO90_GPIO		MFP_CFG(GPIO90, AF0)
#define GPIO91_GPIO		MFP_CFG(GPIO91, AF0)
#define GPIO92_GPIO		MFP_CFG(GPIO92, AF0)
#define GPIO93_GPIO		MFP_CFG(GPIO93, AF0)
#define GPIO94_GPIO		MFP_CFG(GPIO94, AF0)
#define GPIO95_GPIO		MFP_CFG(GPIO95, AF0)
#define GPIO96_GPIO		MFP_CFG(GPIO96, AF0)
#define GPIO97_GPIO		MFP_CFG(GPIO97, AF0)
#define GPIO98_GPIO		MFP_CFG(GPIO98, AF0)
#define GPIO99_GPIO		MFP_CFG(GPIO99, AF0)
#define GPIO100_GPIO		MFP_CFG(GPIO100, AF0)
#define GPIO101_GPIO		MFP_CFG(GPIO101, AF0)
#define GPIO102_GPIO		MFP_CFG(GPIO102, AF0)
#define GPIO103_GPIO		MFP_CFG(GPIO103, AF0)
#define GPIO104_GPIO		MFP_CFG(GPIO104, AF0)
#define GPIO105_GPIO		MFP_CFG(GPIO105, AF0)
#define GPIO106_GPIO		MFP_CFG(GPIO106, AF0)
#define GPIO107_GPIO		MFP_CFG(GPIO107, AF0)
#define GPIO108_GPIO		MFP_CFG(GPIO108, AF0)
#define GPIO109_GPIO		MFP_CFG(GPIO109, AF0)
#define GPIO110_GPIO		MFP_CFG(GPIO110, AF0)
#define GPIO111_GPIO		MFP_CFG(GPIO111, AF0)
#define GPIO112_GPIO		MFP_CFG(GPIO112, AF0)
#define GPIO113_GPIO		MFP_CFG(GPIO113, AF0)
#define GPIO114_GPIO		MFP_CFG(GPIO114, AF0)
#define GPIO115_GPIO		MFP_CFG(GPIO115, AF0)
#define GPIO116_GPIO		MFP_CFG(GPIO116, AF0)
#define GPIO117_GPIO		MFP_CFG(GPIO117, AF0)
#define GPIO118_GPIO		MFP_CFG(GPIO118, AF0)
#define GPIO119_GPIO		MFP_CFG(GPIO119, AF0)
#define GPIO120_GPIO		MFP_CFG(GPIO120, AF0)
#define GPIO121_GPIO		MFP_CFG(GPIO121, AF0)
#define GPIO122_GPIO		MFP_CFG(GPIO122, AF0)

/* DFI */
#define GPIO0_DFI_D15		MFP_CFG(GPIO0, AF0)
#define GPIO1_DFI_D14		MFP_CFG(GPIO1, AF0)
#define GPIO2_DFI_D13		MFP_CFG(GPIO2, AF0)
#define GPIO3_DFI_D12		MFP_CFG(GPIO3, AF0)
#define GPIO4_DFI_D11		MFP_CFG(GPIO4, AF0)
#define GPIO5_DFI_D10		MFP_CFG(GPIO5, AF0)
#define GPIO6_DFI_D9		MFP_CFG(GPIO6, AF0)
#define GPIO7_DFI_D8		MFP_CFG(GPIO7, AF0)
#define GPIO8_DFI_D7		MFP_CFG(GPIO8, AF0)
#define GPIO9_DFI_D6		MFP_CFG(GPIO9, AF0)
#define GPIO10_DFI_D5		MFP_CFG(GPIO10, AF0)
#define GPIO11_DFI_D4		MFP_CFG(GPIO11, AF0)
#define GPIO12_DFI_D3		MFP_CFG(GPIO12, AF0)
#define GPIO13_DFI_D2		MFP_CFG(GPIO13, AF0)
#define GPIO14_DFI_D1		MFP_CFG(GPIO14, AF0)
#define GPIO15_DFI_D0		MFP_CFG(GPIO15, AF0)

#define GPIO30_DFI_ADDR0	MFP_CFG(GPIO30, AF0)
#define GPIO31_DFI_ADDR1	MFP_CFG(GPIO31, AF0)
#define GPIO32_DFI_ADDR2	MFP_CFG(GPIO32, AF0)
#define GPIO33_DFI_ADDR3	MFP_CFG(GPIO33, AF0)

/* NAND */
#define GPIO16_ND_nCS0		MFP_CFG(GPIO16, AF1)
#define GPIO17_ND_nWE		MFP_CFG(GPIO17, AF0)
#define GPIO21_ND_ALE		MFP_CFG(GPIO21, AF0)
#define GPIO22_ND_CLE		MFP_CFG(GPIO22, AF0)
#define GPIO24_ND_nRE		MFP_CFG(GPIO24, AF0)
#define GPIO26_ND_RnB1		MFP_CFG(GPIO26, AF1)
#define GPIO27_ND_RnB2		MFP_CFG(GPIO27, AF1)

/* Static Memory Controller */
#define GPIO18_SMC_nCS0		MFP_CFG(GPIO18, AF3)
#define GPIO18_SMC_nCS1		MFP_CFG(GPIO18, AF2)
#define GPIO16_SMC_nCS0		MFP_CFG(GPIO16, AF2)
#define GPIO16_SMC_nCS1		MFP_CFG(GPIO16, AF3)
#define GPIO19_SMC_nCS0		MFP_CFG(GPIO19, AF0)
#define GPIO20_SMC_nCS1		MFP_CFG(GPIO20, AF2)
#define GPIO23_SMC_nLUA		MFP_CFG(GPIO23, AF0)
#define GPIO25_SMC_nLLA		MFP_CFG(GPIO25, AF0)
#define GPIO27_SMC_IRQ		MFP_CFG(GPIO27, AF0)
#define GPIO28_SMC_RDY		MFP_CFG(GPIO28, AF0)
#define GPIO29_SMC_SCLK		MFP_CFG(GPIO29, AF0)
#define GPIO34_SMC_nCS1		MFP_CFG(GPIO34, AF2)
#define GPIO35_SMC_BE1		MFP_CFG(GPIO35, AF2)
#define GPIO36_SMC_BE2		MFP_CFG(GPIO36, AF2)

/* Compact Flash */
#define GPIO19_CF_nCE1		MFP_CFG(GPIO19, AF3)
#define GPIO20_CF_nCE2		MFP_CFG(GPIO20, AF3)
#define GPIO23_CF_nALE		MFP_CFG(GPIO23, AF3)
#define GPIO25_CF_nRESET	MFP_CFG(GPIO25, AF3)
#define GPIO28_CF_RDY		MFP_CFG(GPIO28, AF3)
#define GPIO29_CF_STSCH		MFP_CFG(GPIO29, AF3)
#define GPIO30_CF_nREG		MFP_CFG(GPIO30, AF3)
#define GPIO31_CF_nIOIS16	MFP_CFG(GPIO31, AF3)
#define GPIO32_CF_nCD1		MFP_CFG(GPIO32, AF3)
#define GPIO33_CF_nCD2		MFP_CFG(GPIO33, AF3)

/* UART */
#define GPIO8_UART3_TXD		MFP_CFG(GPIO8, AF2)
#define GPIO9_UART3_RXD		MFP_CFG(GPIO9, AF2)
#define GPIO1O_UART3_CTS	MFP_CFG(GPIO10, AF2)
#define GPIO11_UART3_RTS	MFP_CFG(GPIO11, AF2)
#define GPIO88_UART2_TXD	MFP_CFG(GPIO88, AF2)
#define GPIO89_UART2_RXD	MFP_CFG(GPIO89, AF2)
#define GPIO107_UART1_TXD	MFP_CFG_DRV(GPIO107, AF1, FAST)
#define GPIO107_UART1_RXD	MFP_CFG_DRV(GPIO107, AF2, FAST)
#define GPIO108_UART1_RXD	MFP_CFG_DRV(GPIO108, AF1, FAST)
#define GPIO108_UART1_TXD	MFP_CFG_DRV(GPIO108, AF2, FAST)
#define GPIO109_UART1_CTS	MFP_CFG(GPIO109, AF1)
#define GPIO109_UART1_RTS	MFP_CFG(GPIO109, AF2)
#define GPIO110_UART1_RTS	MFP_CFG(GPIO110, AF1)
#define GPIO110_UART1_CTS	MFP_CFG(GPIO110, AF2)
#define GPIO111_UART1_RI	MFP_CFG(GPIO111, AF1)
#define GPIO111_UART1_DSR	MFP_CFG(GPIO111, AF2)
#define GPIO112_UART1_DTR	MFP_CFG(GPIO111, AF1)
#define GPIO112_UART1_DCD	MFP_CFG(GPIO112, AF2)

/* MMC1 */
#define GPIO37_MMC1_DAT7	MFP_CFG(GPIO37, AF1)
#define GPIO38_MMC1_DAT6	MFP_CFG(GPIO38, AF1)
#define GPIO54_MMC1_DAT5	MFP_CFG(GPIO54, AF1)
#define GPIO48_MMC1_DAT4	MFP_CFG(GPIO48, AF1)
#define GPIO51_MMC1_DAT3	MFP_CFG(GPIO51, AF1)
#define GPIO52_MMC1_DAT2	MFP_CFG(GPIO52, AF1)
#define GPIO40_MMC1_DAT1	MFP_CFG(GPIO40, AF1)
#define GPIO41_MMC1_DAT0	MFP_CFG(GPIO41, AF1)
#define GPIO49_MMC1_CMD		MFP_CFG(GPIO49, AF1)
#define GPIO43_MMC1_CLK		MFP_CFG(GPIO43, AF1)
#define GPIO53_MMC1_CD		MFP_CFG(GPIO53, AF1)
#define GPIO46_MMC1_WP		MFP_CFG(GPIO46, AF1)

/* MMC2 */
#define	GPIO28_MMC2_CMD		MFP_CFG_DRV(GPIO28, AF6, FAST)
#define	GPIO29_MMC2_CLK		MFP_CFG_DRV(GPIO29, AF6, FAST)
#define	GPIO30_MMC2_DAT0	MFP_CFG_DRV(GPIO30, AF6, FAST)
#define	GPIO31_MMC2_DAT1	MFP_CFG_DRV(GPIO31, AF6, FAST)
#define	GPIO32_MMC2_DAT2	MFP_CFG_DRV(GPIO32, AF6, FAST)
#define	GPIO33_MMC2_DAT3	MFP_CFG_DRV(GPIO33, AF6, FAST)

/* MMC4 */
#define GPIO125_MMC4_DAT3       MFP_CFG_DRV(GPIO125, AF7, FAST)
#define GPIO126_MMC4_DAT2       MFP_CFG_DRV(GPIO126, AF7, FAST)
#define GPIO127_MMC4_DAT1       MFP_CFG_DRV(GPIO127, AF7, FAST)
#define GPIO0_2_MMC4_DAT0       MFP_CFG_DRV(GPIO0_2, AF7, FAST)
#define GPIO1_2_MMC4_CMD        MFP_CFG_DRV(GPIO1_2, AF7, FAST)
#define GPIO2_2_MMC4_CLK        MFP_CFG_DRV(GPIO2_2, AF7, FAST)

/* LCD */
#define GPIO84_LCD_CS		MFP_CFG(GPIO84, AF1)
#define GPIO60_LCD_DD0		MFP_CFG(GPIO60, AF1)
#define GPIO61_LCD_DD1		MFP_CFG(GPIO61, AF1)
#define GPIO70_LCD_DD10		MFP_CFG(GPIO70, AF1)
#define GPIO71_LCD_DD11		MFP_CFG(GPIO71, AF1)
#define GPIO72_LCD_DD12		MFP_CFG(GPIO72, AF1)
#define GPIO73_LCD_DD13		MFP_CFG(GPIO73, AF1)
#define GPIO74_LCD_DD14		MFP_CFG(GPIO74, AF1)
#define GPIO75_LCD_DD15		MFP_CFG(GPIO75, AF1)
#define GPIO76_LCD_DD16		MFP_CFG(GPIO76, AF1)
#define GPIO77_LCD_DD17		MFP_CFG(GPIO77, AF1)
#define GPIO78_LCD_DD18		MFP_CFG(GPIO78, AF1)
#define GPIO79_LCD_DD19		MFP_CFG(GPIO79, AF1)
#define GPIO62_LCD_DD2		MFP_CFG(GPIO62, AF1)
#define GPIO80_LCD_DD20		MFP_CFG(GPIO80, AF1)
#define GPIO81_LCD_DD21		MFP_CFG(GPIO81, AF1)
#define GPIO82_LCD_DD22		MFP_CFG(GPIO82, AF1)
#define GPIO83_LCD_DD23		MFP_CFG(GPIO83, AF1)
#define GPIO63_LCD_DD3		MFP_CFG(GPIO63, AF1)
#define GPIO64_LCD_DD4		MFP_CFG(GPIO64, AF1)
#define GPIO65_LCD_DD5		MFP_CFG(GPIO65, AF1)
#define GPIO66_LCD_DD6		MFP_CFG(GPIO66, AF1)
#define GPIO67_LCD_DD7		MFP_CFG(GPIO67, AF1)
#define GPIO68_LCD_DD8		MFP_CFG(GPIO68, AF1)
#define GPIO69_LCD_DD9		MFP_CFG(GPIO69, AF1)
#define GPIO59_LCD_DENA_BIAS	MFP_CFG(GPIO59, AF1)
#define GPIO56_LCD_FCLK_RD	MFP_CFG(GPIO56, AF1)
#define GPIO57_LCD_LCLK_A0	MFP_CFG(GPIO57, AF1)
#define GPIO58_LCD_PCLK_WR	MFP_CFG(GPIO58, AF1)
#define GPIO85_LCD_VSYNC	MFP_CFG(GPIO85, AF1)

/* I2C */
#define GPIO105_CI2C_SDA	MFP_CFG(GPIO105, AF1)
#define GPIO106_CI2C_SCL	MFP_CFG(GPIO106, AF1)

/* I2S */
#define GPIO113_I2S_MCLK	MFP_CFG(GPIO113, AF6)
#define GPIO114_I2S_FRM		MFP_CFG(GPIO114, AF1)
#define GPIO115_I2S_BCLK	MFP_CFG(GPIO115, AF1)
#define GPIO116_I2S_RXD		MFP_CFG(GPIO116, AF2)
#define GPIO116_I2S_TXD         MFP_CFG(GPIO116, AF1)
#define GPIO117_I2S_TXD		MFP_CFG(GPIO117, AF2)

/* PWM */
#define GPIO96_PWM3_OUT		MFP_CFG(GPIO96, AF1)
#define GPIO97_PWM2_OUT		MFP_CFG(GPIO97, AF1)
#define GPIO98_PWM1_OUT		MFP_CFG(GPIO98, AF1)
#define GPIO104_PWM4_OUT	MFP_CFG(GPIO104, AF1)
#define GPIO106_PWM2_OUT	MFP_CFG(GPIO106, AF2)
#define GPIO74_PWM4_OUT		MFP_CFG(GPIO74, AF2)
#define GPIO75_PWM3_OUT		MFP_CFG(GPIO75, AF2)
#define GPIO76_PWM2_OUT		MFP_CFG(GPIO76, AF2)
#define GPIO77_PWM1_OUT		MFP_CFG(GPIO77, AF2)
#define GPIO82_PWM4_OUT		MFP_CFG(GPIO82, AF2)
#define GPIO83_PWM3_OUT		MFP_CFG(GPIO83, AF2)
#define GPIO84_PWM2_OUT		MFP_CFG(GPIO84, AF2)
#define GPIO85_PWM1_OUT		MFP_CFG(GPIO85, AF2)
#define GPIO84_PWM1_OUT		MFP_CFG(GPIO84, AF4)
#define GPIO122_PWM3_OUT	MFP_CFG(GPIO122, AF3)
#define GPIO123_PWM1_OUT	MFP_CFG(GPIO123, AF1)
#define GPIO124_PWM2_OUT	MFP_CFG(GPIO124, AF1)
#define GPIO125_PWM3_OUT	MFP_CFG(GPIO125, AF1)
#define GPIO126_PWM4_OUT	MFP_CFG(GPIO126, AF1)
#define GPIO86_PWM1_OUT		MFP_CFG(GPIO86, AF2)
#define GPIO86_PWM2_OUT		MFP_CFG(GPIO86, AF3)

/* Keypad */
#define GPIO109_KP_MKIN1        MFP_CFG(GPIO109, AF7)
#define GPIO110_KP_MKIN0        MFP_CFG(GPIO110, AF7)
#define GPIO111_KP_MKOUT7       MFP_CFG(GPIO111, AF7)
#define GPIO112_KP_MKOUT6       MFP_CFG(GPIO112, AF7)
#define GPIO121_KP_MKIN4        MFP_CFG(GPIO121, AF7)

/* Fast Ethernet */
#define GPIO86_TX_CLK		MFP_CFG(GPIO86, AF5)
#define GPIO87_TX_EN		MFP_CFG(GPIO87, AF5)
#define GPIO88_TX_DQ3		MFP_CFG(GPIO88, AF5)
#define GPIO89_TX_DQ2		MFP_CFG(GPIO89, AF5)
#define GPIO90_TX_DQ1		MFP_CFG(GPIO90, AF5)
#define GPIO91_TX_DQ0		MFP_CFG(GPIO91, AF5)
#define GPIO92_MII_CRS		MFP_CFG(GPIO92, AF5)
#define GPIO93_MII_COL		MFP_CFG(GPIO93, AF5)
#define GPIO94_RX_CLK		MFP_CFG(GPIO94, AF5)
#define GPIO95_RX_ER		MFP_CFG(GPIO95, AF5)
#define GPIO96_RX_DQ3		MFP_CFG(GPIO96, AF5)
#define GPIO97_RX_DQ2		MFP_CFG(GPIO97, AF5)
#define GPIO98_RX_DQ1		MFP_CFG(GPIO98, AF5)
#define GPIO99_RX_DQ0		MFP_CFG(GPIO99, AF5)
#define GPIO100_MII_MDC		MFP_CFG(GPIO100, AF5)
#define GPIO101_MII_MDIO	MFP_CFG(GPIO101, AF5)
#define GPIO103_RX_DV		MFP_CFG(GPIO103, AF5)

/* SSP2 */
#define GPIO107_SSP2_RXD	MFP_CFG(GPIO107, AF4)
#define GPIO108_SSP2_TXD	MFP_CFG(GPIO108, AF4)
#define GPIO111_SSP2_CLK	MFP_CFG(GPIO111, AF4)
#define GPIO112_SSP2_FRM	MFP_CFG(GPIO112, AF4)

#endif /* __ASM_MACH_MFP_PXA168_H */
