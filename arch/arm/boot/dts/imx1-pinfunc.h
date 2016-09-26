/*
 * Copyright (C) 2014 Alexander Shiyan <shc_work@mail.ru>
 *
 * The code contained herein is licensed under the GNU General Public
 * License. You may obtain a copy of the GNU General Public License
 * Version 2 or later at the following locations:
 *
 * http://www.opensource.org/licenses/gpl-license.html
 * http://www.gnu.org/copyleft/gpl.html
 */

#ifndef __DTS_IMX1_PINFUNC_H
#define __DTS_IMX1_PINFUNC_H

/*
 * The pin function ID is a tuple of
 * <pin mux_id>
 * mux_id consists of
 * function + (direction << 2) + (gpio_oconf << 4) + (gpio_iconfa << 8) + (gpio_iconfb << 10)
 *
 * function:      0 - Primary function
 *                1 - Alternate function
 *                2 - GPIO
 * direction:     0 - Input
 *                1 - Output
 * gpio_oconf:    0 - A_IN
 *                1 - B_IN
 *                2 - A_OUT
 *                3 - Data Register
 * gpio_iconfa/b: 0 - GPIO_IN
 *                1 - Interrupt Status Register
 *                2 - 0
 *                3 - 1
 *
 * 'pin' is an integer between 0 and 0xbf. i.MX1 has 4 ports with 32 configurable
 * configurable pins each. 'pin' is PORT * 32 + PORT_PIN, PORT_PIN is the pin
 * number on the specific port (between 0 and 31).
 */

#define MX1_PAD_A24__A24			0x00 0x004
#define MX1_PAD_A24__GPIO1_0			0x00 0x032
#define MX1_PAD_A24__SPI2_CLK			0x00 0x006
#define MX1_PAD_TIN__TIN			0x01 0x000
#define MX1_PAD_TIN__GPIO1_1			0x01 0x032
#define MX1_PAD_TIN__SPI2_RXD			0x01 0x022
#define MX1_PAD_PWMO__PWMO			0x02 0x004
#define MX1_PAD_PWMO__GPIO1_2			0x02 0x032
#define MX1_PAD_CSI_MCLK__CSI_MCLK		0x03 0x004
#define MX1_PAD_CSI_MCLK__GPIO1_3		0x03 0x032
#define MX1_PAD_CSI_D0__CSI_D0			0x04 0x000
#define MX1_PAD_CSI_D0__GPIO1_4			0x04 0x032
#define MX1_PAD_CSI_D1__CSI_D1			0x05 0x000
#define MX1_PAD_CSI_D1__GPIO1_5			0x05 0x032
#define MX1_PAD_CSI_D2__CSI_D2			0x06 0x000
#define MX1_PAD_CSI_D2__GPIO1_6			0x06 0x032
#define MX1_PAD_CSI_D3__CSI_D3			0x07 0x000
#define MX1_PAD_CSI_D3__GPIO1_7			0x07 0x032
#define MX1_PAD_CSI_D4__CSI_D4			0x08 0x000
#define MX1_PAD_CSI_D4__GPIO1_8			0x08 0x032
#define MX1_PAD_CSI_D5__CSI_D5			0x09 0x000
#define MX1_PAD_CSI_D5__GPIO1_9			0x09 0x032
#define MX1_PAD_CSI_D6__CSI_D6			0x0a 0x000
#define MX1_PAD_CSI_D6__GPIO1_10		0x0a 0x032
#define MX1_PAD_CSI_D7__CSI_D7			0x0b 0x000
#define MX1_PAD_CSI_D7__GPIO1_11		0x0b 0x032
#define MX1_PAD_CSI_VSYNC__CSI_VSYNC		0x0c 0x000
#define MX1_PAD_CSI_VSYNC__GPIO1_12		0x0c 0x032
#define MX1_PAD_CSI_HSYNC__CSI_HSYNC		0x0d 0x000
#define MX1_PAD_CSI_HSYNC__GPIO1_13		0x0d 0x032
#define MX1_PAD_CSI_PIXCLK__CSI_PIXCLK		0x0e 0x000
#define MX1_PAD_CSI_PIXCLK__GPIO1_14		0x0e 0x032
#define MX1_PAD_I2C_SDA__I2C_SDA		0x0f 0x000
#define MX1_PAD_I2C_SDA__GPIO1_15		0x0f 0x032
#define MX1_PAD_I2C_SCL__I2C_SCL		0x10 0x004
#define MX1_PAD_I2C_SCL__GPIO1_16		0x10 0x032
#define MX1_PAD_DTACK__DTACK			0x11 0x000
#define MX1_PAD_DTACK__GPIO1_17			0x11 0x032
#define MX1_PAD_DTACK__SPI2_SS			0x11 0x002
#define MX1_PAD_DTACK__A25			0x11 0x016
#define MX1_PAD_BCLK__BCLK			0x12 0x004
#define MX1_PAD_BCLK__GPIO1_18			0x12 0x032
#define MX1_PAD_LBA__LBA			0x13 0x004
#define MX1_PAD_LBA__GPIO1_19			0x13 0x032
#define MX1_PAD_ECB__ECB			0x14 0x000
#define MX1_PAD_ECB__GPIO1_20			0x14 0x032
#define MX1_PAD_A0__A0				0x15 0x004
#define MX1_PAD_A0__GPIO1_21			0x15 0x032
#define MX1_PAD_CS4__CS4			0x16 0x004
#define MX1_PAD_CS4__GPIO1_22			0x16 0x032
#define MX1_PAD_CS5__CS5			0x17 0x004
#define MX1_PAD_CS5__GPIO1_23			0x17 0x032
#define MX1_PAD_A16__A16			0x18 0x004
#define MX1_PAD_A16__GPIO1_24			0x18 0x032
#define MX1_PAD_A17__A17			0x19 0x004
#define MX1_PAD_A17__GPIO1_25			0x19 0x032
#define MX1_PAD_A18__A18			0x1a 0x004
#define MX1_PAD_A18__GPIO1_26			0x1a 0x032
#define MX1_PAD_A19__A19			0x1b 0x004
#define MX1_PAD_A19__GPIO1_27			0x1b 0x032
#define MX1_PAD_A20__A20			0x1c 0x004
#define MX1_PAD_A20__GPIO1_28			0x1c 0x032
#define MX1_PAD_A21__A21			0x1d 0x004
#define MX1_PAD_A21__GPIO1_29			0x1d 0x032
#define MX1_PAD_A22__A22			0x1e 0x004
#define MX1_PAD_A22__GPIO1_30			0x1e 0x032
#define MX1_PAD_A23__A23			0x1f 0x004
#define MX1_PAD_A23__GPIO1_31			0x1f 0x032
#define MX1_PAD_SD_DAT0__SD_DAT0		0x28 0x000
#define MX1_PAD_SD_DAT0__MS_PI0			0x28 0x001
#define MX1_PAD_SD_DAT0__GPIO2_8		0x28 0x032
#define MX1_PAD_SD_DAT1__SD_DAT1		0x29 0x000
#define MX1_PAD_SD_DAT1__MS_PI1			0x29 0x001
#define MX1_PAD_SD_DAT1__GPIO2_9		0x29 0x032
#define MX1_PAD_SD_DAT2__SD_DAT2		0x2a 0x000
#define MX1_PAD_SD_DAT2__MS_SCLKI		0x2a 0x001
#define MX1_PAD_SD_DAT2__GPIO2_10		0x2a 0x032
#define MX1_PAD_SD_DAT3__SD_DAT3		0x2b 0x000
#define MX1_PAD_SD_DAT3__MS_SDIO		0x2b 0x001
#define MX1_PAD_SD_DAT3__GPIO2_11		0x2b 0x032
#define MX1_PAD_SD_SCLK__SD_SCLK		0x2c 0x004
#define MX1_PAD_SD_SCLK__MS_SCLKO		0x2c 0x005
#define MX1_PAD_SD_SCLK__GPIO2_12		0x2c 0x032
#define MX1_PAD_SD_CMD__SD_CMD			0x2d 0x000
#define MX1_PAD_SD_CMD__MS_BS			0x2d 0x005
#define MX1_PAD_SD_CMD__GPIO2_13		0x2d 0x032
#define MX1_PAD_SIM_SVEN__SIM_SVEN		0x2e 0x004
#define MX1_PAD_SIM_SVEN__SSI_RXFS		0x2e 0x001
#define MX1_PAD_SIM_SVEN__GPIO2_14		0x2e 0x032
#define MX1_PAD_SIM_PD__SIM_PD			0x2f 0x000
#define MX1_PAD_SIM_PD__SSI_RXCLK		0x2f 0x001
#define MX1_PAD_SIM_PD__GPIO2_15		0x2f 0x032
#define MX1_PAD_SIM_TX__SIM_TX			0x30 0x000
#define MX1_PAD_SIM_TX__SSI_RXDAT		0x30 0x001
#define MX1_PAD_SIM_TX__GPIO2_16		0x30 0x032
#define MX1_PAD_SIM_RX__SIM_RX			0x31 0x000
#define MX1_PAD_SIM_RX__SSI_TXDAT		0x31 0x005
#define MX1_PAD_SIM_RX__GPIO2_17		0x31 0x032
#define MX1_PAD_SIM_RST__SIM_RST		0x32 0x004
#define MX1_PAD_SIM_RST__SSI_TXFS		0x32 0x001
#define MX1_PAD_SIM_RST__GPIO2_18		0x32 0x032
#define MX1_PAD_SIM_CLK__SIM_CLK		0x33 0x004
#define MX1_PAD_SIM_CLK__SSI_TXCLK		0x33 0x001
#define MX1_PAD_SIM_CLK__GPIO2_19		0x33 0x032
#define MX1_PAD_USBD_AFE__USBD_AFE		0x34 0x004
#define MX1_PAD_USBD_AFE__GPIO2_20		0x34 0x032
#define MX1_PAD_USBD_OE__USBD_OE		0x35 0x004
#define MX1_PAD_USBD_OE__GPIO2_21		0x35 0x032
#define MX1_PAD_USBD_RCV__USBD_RCV		0x36 0x000
#define MX1_PAD_USBD_RCV__GPIO2_22		0x36 0x032
#define MX1_PAD_USBD_SUSPND__USBD_SUSPND	0x37 0x004
#define MX1_PAD_USBD_SUSPND__GPIO2_23		0x37 0x032
#define MX1_PAD_USBD_VP__USBD_VP		0x38 0x000
#define MX1_PAD_USBD_VP__GPIO2_24		0x38 0x032
#define MX1_PAD_USBD_VM__USBD_VM		0x39 0x000
#define MX1_PAD_USBD_VM__GPIO2_25		0x39 0x032
#define MX1_PAD_USBD_VPO__USBD_VPO		0x3a 0x004
#define MX1_PAD_USBD_VPO__GPIO2_26		0x3a 0x032
#define MX1_PAD_USBD_VMO__USBD_VMO		0x3b 0x004
#define MX1_PAD_USBD_VMO__GPIO2_27		0x3b 0x032
#define MX1_PAD_UART2_CTS__UART2_CTS		0x3c 0x004
#define MX1_PAD_UART2_CTS__GPIO2_28		0x3c 0x032
#define MX1_PAD_UART2_RTS__UART2_RTS		0x3d 0x000
#define MX1_PAD_UART2_RTS__GPIO2_29		0x3d 0x032
#define MX1_PAD_UART2_TXD__UART2_TXD		0x3e 0x004
#define MX1_PAD_UART2_TXD__GPIO2_30		0x3e 0x032
#define MX1_PAD_UART2_RXD__UART2_RXD		0x3f 0x000
#define MX1_PAD_UART2_RXD__GPIO2_31		0x3f 0x032
#define MX1_PAD_SSI_RXFS__SSI_RXFS		0x43 0x000
#define MX1_PAD_SSI_RXFS__GPIO3_3		0x43 0x032
#define MX1_PAD_SSI_RXCLK__SSI_RXCLK		0x44 0x000
#define MX1_PAD_SSI_RXCLK__GPIO3_4		0x44 0x032
#define MX1_PAD_SSI_RXDAT__SSI_RXDAT		0x45 0x000
#define MX1_PAD_SSI_RXDAT__GPIO3_5		0x45 0x032
#define MX1_PAD_SSI_TXDAT__SSI_TXDAT		0x46 0x004
#define MX1_PAD_SSI_TXDAT__GPIO3_6		0x46 0x032
#define MX1_PAD_SSI_TXFS__SSI_TXFS		0x47 0x000
#define MX1_PAD_SSI_TXFS__GPIO3_7		0x47 0x032
#define MX1_PAD_SSI_TXCLK__SSI_TXCLK		0x48 0x000
#define MX1_PAD_SSI_TXCLK__GPIO3_8		0x48 0x032
#define MX1_PAD_UART1_CTS__UART1_CTS		0x49 0x004
#define MX1_PAD_UART1_CTS__GPIO3_9		0x49 0x032
#define MX1_PAD_UART1_RTS__UART1_RTS		0x4a 0x000
#define MX1_PAD_UART1_RTS__GPIO3_10		0x4a 0x032
#define MX1_PAD_UART1_TXD__UART1_TXD		0x4b 0x004
#define MX1_PAD_UART1_TXD__GPIO3_11		0x4b 0x032
#define MX1_PAD_UART1_RXD__UART1_RXD		0x4c 0x000
#define MX1_PAD_UART1_RXD__GPIO3_12		0x4c 0x032
#define MX1_PAD_SPI1_RDY__SPI1_RDY		0x4d 0x000
#define MX1_PAD_SPI1_RDY__GPIO3_13		0x4d 0x032
#define MX1_PAD_SPI1_SCLK__SPI1_SCLK		0x4e 0x004
#define MX1_PAD_SPI1_SCLK__GPIO3_14		0x4e 0x032
#define MX1_PAD_SPI1_SS__SPI1_SS		0x4f 0x000
#define MX1_PAD_SPI1_SS__GPIO3_15		0x4f 0x032
#define MX1_PAD_SPI1_MISO__SPI1_MISO		0x50 0x000
#define MX1_PAD_SPI1_MISO__GPIO3_16		0x50 0x032
#define MX1_PAD_SPI1_MOSI__SPI1_MOSI		0x51 0x004
#define MX1_PAD_SPI1_MOSI__GPIO3_17		0x51 0x032
#define MX1_PAD_BT13__BT13			0x53 0x004
#define MX1_PAD_BT13__SSI2_RXCLK		0x53 0x001
#define MX1_PAD_BT13__GPIO3_19			0x53 0x032
#define MX1_PAD_BT12__BT12			0x54 0x004
#define MX1_PAD_BT12__SSI2_TXFS			0x54 0x001
#define MX1_PAD_BT12__GPIO3_20			0x54 0x032
#define MX1_PAD_BT11__BT11			0x55 0x004
#define MX1_PAD_BT11__SSI2_TXCLK		0x55 0x001
#define MX1_PAD_BT11__GPIO3_21			0x55 0x032
#define MX1_PAD_BT10__BT10			0x56 0x004
#define MX1_PAD_BT10__SSI2_TX			0x56 0x001
#define MX1_PAD_BT10__GPIO3_22			0x56 0x032
#define MX1_PAD_BT9__BT9			0x57 0x004
#define MX1_PAD_BT9__SSI2_RX			0x57 0x001
#define MX1_PAD_BT9__GPIO3_23			0x57 0x032
#define MX1_PAD_BT8__BT8			0x58 0x004
#define MX1_PAD_BT8__SSI2_RXFS			0x58 0x001
#define MX1_PAD_BT8__GPIO3_24			0x58 0x032
#define MX1_PAD_BT8__UART3_RI			0x58 0x016
#define MX1_PAD_BT7__BT7			0x59 0x004
#define MX1_PAD_BT7__GPIO3_25			0x59 0x032
#define MX1_PAD_BT7__UART3_DSR			0x59 0x016
#define MX1_PAD_BT6__BT6			0x5a 0x004
#define MX1_PAD_BT6__GPIO3_26			0x5a 0x032
#define MX1_PAD_BT6__SPI2_SS3			0x5a 0x016
#define MX1_PAD_BT6__UART3_DTR			0x5a 0x022
#define MX1_PAD_BT5__BT5			0x5b 0x000
#define MX1_PAD_BT5__GPIO3_27			0x5b 0x032
#define MX1_PAD_BT5__UART3_DCD			0x5b 0x016
#define MX1_PAD_BT4__BT4			0x5c 0x000
#define MX1_PAD_BT4__GPIO3_28			0x5c 0x032
#define MX1_PAD_BT4__UART3_CTS			0x5c 0x016
#define MX1_PAD_BT3__BT3			0x5d 0x000
#define MX1_PAD_BT3__GPIO3_29			0x5d 0x032
#define MX1_PAD_BT3__UART3_RTS			0x5d 0x022
#define MX1_PAD_BT2__BT2			0x5e 0x004
#define MX1_PAD_BT2__GPIO3_30			0x5e 0x032
#define MX1_PAD_BT2__UART3_TX			0x5e 0x016
#define MX1_PAD_BT1__BT1			0x5f 0x000
#define MX1_PAD_BT1__GPIO3_31			0x5f 0x032
#define MX1_PAD_BT1__UART3_RX			0x5f 0x022
#define MX1_PAD_LSCLK__LSCLK			0x66 0x004
#define MX1_PAD_LSCLK__GPIO4_6			0x66 0x032
#define MX1_PAD_REV__REV			0x67 0x004
#define MX1_PAD_REV__UART2_DTR			0x67 0x001
#define MX1_PAD_REV__GPIO4_7			0x67 0x032
#define MX1_PAD_REV__SPI2_CLK			0x67 0x006
#define MX1_PAD_CLS__CLS			0x68 0x004
#define MX1_PAD_CLS__UART2_DCD			0x68 0x005
#define MX1_PAD_CLS__GPIO4_8			0x68 0x032
#define MX1_PAD_CLS__SPI2_SS			0x68 0x002
#define MX1_PAD_PS__PS				0x69 0x004
#define MX1_PAD_PS__UART2_RI			0x69 0x005
#define MX1_PAD_PS__GPIO4_9			0x69 0x032
#define MX1_PAD_PS__SPI2_RXD			0x69 0x022
#define MX1_PAD_SPL_SPR__SPL_SPR		0x6a 0x004
#define MX1_PAD_SPL_SPR__UART2_DSR		0x6a 0x005
#define MX1_PAD_SPL_SPR__GPIO4_10		0x6a 0x032
#define MX1_PAD_SPL_SPR__SPI2_TXD		0x6a 0x006
#define MX1_PAD_CONTRAST__CONTRAST		0x6b 0x004
#define MX1_PAD_CONTRAST__GPIO4_11		0x6b 0x032
#define MX1_PAD_CONTRAST__SPI2_SS2		0x6b 0x012
#define MX1_PAD_ACD_OE__ACD_OE			0x6c 0x004
#define MX1_PAD_ACD_OE__GPIO4_12		0x6c 0x032
#define MX1_PAD_LP_HSYNC__LP_HSYNC		0x6d 0x004
#define MX1_PAD_LP_HSYNC__GPIO4_13		0x6d 0x032
#define MX1_PAD_FLM_VSYNC__FLM_VSYNC		0x6e 0x004
#define MX1_PAD_FLM_VSYNC__GPIO4_14		0x6e 0x032
#define MX1_PAD_LD0__LD0			0x6f 0x004
#define MX1_PAD_LD0__GPIO4_15			0x6f 0x032
#define MX1_PAD_LD1__LD1			0x70 0x004
#define MX1_PAD_LD1__GPIO4_16			0x70 0x032
#define MX1_PAD_LD2__LD2			0x71 0x004
#define MX1_PAD_LD2__GPIO4_17			0x71 0x032
#define MX1_PAD_LD3__LD3			0x72 0x004
#define MX1_PAD_LD3__GPIO4_18			0x72 0x032
#define MX1_PAD_LD4__LD4			0x73 0x004
#define MX1_PAD_LD4__GPIO4_19			0x73 0x032
#define MX1_PAD_LD5__LD5			0x74 0x004
#define MX1_PAD_LD5__GPIO4_20			0x74 0x032
#define MX1_PAD_LD6__LD6			0x75 0x004
#define MX1_PAD_LD6__GPIO4_21			0x75 0x032
#define MX1_PAD_LD7__LD7			0x76 0x004
#define MX1_PAD_LD7__GPIO4_22			0x76 0x032
#define MX1_PAD_LD8__LD8			0x77 0x004
#define MX1_PAD_LD8__GPIO4_23			0x77 0x032
#define MX1_PAD_LD9__LD9			0x78 0x004
#define MX1_PAD_LD9__GPIO4_24			0x78 0x032
#define MX1_PAD_LD10__LD10			0x79 0x004
#define MX1_PAD_LD10__GPIO4_25			0x79 0x032
#define MX1_PAD_LD11__LD11			0x7a 0x004
#define MX1_PAD_LD11__GPIO4_26			0x7a 0x032
#define MX1_PAD_LD12__LD12			0x7b 0x004
#define MX1_PAD_LD12__GPIO4_27			0x7b 0x032
#define MX1_PAD_LD13__LD13			0x7c 0x004
#define MX1_PAD_LD13__GPIO4_28			0x7c 0x032
#define MX1_PAD_LD14__LD14			0x7d 0x004
#define MX1_PAD_LD14__GPIO4_29			0x7d 0x032
#define MX1_PAD_LD15__LD15			0x7e 0x004
#define MX1_PAD_LD15__GPIO4_30			0x7e 0x032
#define MX1_PAD_TMR2OUT__TMR2OUT		0x7f 0x000
#define MX1_PAD_TMR2OUT__GPIO4_31		0x7f 0x032
#define MX1_PAD_TMR2OUT__SPI2_TXD		0x7f 0x006

#endif
