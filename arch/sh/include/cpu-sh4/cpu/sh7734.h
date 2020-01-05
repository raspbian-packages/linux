/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_SH7734_H__
#define __ASM_SH7734_H__

/* Pin Function Controller:
 * GPIO_FN_xx - GPIO used to select pin function
 * GPIO_GP_x_x - GPIO mapped to real I/O pin on CPU
 */
enum {
	GPIO_GP_0_0, GPIO_GP_0_1, GPIO_GP_0_2, GPIO_GP_0_3,
	GPIO_GP_0_4, GPIO_GP_0_5, GPIO_GP_0_6, GPIO_GP_0_7,
	GPIO_GP_0_8, GPIO_GP_0_9, GPIO_GP_0_10, GPIO_GP_0_11,
	GPIO_GP_0_12, GPIO_GP_0_13, GPIO_GP_0_14, GPIO_GP_0_15,
	GPIO_GP_0_16, GPIO_GP_0_17, GPIO_GP_0_18, GPIO_GP_0_19,
	GPIO_GP_0_20, GPIO_GP_0_21, GPIO_GP_0_22, GPIO_GP_0_23,
	GPIO_GP_0_24, GPIO_GP_0_25, GPIO_GP_0_26, GPIO_GP_0_27,
	GPIO_GP_0_28, GPIO_GP_0_29, GPIO_GP_0_30, GPIO_GP_0_31,

	GPIO_GP_1_0, GPIO_GP_1_1, GPIO_GP_1_2, GPIO_GP_1_3,
	GPIO_GP_1_4, GPIO_GP_1_5, GPIO_GP_1_6, GPIO_GP_1_7,
	GPIO_GP_1_8, GPIO_GP_1_9, GPIO_GP_1_10, GPIO_GP_1_11,
	GPIO_GP_1_12, GPIO_GP_1_13, GPIO_GP_1_14, GPIO_GP_1_15,
	GPIO_GP_1_16, GPIO_GP_1_17, GPIO_GP_1_18, GPIO_GP_1_19,
	GPIO_GP_1_20, GPIO_GP_1_21, GPIO_GP_1_22, GPIO_GP_1_23,
	GPIO_GP_1_24, GPIO_GP_1_25, GPIO_GP_1_26, GPIO_GP_1_27,
	GPIO_GP_1_28, GPIO_GP_1_29, GPIO_GP_1_30, GPIO_GP_1_31,

	GPIO_GP_2_0, GPIO_GP_2_1, GPIO_GP_2_2, GPIO_GP_2_3,
	GPIO_GP_2_4, GPIO_GP_2_5, GPIO_GP_2_6, GPIO_GP_2_7,
	GPIO_GP_2_8, GPIO_GP_2_9, GPIO_GP_2_10, GPIO_GP_2_11,
	GPIO_GP_2_12, GPIO_GP_2_13, GPIO_GP_2_14, GPIO_GP_2_15,
	GPIO_GP_2_16, GPIO_GP_2_17, GPIO_GP_2_18, GPIO_GP_2_19,
	GPIO_GP_2_20, GPIO_GP_2_21, GPIO_GP_2_22, GPIO_GP_2_23,
	GPIO_GP_2_24, GPIO_GP_2_25, GPIO_GP_2_26, GPIO_GP_2_27,
	GPIO_GP_2_28, GPIO_GP_2_29, GPIO_GP_2_30, GPIO_GP_2_31,

	GPIO_GP_3_0, GPIO_GP_3_1, GPIO_GP_3_2, GPIO_GP_3_3,
	GPIO_GP_3_4, GPIO_GP_3_5, GPIO_GP_3_6, GPIO_GP_3_7,
	GPIO_GP_3_8, GPIO_GP_3_9, GPIO_GP_3_10, GPIO_GP_3_11,
	GPIO_GP_3_12, GPIO_GP_3_13, GPIO_GP_3_14, GPIO_GP_3_15,
	GPIO_GP_3_16, GPIO_GP_3_17, GPIO_GP_3_18, GPIO_GP_3_19,
	GPIO_GP_3_20, GPIO_GP_3_21, GPIO_GP_3_22, GPIO_GP_3_23,
	GPIO_GP_3_24, GPIO_GP_3_25, GPIO_GP_3_26, GPIO_GP_3_27,
	GPIO_GP_3_28, GPIO_GP_3_29, GPIO_GP_3_30, GPIO_GP_3_31,

	GPIO_GP_4_0, GPIO_GP_4_1, GPIO_GP_4_2, GPIO_GP_4_3,
	GPIO_GP_4_4, GPIO_GP_4_5, GPIO_GP_4_6, GPIO_GP_4_7,
	GPIO_GP_4_8, GPIO_GP_4_9, GPIO_GP_4_10, GPIO_GP_4_11,
	GPIO_GP_4_12, GPIO_GP_4_13, GPIO_GP_4_14, GPIO_GP_4_15,
	GPIO_GP_4_16, GPIO_GP_4_17, GPIO_GP_4_18, GPIO_GP_4_19,
	GPIO_GP_4_20, GPIO_GP_4_21, GPIO_GP_4_22, GPIO_GP_4_23,
	GPIO_GP_4_24, GPIO_GP_4_25, GPIO_GP_4_26, GPIO_GP_4_27,
	GPIO_GP_4_28, GPIO_GP_4_29, GPIO_GP_4_30, GPIO_GP_4_31,

	GPIO_GP_5_0, GPIO_GP_5_1, GPIO_GP_5_2, GPIO_GP_5_3,
	GPIO_GP_5_4, GPIO_GP_5_5, GPIO_GP_5_6, GPIO_GP_5_7,
	GPIO_GP_5_8, GPIO_GP_5_9, GPIO_GP_5_10, GPIO_GP_5_11,

	GPIO_FN_CLKOUT, GPIO_FN_BS, GPIO_FN_CS0, GPIO_FN_EX_CS0, GPIO_FN_RD,
		GPIO_FN_WE0, GPIO_FN_WE1,

	GPIO_FN_SCL0, GPIO_FN_PENC0, GPIO_FN_USB_OVC0,

	GPIO_FN_IRQ2_B, GPIO_FN_IRQ3_B,

	/* IPSR0 */
	GPIO_FN_A15, GPIO_FN_ST0_VCO_CLKIN, GPIO_FN_LCD_DATA15_A,
		GPIO_FN_TIOC3D_C,
	GPIO_FN_A14, GPIO_FN_LCD_DATA14_A, GPIO_FN_TIOC3C_C,
	GPIO_FN_A13, GPIO_FN_LCD_DATA13_A, GPIO_FN_TIOC3B_C,
	GPIO_FN_A12, GPIO_FN_LCD_DATA12_A, GPIO_FN_TIOC3A_C,
	GPIO_FN_A11, GPIO_FN_ST0_D7, GPIO_FN_LCD_DATA11_A,
		GPIO_FN_TIOC2B_C,
	GPIO_FN_A10, GPIO_FN_ST0_D6, GPIO_FN_LCD_DATA10_A,
		GPIO_FN_TIOC2A_C,
	GPIO_FN_A9, GPIO_FN_ST0_D5, GPIO_FN_LCD_DATA9_A,
		GPIO_FN_TIOC1B_C,
	GPIO_FN_A8, GPIO_FN_ST0_D4, GPIO_FN_LCD_DATA8_A,
		GPIO_FN_TIOC1A_C,
	GPIO_FN_A7, GPIO_FN_ST0_D3, GPIO_FN_LCD_DATA7_A, GPIO_FN_TIOC0D_C,
	GPIO_FN_A6, GPIO_FN_ST0_D2, GPIO_FN_LCD_DATA6_A, GPIO_FN_TIOC0C_C,
	GPIO_FN_A5, GPIO_FN_ST0_D1, GPIO_FN_LCD_DATA5_A, GPIO_FN_TIOC0B_C,
	GPIO_FN_A4, GPIO_FN_ST0_D0, GPIO_FN_LCD_DATA4_A, GPIO_FN_TIOC0A_C,
	GPIO_FN_A3, GPIO_FN_ST0_VLD, GPIO_FN_LCD_DATA3_A, GPIO_FN_TCLKD_C,
	GPIO_FN_A2, GPIO_FN_ST0_SYC, GPIO_FN_LCD_DATA2_A, GPIO_FN_TCLKC_C,
	GPIO_FN_A1, GPIO_FN_ST0_REQ, GPIO_FN_LCD_DATA1_A, GPIO_FN_TCLKB_C,
	GPIO_FN_A0, GPIO_FN_ST0_CLKIN, GPIO_FN_LCD_DATA0_A, GPIO_FN_TCLKA_C,

	/* IPSR1 */
	GPIO_FN_D3, GPIO_FN_SD0_DAT3_A, GPIO_FN_MMC_D3_A, GPIO_FN_ST1_D6,
		GPIO_FN_FD3_A,
	GPIO_FN_D2, GPIO_FN_SD0_DAT2_A, GPIO_FN_MMC_D2_A, GPIO_FN_ST1_D5,
		GPIO_FN_FD2_A,
	GPIO_FN_D1, GPIO_FN_SD0_DAT1_A, GPIO_FN_MMC_D1_A, GPIO_FN_ST1_D4,
		GPIO_FN_FD1_A,
	GPIO_FN_D0, GPIO_FN_SD0_DAT0_A, GPIO_FN_MMC_D0_A, GPIO_FN_ST1_D3,
		GPIO_FN_FD0_A,
	GPIO_FN_A25, GPIO_FN_TX2_D, GPIO_FN_ST1_D2,
	GPIO_FN_A24, GPIO_FN_RX2_D, GPIO_FN_ST1_D1,
	GPIO_FN_A23, GPIO_FN_ST1_D0, GPIO_FN_LCD_M_DISP_A,
	GPIO_FN_A22, GPIO_FN_ST1_VLD, GPIO_FN_LCD_VEPWC_A,
	GPIO_FN_A21, GPIO_FN_ST1_SYC, GPIO_FN_LCD_VCPWC_A,
	GPIO_FN_A20, GPIO_FN_ST1_REQ, GPIO_FN_LCD_FLM_A,
	GPIO_FN_A19, GPIO_FN_ST1_CLKIN, GPIO_FN_LCD_CLK_A, GPIO_FN_TIOC4D_C,
	GPIO_FN_A18, GPIO_FN_ST1_PWM, GPIO_FN_LCD_CL2_A, GPIO_FN_TIOC4C_C,
	GPIO_FN_A17, GPIO_FN_ST1_VCO_CLKIN, GPIO_FN_LCD_CL1_A, GPIO_FN_TIOC4B_C,
	GPIO_FN_A16, GPIO_FN_ST0_PWM, GPIO_FN_LCD_DON_A, GPIO_FN_TIOC4A_C,

	/* IPSR2 */
	GPIO_FN_D14, GPIO_FN_TX2_B, GPIO_FN_FSE_A, GPIO_FN_ET0_TX_CLK_B,
	GPIO_FN_D13, GPIO_FN_RX2_B, GPIO_FN_FRB_A,	GPIO_FN_ET0_ETXD6_B,
	GPIO_FN_D12, GPIO_FN_FWE_A, GPIO_FN_ET0_ETXD5_B,
	GPIO_FN_D11, GPIO_FN_RSPI_MISO_A, GPIO_FN_QMI_QIO1_A,
		GPIO_FN_FRE_A, GPIO_FN_ET0_ETXD3_B,
	GPIO_FN_D10, GPIO_FN_RSPI_MOSI_A, GPIO_FN_QMO_QIO0_A,
		GPIO_FN_FALE_A, GPIO_FN_ET0_ETXD2_B,
	GPIO_FN_D9, GPIO_FN_SD0_CMD_A, GPIO_FN_MMC_CMD_A, GPIO_FN_QIO3_A,
		GPIO_FN_FCLE_A, GPIO_FN_ET0_ETXD1_B,
	GPIO_FN_D8, GPIO_FN_SD0_CLK_A, GPIO_FN_MMC_CLK_A, GPIO_FN_QIO2_A,
		GPIO_FN_FCE_A, GPIO_FN_ET0_GTX_CLK_B,
	GPIO_FN_D7, GPIO_FN_RSPI_SSL_A, GPIO_FN_MMC_D7_A, GPIO_FN_QSSL_A,
		GPIO_FN_FD7_A,
	GPIO_FN_D6, GPIO_FN_RSPI_RSPCK_A, GPIO_FN_MMC_D6_A, GPIO_FN_QSPCLK_A,
		GPIO_FN_FD6_A,
	GPIO_FN_D5, GPIO_FN_SD0_WP_A, GPIO_FN_MMC_D5_A, GPIO_FN_FD5_A,
	GPIO_FN_D4, GPIO_FN_SD0_CD_A, GPIO_FN_MMC_D4_A, GPIO_FN_ST1_D7,
		GPIO_FN_FD4_A,

	/* IPSR3 */
	GPIO_FN_DRACK0, GPIO_FN_SD1_DAT2_A, GPIO_FN_ATAG, GPIO_FN_TCLK1_A,
		GPIO_FN_ET0_ETXD7,
	GPIO_FN_EX_WAIT2, GPIO_FN_SD1_DAT1_A, GPIO_FN_DACK2, GPIO_FN_CAN1_RX_C,
		GPIO_FN_ET0_MAGIC_C, GPIO_FN_ET0_ETXD6_A,
	GPIO_FN_EX_WAIT1, GPIO_FN_SD1_DAT0_A, GPIO_FN_DREQ2, GPIO_FN_CAN1_TX_C,
		GPIO_FN_ET0_LINK_C, GPIO_FN_ET0_ETXD5_A,
	GPIO_FN_EX_WAIT0, GPIO_FN_TCLK1_B,
	GPIO_FN_RD_WR, GPIO_FN_TCLK0, GPIO_FN_CAN_CLK_B, GPIO_FN_ET0_ETXD4,
	GPIO_FN_EX_CS5, GPIO_FN_SD1_CMD_A, GPIO_FN_ATADIR, GPIO_FN_QSSL_B,
		GPIO_FN_ET0_ETXD3_A,
	GPIO_FN_EX_CS4, GPIO_FN_SD1_WP_A, GPIO_FN_ATAWR, GPIO_FN_QMI_QIO1_B,
		GPIO_FN_ET0_ETXD2_A,
	GPIO_FN_EX_CS3, GPIO_FN_SD1_CD_A, GPIO_FN_ATARD, GPIO_FN_QMO_QIO0_B,
		GPIO_FN_ET0_ETXD1_A,
	GPIO_FN_EX_CS2, GPIO_FN_TX3_B, GPIO_FN_ATACS1, GPIO_FN_QSPCLK_B,
		GPIO_FN_ET0_GTX_CLK_A,
	GPIO_FN_EX_CS1, GPIO_FN_RX3_B, GPIO_FN_ATACS0, GPIO_FN_QIO2_B,
		GPIO_FN_ET0_ETXD0,
	GPIO_FN_CS1_A26, GPIO_FN_QIO3_B,
	GPIO_FN_D15, GPIO_FN_SCK2_B,

	/* IPSR4 */
	GPIO_FN_SCK2_A, GPIO_FN_VI0_G3,
	GPIO_FN_RTS1_B, GPIO_FN_VI0_G2,
	GPIO_FN_CTS1_B, GPIO_FN_VI0_DATA7_VI0_G1,
	GPIO_FN_TX1_B, GPIO_FN_VI0_DATA6_VI0_G0, GPIO_FN_ET0_PHY_INT_A,
	GPIO_FN_RX1_B, GPIO_FN_VI0_DATA5_VI0_B5, GPIO_FN_ET0_MAGIC_A,
	GPIO_FN_SCK1_B, GPIO_FN_VI0_DATA4_VI0_B4, GPIO_FN_ET0_LINK_A,
	GPIO_FN_RTS0_B, GPIO_FN_VI0_DATA3_VI0_B3, GPIO_FN_ET0_MDIO_A,
	GPIO_FN_CTS0_B, GPIO_FN_VI0_DATA2_VI0_B2, GPIO_FN_RMII0_MDIO_A,
		GPIO_FN_ET0_MDC,
	GPIO_FN_HTX0_A, GPIO_FN_TX1_A, GPIO_FN_VI0_DATA1_VI0_B1,
		GPIO_FN_RMII0_MDC_A, GPIO_FN_ET0_COL,
	GPIO_FN_HRX0_A, GPIO_FN_RX1_A, GPIO_FN_VI0_DATA0_VI0_B0,
		GPIO_FN_RMII0_CRS_DV_A, GPIO_FN_ET0_CRS,
	GPIO_FN_HSCK0_A, GPIO_FN_SCK1_A, GPIO_FN_VI0_VSYNC,
		GPIO_FN_RMII0_RX_ER_A, GPIO_FN_ET0_RX_ER,
	GPIO_FN_HRTS0_A, GPIO_FN_RTS1_A, GPIO_FN_VI0_HSYNC,
		GPIO_FN_RMII0_TXD_EN_A, GPIO_FN_ET0_RX_DV,
	GPIO_FN_HCTS0_A, GPIO_FN_CTS1_A, GPIO_FN_VI0_FIELD,
		GPIO_FN_RMII0_RXD1_A, GPIO_FN_ET0_ERXD7,

	/* IPSR5 */
	GPIO_FN_SD2_CLK_A, GPIO_FN_RX2_A, GPIO_FN_VI0_G4, GPIO_FN_ET0_RX_CLK_B,
	GPIO_FN_SD2_CMD_A, GPIO_FN_TX2_A, GPIO_FN_VI0_G5, GPIO_FN_ET0_ERXD2_B,
	GPIO_FN_SD2_DAT0_A, GPIO_FN_RX3_A, GPIO_FN_VI0_R0, GPIO_FN_ET0_ERXD3_B,
	GPIO_FN_SD2_DAT1_A, GPIO_FN_TX3_A, GPIO_FN_VI0_R1, GPIO_FN_ET0_MDIO_B,
	GPIO_FN_SD2_DAT2_A, GPIO_FN_RX4_A, GPIO_FN_VI0_R2, GPIO_FN_ET0_LINK_B,
	GPIO_FN_SD2_DAT3_A, GPIO_FN_TX4_A, GPIO_FN_VI0_R3, GPIO_FN_ET0_MAGIC_B,
	GPIO_FN_SD2_CD_A, GPIO_FN_RX5_A, GPIO_FN_VI0_R4, GPIO_FN_ET0_PHY_INT_B,
	GPIO_FN_SD2_WP_A, GPIO_FN_TX5_A, GPIO_FN_VI0_R5,
	GPIO_FN_REF125CK, GPIO_FN_ADTRG, GPIO_FN_RX5_C,
	GPIO_FN_REF50CK, GPIO_FN_CTS1_E, GPIO_FN_HCTS0_D,

	/* IPSR6 */
	GPIO_FN_DU0_DR0, GPIO_FN_SCIF_CLK_B, GPIO_FN_HRX0_D, GPIO_FN_IETX_A,
		GPIO_FN_TCLKA_A, GPIO_FN_HIFD00,
	GPIO_FN_DU0_DR1, GPIO_FN_SCK0_B, GPIO_FN_HTX0_D, GPIO_FN_IERX_A,
		GPIO_FN_TCLKB_A, GPIO_FN_HIFD01,
	GPIO_FN_DU0_DR2, GPIO_FN_RX0_B, GPIO_FN_TCLKC_A, GPIO_FN_HIFD02,
	GPIO_FN_DU0_DR3, GPIO_FN_TX0_B, GPIO_FN_TCLKD_A, GPIO_FN_HIFD03,
	GPIO_FN_DU0_DR4, GPIO_FN_CTS0_C, GPIO_FN_TIOC0A_A, GPIO_FN_HIFD04,
	GPIO_FN_DU0_DR5, GPIO_FN_RTS0_C, GPIO_FN_TIOC0B_A, GPIO_FN_HIFD05,
	GPIO_FN_DU0_DR6, GPIO_FN_SCK1_C, GPIO_FN_TIOC0C_A, GPIO_FN_HIFD06,
	GPIO_FN_DU0_DR7, GPIO_FN_RX1_C, GPIO_FN_TIOC0D_A, GPIO_FN_HIFD07,
	GPIO_FN_DU0_DG0, GPIO_FN_TX1_C, GPIO_FN_HSCK0_D, GPIO_FN_IECLK_A,
		GPIO_FN_TIOC1A_A, GPIO_FN_HIFD08,
	GPIO_FN_DU0_DG1, GPIO_FN_CTS1_C, GPIO_FN_HRTS0_D, GPIO_FN_TIOC1B_A,
		GPIO_FN_HIFD09,

	/* IPSR7 */
	GPIO_FN_DU0_DG2, GPIO_FN_RTS1_C, GPIO_FN_RMII0_MDC_B, GPIO_FN_TIOC2A_A,
		GPIO_FN_HIFD10,
	GPIO_FN_DU0_DG3, GPIO_FN_SCK2_C, GPIO_FN_RMII0_MDIO_B, GPIO_FN_TIOC2B_A,
		GPIO_FN_HIFD11,
	GPIO_FN_DU0_DG4, GPIO_FN_RX2_C, GPIO_FN_RMII0_CRS_DV_B,
		GPIO_FN_TIOC3A_A, GPIO_FN_HIFD12,
	GPIO_FN_DU0_DG5, GPIO_FN_TX2_C, GPIO_FN_RMII0_RX_ER_B,
		GPIO_FN_TIOC3B_A, GPIO_FN_HIFD13,
	GPIO_FN_DU0_DG6, GPIO_FN_RX3_C, GPIO_FN_RMII0_RXD0_B,
		GPIO_FN_TIOC3C_A, GPIO_FN_HIFD14,
	GPIO_FN_DU0_DG7, GPIO_FN_TX3_C, GPIO_FN_RMII0_RXD1_B,
		GPIO_FN_TIOC3D_A, GPIO_FN_HIFD15,
	GPIO_FN_DU0_DB0, GPIO_FN_RX4_C, GPIO_FN_RMII0_TXD_EN_B,
		GPIO_FN_TIOC4A_A, GPIO_FN_HIFCS,
	GPIO_FN_DU0_DB1, GPIO_FN_TX4_C, GPIO_FN_RMII0_TXD0_B,
		GPIO_FN_TIOC4B_A, GPIO_FN_HIFRS,
	GPIO_FN_DU0_DB2, GPIO_FN_RX5_B, GPIO_FN_RMII0_TXD1_B,
		GPIO_FN_TIOC4C_A, GPIO_FN_HIFWR,
	GPIO_FN_DU0_DB3, GPIO_FN_TX5_B, GPIO_FN_TIOC4D_A, GPIO_FN_HIFRD,
	GPIO_FN_DU0_DB4, GPIO_FN_HIFINT,

	/* IPSR8 */
	GPIO_FN_DU0_DB5, GPIO_FN_HIFDREQ,
	GPIO_FN_DU0_DB6, GPIO_FN_HIFRDY,
	GPIO_FN_DU0_DB7, GPIO_FN_SSI_SCK0_B, GPIO_FN_HIFEBL_B,
	GPIO_FN_DU0_DOTCLKIN, GPIO_FN_HSPI_CS0_C, GPIO_FN_SSI_WS0_B,
	GPIO_FN_DU0_DOTCLKOUT, GPIO_FN_HSPI_CLK0_C, GPIO_FN_SSI_SDATA0_B,
	GPIO_FN_DU0_EXHSYNC_DU0_HSYNC, GPIO_FN_HSPI_TX0_C, GPIO_FN_SSI_SCK1_B,
	GPIO_FN_DU0_EXVSYNC_DU0_VSYNC, GPIO_FN_HSPI_RX0_C, GPIO_FN_SSI_WS1_B,
	GPIO_FN_DU0_EXODDF_DU0_ODDF, GPIO_FN_CAN0_RX_B, GPIO_FN_HSCK0_B,
		GPIO_FN_SSI_SDATA1_B,
	GPIO_FN_DU0_DISP, GPIO_FN_CAN0_TX_B, GPIO_FN_HRX0_B,
		GPIO_FN_AUDIO_CLKA_B,
	GPIO_FN_DU0_CDE, GPIO_FN_HTX0_B, GPIO_FN_AUDIO_CLKB_B,
		GPIO_FN_LCD_VCPWC_B,
	GPIO_FN_IRQ0_A, GPIO_FN_HSPI_TX_B, GPIO_FN_RX3_E, GPIO_FN_ET0_ERXD0,
	GPIO_FN_IRQ1_A, GPIO_FN_HSPI_RX_B, GPIO_FN_TX3_E, GPIO_FN_ET0_ERXD1,
	GPIO_FN_IRQ2_A, GPIO_FN_CTS0_A, GPIO_FN_HCTS0_B, GPIO_FN_ET0_ERXD2_A,
	GPIO_FN_IRQ3_A, GPIO_FN_RTS0_A, GPIO_FN_HRTS0_B, GPIO_FN_ET0_ERXD3_A,

	/* IPSR9 */
	GPIO_FN_VI1_CLK_A, GPIO_FN_FD0_B, GPIO_FN_LCD_DATA0_B,
	GPIO_FN_VI1_0_A, GPIO_FN_FD1_B, GPIO_FN_LCD_DATA1_B,
	GPIO_FN_VI1_1_A, GPIO_FN_FD2_B, GPIO_FN_LCD_DATA2_B,
	GPIO_FN_VI1_2_A, GPIO_FN_FD3_B, GPIO_FN_LCD_DATA3_B,
	GPIO_FN_VI1_3_A, GPIO_FN_FD4_B, GPIO_FN_LCD_DATA4_B,
	GPIO_FN_VI1_4_A, GPIO_FN_FD5_B, GPIO_FN_LCD_DATA5_B,
	GPIO_FN_VI1_5_A, GPIO_FN_FD6_B, GPIO_FN_LCD_DATA6_B,
	GPIO_FN_VI1_6_A, GPIO_FN_FD7_B, GPIO_FN_LCD_DATA7_B,
	GPIO_FN_VI1_7_A, GPIO_FN_FCE_B, GPIO_FN_LCD_DATA8_B,
	GPIO_FN_SSI_SCK0_A, GPIO_FN_TIOC1A_B, GPIO_FN_LCD_DATA9_B,
	GPIO_FN_SSI_WS0_A, GPIO_FN_TIOC1B_B, GPIO_FN_LCD_DATA10_B,
	GPIO_FN_SSI_SDATA0_A, GPIO_FN_VI1_0_B, GPIO_FN_TIOC2A_B,
		GPIO_FN_LCD_DATA11_B,
	GPIO_FN_SSI_SCK1_A, GPIO_FN_VI1_1_B, GPIO_FN_TIOC2B_B,
		GPIO_FN_LCD_DATA12_B,
	GPIO_FN_SSI_WS1_A, GPIO_FN_VI1_2_B, GPIO_FN_LCD_DATA13_B,
	GPIO_FN_SSI_SDATA1_A, GPIO_FN_VI1_3_B, GPIO_FN_LCD_DATA14_B,

	/* IPSR10 */
	GPIO_FN_SSI_SCK23, GPIO_FN_VI1_4_B, GPIO_FN_RX1_D, GPIO_FN_FCLE_B,
		GPIO_FN_LCD_DATA15_B,
	GPIO_FN_SSI_WS23, GPIO_FN_VI1_5_B, GPIO_FN_TX1_D, GPIO_FN_HSCK0_C,
		GPIO_FN_FALE_B, GPIO_FN_LCD_DON_B,
	GPIO_FN_SSI_SDATA2, GPIO_FN_VI1_6_B, GPIO_FN_HRX0_C, GPIO_FN_FRE_B,
		GPIO_FN_LCD_CL1_B,
	GPIO_FN_SSI_SDATA3, GPIO_FN_VI1_7_B, GPIO_FN_HTX0_C, GPIO_FN_FWE_B,
		GPIO_FN_LCD_CL2_B,
	GPIO_FN_AUDIO_CLKA_A, GPIO_FN_VI1_CLK_B, GPIO_FN_SCK1_D,
		GPIO_FN_IECLK_B, GPIO_FN_LCD_FLM_B,
	GPIO_FN_AUDIO_CLKB_A, GPIO_FN_LCD_CLK_B,
	GPIO_FN_AUDIO_CLKC, GPIO_FN_SCK1_E, GPIO_FN_HCTS0_C, GPIO_FN_FRB_B,
		GPIO_FN_LCD_VEPWC_B,
	GPIO_FN_AUDIO_CLKOUT, GPIO_FN_TX1_E, GPIO_FN_HRTS0_C, GPIO_FN_FSE_B,
		GPIO_FN_LCD_M_DISP_B,
	GPIO_FN_CAN_CLK_A, GPIO_FN_RX4_D,
	GPIO_FN_CAN0_TX_A, GPIO_FN_TX4_D, GPIO_FN_MLB_CLK,
	GPIO_FN_CAN1_RX_A, GPIO_FN_IRQ1_B,
	GPIO_FN_CAN0_RX_A, GPIO_FN_IRQ0_B, GPIO_FN_MLB_SIG,
	GPIO_FN_CAN1_TX_A, GPIO_FN_TX5_C, GPIO_FN_MLB_DAT,

	/* IPSR11 */
	GPIO_FN_SCL1, GPIO_FN_SCIF_CLK_C,
	GPIO_FN_SDA1, GPIO_FN_RX1_E,
	GPIO_FN_SDA0, GPIO_FN_HIFEBL_A,
	GPIO_FN_SDSELF, GPIO_FN_RTS1_E,
	GPIO_FN_SCIF_CLK_A, GPIO_FN_HSPI_CLK_A, GPIO_FN_VI0_CLK,
		GPIO_FN_RMII0_TXD0_A, GPIO_FN_ET0_ERXD4,
	GPIO_FN_SCK0_A, GPIO_FN_HSPI_CS_A, GPIO_FN_VI0_CLKENB,
		GPIO_FN_RMII0_TXD1_A, GPIO_FN_ET0_ERXD5,
	GPIO_FN_RX0_A, GPIO_FN_HSPI_RX_A, GPIO_FN_RMII0_RXD0_A,
		GPIO_FN_ET0_ERXD6,
	GPIO_FN_TX0_A, GPIO_FN_HSPI_TX_A,
	GPIO_FN_PENC1, GPIO_FN_TX3_D, GPIO_FN_CAN1_TX_B, GPIO_FN_TX5_D,
		GPIO_FN_IETX_B,
	GPIO_FN_USB_OVC1, GPIO_FN_RX3_D, GPIO_FN_CAN1_RX_B, GPIO_FN_RX5_D,
		GPIO_FN_IERX_B,
	GPIO_FN_DREQ0, GPIO_FN_SD1_CLK_A, GPIO_FN_ET0_TX_EN,
	GPIO_FN_DACK0, GPIO_FN_SD1_DAT3_A, GPIO_FN_ET0_TX_ER,
	GPIO_FN_DREQ1, GPIO_FN_HSPI_CLK_B, GPIO_FN_RX4_B, GPIO_FN_ET0_PHY_INT_C,
		GPIO_FN_ET0_TX_CLK_A,
	GPIO_FN_DACK1, GPIO_FN_HSPI_CS_B, GPIO_FN_TX4_B, GPIO_FN_ET0_RX_CLK_A,
	GPIO_FN_PRESETOUT, GPIO_FN_ST_CLKOUT,

};

#endif /* __ASM_SH7734_H__ */
