// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2017~2018 NXP
 *	Dong Aisheng <aisheng.dong@nxp.com>
 */

#include <dt-bindings/pinctrl/pads-imx8qm.h>
#include <linux/err.h>
#include <linux/firmware/imx/sci.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/platform_device.h>

#include "pinctrl-imx.h"

static const struct pinctrl_pin_desc imx8qm_pinctrl_pads[] = {
	IMX_PINCTRL_PIN(IMX8QM_SIM0_CLK),
	IMX_PINCTRL_PIN(IMX8QM_SIM0_RST),
	IMX_PINCTRL_PIN(IMX8QM_SIM0_IO),
	IMX_PINCTRL_PIN(IMX8QM_SIM0_PD),
	IMX_PINCTRL_PIN(IMX8QM_SIM0_POWER_EN),
	IMX_PINCTRL_PIN(IMX8QM_SIM0_GPIO0_00),
	IMX_PINCTRL_PIN(IMX8QM_COMP_CTL_GPIO_1V8_3V3_SIM),
	IMX_PINCTRL_PIN(IMX8QM_M40_I2C0_SCL),
	IMX_PINCTRL_PIN(IMX8QM_M40_I2C0_SDA),
	IMX_PINCTRL_PIN(IMX8QM_M40_GPIO0_00),
	IMX_PINCTRL_PIN(IMX8QM_M40_GPIO0_01),
	IMX_PINCTRL_PIN(IMX8QM_M41_I2C0_SCL),
	IMX_PINCTRL_PIN(IMX8QM_M41_I2C0_SDA),
	IMX_PINCTRL_PIN(IMX8QM_M41_GPIO0_00),
	IMX_PINCTRL_PIN(IMX8QM_M41_GPIO0_01),
	IMX_PINCTRL_PIN(IMX8QM_GPT0_CLK),
	IMX_PINCTRL_PIN(IMX8QM_GPT0_CAPTURE),
	IMX_PINCTRL_PIN(IMX8QM_GPT0_COMPARE),
	IMX_PINCTRL_PIN(IMX8QM_GPT1_CLK),
	IMX_PINCTRL_PIN(IMX8QM_GPT1_CAPTURE),
	IMX_PINCTRL_PIN(IMX8QM_GPT1_COMPARE),
	IMX_PINCTRL_PIN(IMX8QM_UART0_RX),
	IMX_PINCTRL_PIN(IMX8QM_UART0_TX),
	IMX_PINCTRL_PIN(IMX8QM_UART0_RTS_B),
	IMX_PINCTRL_PIN(IMX8QM_UART0_CTS_B),
	IMX_PINCTRL_PIN(IMX8QM_UART1_TX),
	IMX_PINCTRL_PIN(IMX8QM_UART1_RX),
	IMX_PINCTRL_PIN(IMX8QM_UART1_RTS_B),
	IMX_PINCTRL_PIN(IMX8QM_UART1_CTS_B),
	IMX_PINCTRL_PIN(IMX8QM_COMP_CTL_GPIO_1V8_3V3_GPIOLH),
	IMX_PINCTRL_PIN(IMX8QM_SCU_PMIC_MEMC_ON),
	IMX_PINCTRL_PIN(IMX8QM_SCU_WDOG_OUT),
	IMX_PINCTRL_PIN(IMX8QM_PMIC_I2C_SDA),
	IMX_PINCTRL_PIN(IMX8QM_PMIC_I2C_SCL),
	IMX_PINCTRL_PIN(IMX8QM_PMIC_EARLY_WARNING),
	IMX_PINCTRL_PIN(IMX8QM_PMIC_INT_B),
	IMX_PINCTRL_PIN(IMX8QM_SCU_GPIO0_00),
	IMX_PINCTRL_PIN(IMX8QM_SCU_GPIO0_01),
	IMX_PINCTRL_PIN(IMX8QM_SCU_GPIO0_02),
	IMX_PINCTRL_PIN(IMX8QM_SCU_GPIO0_03),
	IMX_PINCTRL_PIN(IMX8QM_SCU_GPIO0_04),
	IMX_PINCTRL_PIN(IMX8QM_SCU_GPIO0_05),
	IMX_PINCTRL_PIN(IMX8QM_SCU_GPIO0_06),
	IMX_PINCTRL_PIN(IMX8QM_SCU_GPIO0_07),
	IMX_PINCTRL_PIN(IMX8QM_SCU_BOOT_MODE0),
	IMX_PINCTRL_PIN(IMX8QM_SCU_BOOT_MODE1),
	IMX_PINCTRL_PIN(IMX8QM_SCU_BOOT_MODE2),
	IMX_PINCTRL_PIN(IMX8QM_SCU_BOOT_MODE3),
	IMX_PINCTRL_PIN(IMX8QM_SCU_BOOT_MODE4),
	IMX_PINCTRL_PIN(IMX8QM_SCU_BOOT_MODE5),
	IMX_PINCTRL_PIN(IMX8QM_LVDS0_GPIO00),
	IMX_PINCTRL_PIN(IMX8QM_LVDS0_GPIO01),
	IMX_PINCTRL_PIN(IMX8QM_LVDS0_I2C0_SCL),
	IMX_PINCTRL_PIN(IMX8QM_LVDS0_I2C0_SDA),
	IMX_PINCTRL_PIN(IMX8QM_LVDS0_I2C1_SCL),
	IMX_PINCTRL_PIN(IMX8QM_LVDS0_I2C1_SDA),
	IMX_PINCTRL_PIN(IMX8QM_LVDS1_GPIO00),
	IMX_PINCTRL_PIN(IMX8QM_LVDS1_GPIO01),
	IMX_PINCTRL_PIN(IMX8QM_LVDS1_I2C0_SCL),
	IMX_PINCTRL_PIN(IMX8QM_LVDS1_I2C0_SDA),
	IMX_PINCTRL_PIN(IMX8QM_LVDS1_I2C1_SCL),
	IMX_PINCTRL_PIN(IMX8QM_LVDS1_I2C1_SDA),
	IMX_PINCTRL_PIN(IMX8QM_COMP_CTL_GPIO_1V8_3V3_LVDSGPIO),
	IMX_PINCTRL_PIN(IMX8QM_MIPI_DSI0_I2C0_SCL),
	IMX_PINCTRL_PIN(IMX8QM_MIPI_DSI0_I2C0_SDA),
	IMX_PINCTRL_PIN(IMX8QM_MIPI_DSI0_GPIO0_00),
	IMX_PINCTRL_PIN(IMX8QM_MIPI_DSI0_GPIO0_01),
	IMX_PINCTRL_PIN(IMX8QM_MIPI_DSI1_I2C0_SCL),
	IMX_PINCTRL_PIN(IMX8QM_MIPI_DSI1_I2C0_SDA),
	IMX_PINCTRL_PIN(IMX8QM_MIPI_DSI1_GPIO0_00),
	IMX_PINCTRL_PIN(IMX8QM_MIPI_DSI1_GPIO0_01),
	IMX_PINCTRL_PIN(IMX8QM_COMP_CTL_GPIO_1V8_3V3_MIPIDSIGPIO),
	IMX_PINCTRL_PIN(IMX8QM_MIPI_CSI0_MCLK_OUT),
	IMX_PINCTRL_PIN(IMX8QM_MIPI_CSI0_I2C0_SCL),
	IMX_PINCTRL_PIN(IMX8QM_MIPI_CSI0_I2C0_SDA),
	IMX_PINCTRL_PIN(IMX8QM_MIPI_CSI0_GPIO0_00),
	IMX_PINCTRL_PIN(IMX8QM_MIPI_CSI0_GPIO0_01),
	IMX_PINCTRL_PIN(IMX8QM_MIPI_CSI1_MCLK_OUT),
	IMX_PINCTRL_PIN(IMX8QM_MIPI_CSI1_GPIO0_00),
	IMX_PINCTRL_PIN(IMX8QM_MIPI_CSI1_GPIO0_01),
	IMX_PINCTRL_PIN(IMX8QM_MIPI_CSI1_I2C0_SCL),
	IMX_PINCTRL_PIN(IMX8QM_MIPI_CSI1_I2C0_SDA),
	IMX_PINCTRL_PIN(IMX8QM_HDMI_TX0_TS_SCL),
	IMX_PINCTRL_PIN(IMX8QM_HDMI_TX0_TS_SDA),
	IMX_PINCTRL_PIN(IMX8QM_COMP_CTL_GPIO_3V3_HDMIGPIO),
	IMX_PINCTRL_PIN(IMX8QM_ESAI1_FSR),
	IMX_PINCTRL_PIN(IMX8QM_ESAI1_FST),
	IMX_PINCTRL_PIN(IMX8QM_ESAI1_SCKR),
	IMX_PINCTRL_PIN(IMX8QM_ESAI1_SCKT),
	IMX_PINCTRL_PIN(IMX8QM_ESAI1_TX0),
	IMX_PINCTRL_PIN(IMX8QM_ESAI1_TX1),
	IMX_PINCTRL_PIN(IMX8QM_ESAI1_TX2_RX3),
	IMX_PINCTRL_PIN(IMX8QM_ESAI1_TX3_RX2),
	IMX_PINCTRL_PIN(IMX8QM_ESAI1_TX4_RX1),
	IMX_PINCTRL_PIN(IMX8QM_ESAI1_TX5_RX0),
	IMX_PINCTRL_PIN(IMX8QM_SPDIF0_RX),
	IMX_PINCTRL_PIN(IMX8QM_SPDIF0_TX),
	IMX_PINCTRL_PIN(IMX8QM_SPDIF0_EXT_CLK),
	IMX_PINCTRL_PIN(IMX8QM_SPI3_SCK),
	IMX_PINCTRL_PIN(IMX8QM_SPI3_SDO),
	IMX_PINCTRL_PIN(IMX8QM_SPI3_SDI),
	IMX_PINCTRL_PIN(IMX8QM_SPI3_CS0),
	IMX_PINCTRL_PIN(IMX8QM_SPI3_CS1),
	IMX_PINCTRL_PIN(IMX8QM_COMP_CTL_GPIO_1V8_3V3_GPIORHB),
	IMX_PINCTRL_PIN(IMX8QM_ESAI0_FSR),
	IMX_PINCTRL_PIN(IMX8QM_ESAI0_FST),
	IMX_PINCTRL_PIN(IMX8QM_ESAI0_SCKR),
	IMX_PINCTRL_PIN(IMX8QM_ESAI0_SCKT),
	IMX_PINCTRL_PIN(IMX8QM_ESAI0_TX0),
	IMX_PINCTRL_PIN(IMX8QM_ESAI0_TX1),
	IMX_PINCTRL_PIN(IMX8QM_ESAI0_TX2_RX3),
	IMX_PINCTRL_PIN(IMX8QM_ESAI0_TX3_RX2),
	IMX_PINCTRL_PIN(IMX8QM_ESAI0_TX4_RX1),
	IMX_PINCTRL_PIN(IMX8QM_ESAI0_TX5_RX0),
	IMX_PINCTRL_PIN(IMX8QM_MCLK_IN0),
	IMX_PINCTRL_PIN(IMX8QM_MCLK_OUT0),
	IMX_PINCTRL_PIN(IMX8QM_COMP_CTL_GPIO_1V8_3V3_GPIORHC),
	IMX_PINCTRL_PIN(IMX8QM_SPI0_SCK),
	IMX_PINCTRL_PIN(IMX8QM_SPI0_SDO),
	IMX_PINCTRL_PIN(IMX8QM_SPI0_SDI),
	IMX_PINCTRL_PIN(IMX8QM_SPI0_CS0),
	IMX_PINCTRL_PIN(IMX8QM_SPI0_CS1),
	IMX_PINCTRL_PIN(IMX8QM_SPI2_SCK),
	IMX_PINCTRL_PIN(IMX8QM_SPI2_SDO),
	IMX_PINCTRL_PIN(IMX8QM_SPI2_SDI),
	IMX_PINCTRL_PIN(IMX8QM_SPI2_CS0),
	IMX_PINCTRL_PIN(IMX8QM_SPI2_CS1),
	IMX_PINCTRL_PIN(IMX8QM_SAI1_RXC),
	IMX_PINCTRL_PIN(IMX8QM_SAI1_RXD),
	IMX_PINCTRL_PIN(IMX8QM_SAI1_RXFS),
	IMX_PINCTRL_PIN(IMX8QM_SAI1_TXC),
	IMX_PINCTRL_PIN(IMX8QM_SAI1_TXD),
	IMX_PINCTRL_PIN(IMX8QM_SAI1_TXFS),
	IMX_PINCTRL_PIN(IMX8QM_COMP_CTL_GPIO_1V8_3V3_GPIORHT),
	IMX_PINCTRL_PIN(IMX8QM_ADC_IN7),
	IMX_PINCTRL_PIN(IMX8QM_ADC_IN6),
	IMX_PINCTRL_PIN(IMX8QM_ADC_IN5),
	IMX_PINCTRL_PIN(IMX8QM_ADC_IN4),
	IMX_PINCTRL_PIN(IMX8QM_ADC_IN3),
	IMX_PINCTRL_PIN(IMX8QM_ADC_IN2),
	IMX_PINCTRL_PIN(IMX8QM_ADC_IN1),
	IMX_PINCTRL_PIN(IMX8QM_ADC_IN0),
	IMX_PINCTRL_PIN(IMX8QM_MLB_SIG),
	IMX_PINCTRL_PIN(IMX8QM_MLB_CLK),
	IMX_PINCTRL_PIN(IMX8QM_MLB_DATA),
	IMX_PINCTRL_PIN(IMX8QM_COMP_CTL_GPIO_1V8_3V3_GPIOLHT),
	IMX_PINCTRL_PIN(IMX8QM_FLEXCAN0_RX),
	IMX_PINCTRL_PIN(IMX8QM_FLEXCAN0_TX),
	IMX_PINCTRL_PIN(IMX8QM_FLEXCAN1_RX),
	IMX_PINCTRL_PIN(IMX8QM_FLEXCAN1_TX),
	IMX_PINCTRL_PIN(IMX8QM_FLEXCAN2_RX),
	IMX_PINCTRL_PIN(IMX8QM_FLEXCAN2_TX),
	IMX_PINCTRL_PIN(IMX8QM_COMP_CTL_GPIO_1V8_3V3_GPIOTHR),
	IMX_PINCTRL_PIN(IMX8QM_USB_SS3_TC0),
	IMX_PINCTRL_PIN(IMX8QM_USB_SS3_TC1),
	IMX_PINCTRL_PIN(IMX8QM_USB_SS3_TC2),
	IMX_PINCTRL_PIN(IMX8QM_USB_SS3_TC3),
	IMX_PINCTRL_PIN(IMX8QM_COMP_CTL_GPIO_3V3_USB3IO),
	IMX_PINCTRL_PIN(IMX8QM_USDHC1_RESET_B),
	IMX_PINCTRL_PIN(IMX8QM_USDHC1_VSELECT),
	IMX_PINCTRL_PIN(IMX8QM_USDHC2_RESET_B),
	IMX_PINCTRL_PIN(IMX8QM_USDHC2_VSELECT),
	IMX_PINCTRL_PIN(IMX8QM_USDHC2_WP),
	IMX_PINCTRL_PIN(IMX8QM_USDHC2_CD_B),
	IMX_PINCTRL_PIN(IMX8QM_COMP_CTL_GPIO_1V8_3V3_VSELSEP),
	IMX_PINCTRL_PIN(IMX8QM_ENET0_MDIO),
	IMX_PINCTRL_PIN(IMX8QM_ENET0_MDC),
	IMX_PINCTRL_PIN(IMX8QM_ENET0_REFCLK_125M_25M),
	IMX_PINCTRL_PIN(IMX8QM_ENET1_REFCLK_125M_25M),
	IMX_PINCTRL_PIN(IMX8QM_ENET1_MDIO),
	IMX_PINCTRL_PIN(IMX8QM_ENET1_MDC),
	IMX_PINCTRL_PIN(IMX8QM_COMP_CTL_GPIO_1V8_3V3_GPIOCT),
	IMX_PINCTRL_PIN(IMX8QM_QSPI1A_SS0_B),
	IMX_PINCTRL_PIN(IMX8QM_QSPI1A_SS1_B),
	IMX_PINCTRL_PIN(IMX8QM_QSPI1A_SCLK),
	IMX_PINCTRL_PIN(IMX8QM_QSPI1A_DQS),
	IMX_PINCTRL_PIN(IMX8QM_QSPI1A_DATA3),
	IMX_PINCTRL_PIN(IMX8QM_QSPI1A_DATA2),
	IMX_PINCTRL_PIN(IMX8QM_QSPI1A_DATA1),
	IMX_PINCTRL_PIN(IMX8QM_QSPI1A_DATA0),
	IMX_PINCTRL_PIN(IMX8QM_COMP_CTL_GPIO_1V8_3V3_QSPI1),
	IMX_PINCTRL_PIN(IMX8QM_QSPI0A_DATA0),
	IMX_PINCTRL_PIN(IMX8QM_QSPI0A_DATA1),
	IMX_PINCTRL_PIN(IMX8QM_QSPI0A_DATA2),
	IMX_PINCTRL_PIN(IMX8QM_QSPI0A_DATA3),
	IMX_PINCTRL_PIN(IMX8QM_QSPI0A_DQS),
	IMX_PINCTRL_PIN(IMX8QM_QSPI0A_SS0_B),
	IMX_PINCTRL_PIN(IMX8QM_QSPI0A_SS1_B),
	IMX_PINCTRL_PIN(IMX8QM_QSPI0A_SCLK),
	IMX_PINCTRL_PIN(IMX8QM_QSPI0B_SCLK),
	IMX_PINCTRL_PIN(IMX8QM_QSPI0B_DATA0),
	IMX_PINCTRL_PIN(IMX8QM_QSPI0B_DATA1),
	IMX_PINCTRL_PIN(IMX8QM_QSPI0B_DATA2),
	IMX_PINCTRL_PIN(IMX8QM_QSPI0B_DATA3),
	IMX_PINCTRL_PIN(IMX8QM_QSPI0B_DQS),
	IMX_PINCTRL_PIN(IMX8QM_QSPI0B_SS0_B),
	IMX_PINCTRL_PIN(IMX8QM_QSPI0B_SS1_B),
	IMX_PINCTRL_PIN(IMX8QM_COMP_CTL_GPIO_1V8_3V3_QSPI0),
	IMX_PINCTRL_PIN(IMX8QM_PCIE_CTRL0_CLKREQ_B),
	IMX_PINCTRL_PIN(IMX8QM_PCIE_CTRL0_WAKE_B),
	IMX_PINCTRL_PIN(IMX8QM_PCIE_CTRL0_PERST_B),
	IMX_PINCTRL_PIN(IMX8QM_PCIE_CTRL1_CLKREQ_B),
	IMX_PINCTRL_PIN(IMX8QM_PCIE_CTRL1_WAKE_B),
	IMX_PINCTRL_PIN(IMX8QM_PCIE_CTRL1_PERST_B),
	IMX_PINCTRL_PIN(IMX8QM_COMP_CTL_GPIO_1V8_3V3_PCIESEP),
	IMX_PINCTRL_PIN(IMX8QM_USB_HSIC0_DATA),
	IMX_PINCTRL_PIN(IMX8QM_USB_HSIC0_STROBE),
	IMX_PINCTRL_PIN(IMX8QM_CALIBRATION_0_HSIC),
	IMX_PINCTRL_PIN(IMX8QM_CALIBRATION_1_HSIC),
	IMX_PINCTRL_PIN(IMX8QM_EMMC0_CLK),
	IMX_PINCTRL_PIN(IMX8QM_EMMC0_CMD),
	IMX_PINCTRL_PIN(IMX8QM_EMMC0_DATA0),
	IMX_PINCTRL_PIN(IMX8QM_EMMC0_DATA1),
	IMX_PINCTRL_PIN(IMX8QM_EMMC0_DATA2),
	IMX_PINCTRL_PIN(IMX8QM_EMMC0_DATA3),
	IMX_PINCTRL_PIN(IMX8QM_EMMC0_DATA4),
	IMX_PINCTRL_PIN(IMX8QM_EMMC0_DATA5),
	IMX_PINCTRL_PIN(IMX8QM_EMMC0_DATA6),
	IMX_PINCTRL_PIN(IMX8QM_EMMC0_DATA7),
	IMX_PINCTRL_PIN(IMX8QM_EMMC0_STROBE),
	IMX_PINCTRL_PIN(IMX8QM_EMMC0_RESET_B),
	IMX_PINCTRL_PIN(IMX8QM_COMP_CTL_GPIO_1V8_3V3_SD1FIX),
	IMX_PINCTRL_PIN(IMX8QM_USDHC1_CLK),
	IMX_PINCTRL_PIN(IMX8QM_USDHC1_CMD),
	IMX_PINCTRL_PIN(IMX8QM_USDHC1_DATA0),
	IMX_PINCTRL_PIN(IMX8QM_USDHC1_DATA1),
	IMX_PINCTRL_PIN(IMX8QM_CTL_NAND_RE_P_N),
	IMX_PINCTRL_PIN(IMX8QM_USDHC1_DATA2),
	IMX_PINCTRL_PIN(IMX8QM_USDHC1_DATA3),
	IMX_PINCTRL_PIN(IMX8QM_CTL_NAND_DQS_P_N),
	IMX_PINCTRL_PIN(IMX8QM_USDHC1_DATA4),
	IMX_PINCTRL_PIN(IMX8QM_USDHC1_DATA5),
	IMX_PINCTRL_PIN(IMX8QM_USDHC1_DATA6),
	IMX_PINCTRL_PIN(IMX8QM_USDHC1_DATA7),
	IMX_PINCTRL_PIN(IMX8QM_USDHC1_STROBE),
	IMX_PINCTRL_PIN(IMX8QM_COMP_CTL_GPIO_1V8_3V3_VSEL2),
	IMX_PINCTRL_PIN(IMX8QM_USDHC2_CLK),
	IMX_PINCTRL_PIN(IMX8QM_USDHC2_CMD),
	IMX_PINCTRL_PIN(IMX8QM_USDHC2_DATA0),
	IMX_PINCTRL_PIN(IMX8QM_USDHC2_DATA1),
	IMX_PINCTRL_PIN(IMX8QM_USDHC2_DATA2),
	IMX_PINCTRL_PIN(IMX8QM_USDHC2_DATA3),
	IMX_PINCTRL_PIN(IMX8QM_COMP_CTL_GPIO_1V8_3V3_VSEL3),
	IMX_PINCTRL_PIN(IMX8QM_ENET0_RGMII_TXC),
	IMX_PINCTRL_PIN(IMX8QM_ENET0_RGMII_TX_CTL),
	IMX_PINCTRL_PIN(IMX8QM_ENET0_RGMII_TXD0),
	IMX_PINCTRL_PIN(IMX8QM_ENET0_RGMII_TXD1),
	IMX_PINCTRL_PIN(IMX8QM_ENET0_RGMII_TXD2),
	IMX_PINCTRL_PIN(IMX8QM_ENET0_RGMII_TXD3),
	IMX_PINCTRL_PIN(IMX8QM_ENET0_RGMII_RXC),
	IMX_PINCTRL_PIN(IMX8QM_ENET0_RGMII_RX_CTL),
	IMX_PINCTRL_PIN(IMX8QM_ENET0_RGMII_RXD0),
	IMX_PINCTRL_PIN(IMX8QM_ENET0_RGMII_RXD1),
	IMX_PINCTRL_PIN(IMX8QM_ENET0_RGMII_RXD2),
	IMX_PINCTRL_PIN(IMX8QM_ENET0_RGMII_RXD3),
	IMX_PINCTRL_PIN(IMX8QM_COMP_CTL_GPIO_1V8_3V3_ENET_ENETB),
	IMX_PINCTRL_PIN(IMX8QM_ENET1_RGMII_TXC),
	IMX_PINCTRL_PIN(IMX8QM_ENET1_RGMII_TX_CTL),
	IMX_PINCTRL_PIN(IMX8QM_ENET1_RGMII_TXD0),
	IMX_PINCTRL_PIN(IMX8QM_ENET1_RGMII_TXD1),
	IMX_PINCTRL_PIN(IMX8QM_ENET1_RGMII_TXD2),
	IMX_PINCTRL_PIN(IMX8QM_ENET1_RGMII_TXD3),
	IMX_PINCTRL_PIN(IMX8QM_ENET1_RGMII_RXC),
	IMX_PINCTRL_PIN(IMX8QM_ENET1_RGMII_RX_CTL),
	IMX_PINCTRL_PIN(IMX8QM_ENET1_RGMII_RXD0),
	IMX_PINCTRL_PIN(IMX8QM_ENET1_RGMII_RXD1),
	IMX_PINCTRL_PIN(IMX8QM_ENET1_RGMII_RXD2),
	IMX_PINCTRL_PIN(IMX8QM_ENET1_RGMII_RXD3),
	IMX_PINCTRL_PIN(IMX8QM_COMP_CTL_GPIO_1V8_3V3_ENET_ENETA),
};

static const struct imx_pinctrl_soc_info imx8qm_pinctrl_info = {
	.pins = imx8qm_pinctrl_pads,
	.npins = ARRAY_SIZE(imx8qm_pinctrl_pads),
	.flags = IMX_USE_SCU,
	.imx_pinconf_get = imx_pinconf_get_scu,
	.imx_pinconf_set = imx_pinconf_set_scu,
	.imx_pinctrl_parse_pin = imx_pinctrl_parse_pin_scu,
};

static const struct of_device_id imx8qm_pinctrl_of_match[] = {
	{ .compatible = "fsl,imx8qm-iomuxc", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, imx8qm_pinctrl_of_match);

static int imx8qm_pinctrl_probe(struct platform_device *pdev)
{
	int ret;

	ret = imx_pinctrl_sc_ipc_init(pdev);
	if (ret)
		return ret;

	return imx_pinctrl_probe(pdev, &imx8qm_pinctrl_info);
}

static struct platform_driver imx8qm_pinctrl_driver = {
	.driver = {
		.name = "imx8qm-pinctrl",
		.of_match_table = imx8qm_pinctrl_of_match,
		.suppress_bind_attrs = true,
	},
	.probe = imx8qm_pinctrl_probe,
};

static int __init imx8qm_pinctrl_init(void)
{
	return platform_driver_register(&imx8qm_pinctrl_driver);
}
arch_initcall(imx8qm_pinctrl_init);

MODULE_AUTHOR("Aisheng Dong <aisheng.dong@nxp.com>");
MODULE_DESCRIPTION("NXP i.MX8QM pinctrl driver");
MODULE_LICENSE("GPL v2");
