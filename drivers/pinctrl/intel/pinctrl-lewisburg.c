/*
 * Intel Lewisburg pinctrl/GPIO driver
 *
 * Copyright (C) 2017, Intel Corporation
 * Author: Mika Westerberg <mika.westerberg@linux.intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/acpi.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pm.h>
#include <linux/pinctrl/pinctrl.h>

#include "pinctrl-intel.h"

#define LBG_PAD_OWN	0x020
#define LBG_PADCFGLOCK	0x060
#define LBG_HOSTSW_OWN	0x080
#define LBG_GPI_IE	0x110

#define LBG_COMMUNITY(b, s, e)				\
	{						\
		.barno = (b),				\
		.padown_offset = LBG_PAD_OWN,		\
		.padcfglock_offset = LBG_PADCFGLOCK,	\
		.hostown_offset = LBG_HOSTSW_OWN,	\
		.ie_offset = LBG_GPI_IE,		\
		.gpp_size = 24,				\
		.pin_base = (s),			\
		.npins = ((e) - (s) + 1),		\
	}

static const struct pinctrl_pin_desc lbg_pins[] = {
	/* GPP_A */
	PINCTRL_PIN(0, "RCINB"),
	PINCTRL_PIN(1, "LAD_0"),
	PINCTRL_PIN(2, "LAD_1"),
	PINCTRL_PIN(3, "LAD_2"),
	PINCTRL_PIN(4, "LAD_3"),
	PINCTRL_PIN(5, "LFRAMEB"),
	PINCTRL_PIN(6, "SERIRQ"),
	PINCTRL_PIN(7, "PIRQAB"),
	PINCTRL_PIN(8, "CLKRUNB"),
	PINCTRL_PIN(9, "CLKOUT_LPC_0"),
	PINCTRL_PIN(10, "CLKOUT_LPC_1"),
	PINCTRL_PIN(11, "PMEB"),
	PINCTRL_PIN(12, "BM_BUSYB"),
	PINCTRL_PIN(13, "SUSWARNB_SUSPWRDNACK"),
	PINCTRL_PIN(14, "ESPI_RESETB"),
	PINCTRL_PIN(15, "SUSACKB"),
	PINCTRL_PIN(16, "CLKOUT_LPC_2"),
	PINCTRL_PIN(17, "GPP_A_17"),
	PINCTRL_PIN(18, "GPP_A_18"),
	PINCTRL_PIN(19, "GPP_A_19"),
	PINCTRL_PIN(20, "GPP_A_20"),
	PINCTRL_PIN(21, "GPP_A_21"),
	PINCTRL_PIN(22, "GPP_A_22"),
	PINCTRL_PIN(23, "GPP_A_23"),
	/* GPP_B */
	PINCTRL_PIN(24, "CORE_VID_0"),
	PINCTRL_PIN(25, "CORE_VID_1"),
	PINCTRL_PIN(26, "VRALERTB"),
	PINCTRL_PIN(27, "CPU_GP_2"),
	PINCTRL_PIN(28, "CPU_GP_3"),
	PINCTRL_PIN(29, "SRCCLKREQB_0"),
	PINCTRL_PIN(30, "SRCCLKREQB_1"),
	PINCTRL_PIN(31, "SRCCLKREQB_2"),
	PINCTRL_PIN(32, "SRCCLKREQB_3"),
	PINCTRL_PIN(33, "SRCCLKREQB_4"),
	PINCTRL_PIN(34, "SRCCLKREQB_5"),
	PINCTRL_PIN(35, "GPP_B_11"),
	PINCTRL_PIN(36, "GLB_RST_WARN_N"),
	PINCTRL_PIN(37, "PLTRSTB"),
	PINCTRL_PIN(38, "SPKR"),
	PINCTRL_PIN(39, "GPP_B_15"),
	PINCTRL_PIN(40, "GPP_B_16"),
	PINCTRL_PIN(41, "GPP_B_17"),
	PINCTRL_PIN(42, "GPP_B_18"),
	PINCTRL_PIN(43, "GPP_B_19"),
	PINCTRL_PIN(44, "GPP_B_20"),
	PINCTRL_PIN(45, "GPP_B_21"),
	PINCTRL_PIN(46, "GPP_B_22"),
	PINCTRL_PIN(47, "SML1ALERTB"),
	/* GPP_F */
	PINCTRL_PIN(48, "SATAXPCIE_3"),
	PINCTRL_PIN(49, "SATAXPCIE_4"),
	PINCTRL_PIN(50, "SATAXPCIE_5"),
	PINCTRL_PIN(51, "SATAXPCIE_6"),
	PINCTRL_PIN(52, "SATAXPCIE_7"),
	PINCTRL_PIN(53, "SATA_DEVSLP_3"),
	PINCTRL_PIN(54, "SATA_DEVSLP_4"),
	PINCTRL_PIN(55, "SATA_DEVSLP_5"),
	PINCTRL_PIN(56, "SATA_DEVSLP_6"),
	PINCTRL_PIN(57, "SATA_DEVSLP_7"),
	PINCTRL_PIN(58, "SATA_SCLOCK"),
	PINCTRL_PIN(59, "SATA_SLOAD"),
	PINCTRL_PIN(60, "SATA_SDATAOUT1"),
	PINCTRL_PIN(61, "SATA_SDATAOUT0"),
	PINCTRL_PIN(62, "SSATA_LEDB"),
	PINCTRL_PIN(63, "USB2_OCB_4"),
	PINCTRL_PIN(64, "USB2_OCB_5"),
	PINCTRL_PIN(65, "USB2_OCB_6"),
	PINCTRL_PIN(66, "USB2_OCB_7"),
	PINCTRL_PIN(67, "GBE_SMBUS_CLK"),
	PINCTRL_PIN(68, "GBE_SMBDATA"),
	PINCTRL_PIN(69, "GBE_SMBALRTN"),
	PINCTRL_PIN(70, "SSATA_SCLOCK"),
	PINCTRL_PIN(71, "SSATA_SLOAD"),
	/* GPP_C */
	PINCTRL_PIN(72, "SMBCLK"),
	PINCTRL_PIN(73, "SMBDATA"),
	PINCTRL_PIN(74, "SMBALERTB"),
	PINCTRL_PIN(75, "SML0CLK"),
	PINCTRL_PIN(76, "SML0DATA"),
	PINCTRL_PIN(77, "SML0ALERTB"),
	PINCTRL_PIN(78, "SML1CLK"),
	PINCTRL_PIN(79, "SML1DATA"),
	PINCTRL_PIN(80, "GPP_C_8"),
	PINCTRL_PIN(81, "GPP_C_9"),
	PINCTRL_PIN(82, "GPP_C_10"),
	PINCTRL_PIN(83, "GPP_C_11"),
	PINCTRL_PIN(84, "GPP_C_12"),
	PINCTRL_PIN(85, "GPP_C_13"),
	PINCTRL_PIN(86, "GPP_C_14"),
	PINCTRL_PIN(87, "GPP_C_15"),
	PINCTRL_PIN(88, "GPP_C_16"),
	PINCTRL_PIN(89, "GPP_C_17"),
	PINCTRL_PIN(90, "GPP_C_18"),
	PINCTRL_PIN(91, "GPP_C_19"),
	PINCTRL_PIN(92, "GPP_C_20"),
	PINCTRL_PIN(93, "GPP_C_21"),
	PINCTRL_PIN(94, "GPP_C_22"),
	PINCTRL_PIN(95, "GPP_C_23"),
	/* GPP_D */
	PINCTRL_PIN(96, "GPP_D_0"),
	PINCTRL_PIN(97, "GPP_D_1"),
	PINCTRL_PIN(98, "GPP_D_2"),
	PINCTRL_PIN(99, "GPP_D_3"),
	PINCTRL_PIN(100, "GPP_D_4"),
	PINCTRL_PIN(101, "SSP0_SFRM"),
	PINCTRL_PIN(102, "SSP0_TXD"),
	PINCTRL_PIN(103, "SSP0_RXD"),
	PINCTRL_PIN(104, "SSP0_SCLK"),
	PINCTRL_PIN(105, "SSATA_DEVSLP_3"),
	PINCTRL_PIN(106, "SSATA_DEVSLP_4"),
	PINCTRL_PIN(107, "SSATA_DEVSLP_5"),
	PINCTRL_PIN(108, "SSATA_SDATAOUT1"),
	PINCTRL_PIN(109, "SML0BCLK_SML0BCLKIE"),
	PINCTRL_PIN(110, "SML0BDATA_SML0BDATAIE"),
	PINCTRL_PIN(111, "SSATA_SDATAOUT0"),
	PINCTRL_PIN(112, "SML0BALERTB_SML0BALERTBIE"),
	PINCTRL_PIN(113, "DMIC_CLK_1"),
	PINCTRL_PIN(114, "DMIC_DATA_1"),
	PINCTRL_PIN(115, "DMIC_CLK_0"),
	PINCTRL_PIN(116, "DMIC_DATA_0"),
	PINCTRL_PIN(117, "IE_UART_RXD"),
	PINCTRL_PIN(118, "IE_UART_TXD"),
	PINCTRL_PIN(119, "GPP_D_23"),
	/* GPP_E */
	PINCTRL_PIN(120, "SATAXPCIE_0"),
	PINCTRL_PIN(121, "SATAXPCIE_1"),
	PINCTRL_PIN(122, "SATAXPCIE_2"),
	PINCTRL_PIN(123, "CPU_GP_0"),
	PINCTRL_PIN(124, "SATA_DEVSLP_0"),
	PINCTRL_PIN(125, "SATA_DEVSLP_1"),
	PINCTRL_PIN(126, "SATA_DEVSLP_2"),
	PINCTRL_PIN(127, "CPU_GP_1"),
	PINCTRL_PIN(128, "SATA_LEDB"),
	PINCTRL_PIN(129, "USB2_OCB_0"),
	PINCTRL_PIN(130, "USB2_OCB_1"),
	PINCTRL_PIN(131, "USB2_OCB_2"),
	PINCTRL_PIN(132, "USB2_OCB_3"),
	/* GPP_I */
	PINCTRL_PIN(133, "GBE_TDO"),
	PINCTRL_PIN(134, "GBE_TCK"),
	PINCTRL_PIN(135, "GBE_TMS"),
	PINCTRL_PIN(136, "GBE_TDI"),
	PINCTRL_PIN(137, "DO_RESET_INB"),
	PINCTRL_PIN(138, "DO_RESET_OUTB"),
	PINCTRL_PIN(139, "RESET_DONE"),
	PINCTRL_PIN(140, "GBE_TRST_N"),
	PINCTRL_PIN(141, "GBE_PCI_DIS"),
	PINCTRL_PIN(142, "GBE_LAN_DIS"),
	PINCTRL_PIN(143, "GPP_I_10"),
	PINCTRL_PIN(144, "GPIO_RCOMP_3P3"),
	/* GPP_J */
	PINCTRL_PIN(145, "GBE_LED_0_0"),
	PINCTRL_PIN(146, "GBE_LED_0_1"),
	PINCTRL_PIN(147, "GBE_LED_1_0"),
	PINCTRL_PIN(148, "GBE_LED_1_1"),
	PINCTRL_PIN(149, "GBE_LED_2_0"),
	PINCTRL_PIN(150, "GBE_LED_2_1"),
	PINCTRL_PIN(151, "GBE_LED_3_0"),
	PINCTRL_PIN(152, "GBE_LED_3_1"),
	PINCTRL_PIN(153, "GBE_SCL_0"),
	PINCTRL_PIN(154, "GBE_SDA_0"),
	PINCTRL_PIN(155, "GBE_SCL_1"),
	PINCTRL_PIN(156, "GBE_SDA_1"),
	PINCTRL_PIN(157, "GBE_SCL_2"),
	PINCTRL_PIN(158, "GBE_SDA_2"),
	PINCTRL_PIN(159, "GBE_SCL_3"),
	PINCTRL_PIN(160, "GBE_SDA_3"),
	PINCTRL_PIN(161, "GBE_SDP_0_0"),
	PINCTRL_PIN(162, "GBE_SDP_0_1"),
	PINCTRL_PIN(163, "GBE_SDP_1_0"),
	PINCTRL_PIN(164, "GBE_SDP_1_1"),
	PINCTRL_PIN(165, "GBE_SDP_2_0"),
	PINCTRL_PIN(166, "GBE_SDP_2_1"),
	PINCTRL_PIN(167, "GBE_SDP_3_0"),
	PINCTRL_PIN(168, "GBE_SDP_3_1"),
	/* GPP_K */
	PINCTRL_PIN(169, "GBE_RMIICLK"),
	PINCTRL_PIN(170, "GBE_RMII_TXD_0"),
	PINCTRL_PIN(171, "GBE_RMII_TXD_1"),
	PINCTRL_PIN(172, "GBE_RMII_TX_EN"),
	PINCTRL_PIN(173, "GBE_RMII_CRS_DV"),
	PINCTRL_PIN(174, "GBE_RMII_RXD_0"),
	PINCTRL_PIN(175, "GBE_RMII_RXD_1"),
	PINCTRL_PIN(176, "GBE_RMII_RX_ER"),
	PINCTRL_PIN(177, "GBE_RMII_ARBIN"),
	PINCTRL_PIN(178, "GBE_RMII_ARB_OUT"),
	PINCTRL_PIN(179, "PE_RST_N"),
	PINCTRL_PIN(180, "GPIO_RCOMP_1P8_3P3"),
	/* GPP_G */
	PINCTRL_PIN(181, "FAN_TACH_0"),
	PINCTRL_PIN(182, "FAN_TACH_1"),
	PINCTRL_PIN(183, "FAN_TACH_2"),
	PINCTRL_PIN(184, "FAN_TACH_3"),
	PINCTRL_PIN(185, "FAN_TACH_4"),
	PINCTRL_PIN(186, "FAN_TACH_5"),
	PINCTRL_PIN(187, "FAN_TACH_6"),
	PINCTRL_PIN(188, "FAN_TACH_7"),
	PINCTRL_PIN(189, "FAN_PWM_0"),
	PINCTRL_PIN(190, "FAN_PWM_1"),
	PINCTRL_PIN(191, "FAN_PWM_2"),
	PINCTRL_PIN(192, "FAN_PWM_3"),
	PINCTRL_PIN(193, "GSXDOUT"),
	PINCTRL_PIN(194, "GSXSLOAD"),
	PINCTRL_PIN(195, "GSXDIN"),
	PINCTRL_PIN(196, "GSXSRESETB"),
	PINCTRL_PIN(197, "GSXCLK"),
	PINCTRL_PIN(198, "ADR_COMPLETE"),
	PINCTRL_PIN(199, "NMIB"),
	PINCTRL_PIN(200, "SMIB"),
	PINCTRL_PIN(201, "SSATA_DEVSLP_0"),
	PINCTRL_PIN(202, "SSATA_DEVSLP_1"),
	PINCTRL_PIN(203, "SSATA_DEVSLP_2"),
	PINCTRL_PIN(204, "SSATAXPCIE0_SSATAGP0"),
	/* GPP_H */
	PINCTRL_PIN(205, "SRCCLKREQB_6"),
	PINCTRL_PIN(206, "SRCCLKREQB_7"),
	PINCTRL_PIN(207, "SRCCLKREQB_8"),
	PINCTRL_PIN(208, "SRCCLKREQB_9"),
	PINCTRL_PIN(209, "SRCCLKREQB_10"),
	PINCTRL_PIN(210, "SRCCLKREQB_11"),
	PINCTRL_PIN(211, "SRCCLKREQB_12"),
	PINCTRL_PIN(212, "SRCCLKREQB_13"),
	PINCTRL_PIN(213, "SRCCLKREQB_14"),
	PINCTRL_PIN(214, "SRCCLKREQB_15"),
	PINCTRL_PIN(215, "SML2CLK"),
	PINCTRL_PIN(216, "SML2DATA"),
	PINCTRL_PIN(217, "SML2ALERTB"),
	PINCTRL_PIN(218, "SML3CLK"),
	PINCTRL_PIN(219, "SML3DATA"),
	PINCTRL_PIN(220, "SML3ALERTB"),
	PINCTRL_PIN(221, "SML4CLK"),
	PINCTRL_PIN(222, "SML4DATA"),
	PINCTRL_PIN(223, "SML4ALERTB"),
	PINCTRL_PIN(224, "SSATAXPCIE1_SSATAGP1"),
	PINCTRL_PIN(225, "SSATAXPCIE2_SSATAGP2"),
	PINCTRL_PIN(226, "SSATAXPCIE3_SSATAGP3"),
	PINCTRL_PIN(227, "SSATAXPCIE4_SSATAGP4"),
	PINCTRL_PIN(228, "SSATAXPCIE5_SSATAGP5"),
	/* GPP_L */
	PINCTRL_PIN(229, "VISA2CH0_D0"),
	PINCTRL_PIN(230, "VISA2CH0_D1"),
	PINCTRL_PIN(231, "VISA2CH0_D2"),
	PINCTRL_PIN(232, "VISA2CH0_D3"),
	PINCTRL_PIN(233, "VISA2CH0_D4"),
	PINCTRL_PIN(234, "VISA2CH0_D5"),
	PINCTRL_PIN(235, "VISA2CH0_D6"),
	PINCTRL_PIN(236, "VISA2CH0_D7"),
	PINCTRL_PIN(237, "VISA2CH0_CLK"),
	PINCTRL_PIN(238, "VISA2CH1_D0"),
	PINCTRL_PIN(239, "VISA2CH1_D1"),
	PINCTRL_PIN(240, "VISA2CH1_D2"),
	PINCTRL_PIN(241, "VISA2CH1_D3"),
	PINCTRL_PIN(242, "VISA2CH1_D4"),
	PINCTRL_PIN(243, "VISA2CH1_D5"),
	PINCTRL_PIN(244, "VISA2CH1_D6"),
	PINCTRL_PIN(245, "VISA2CH1_D7"),
	PINCTRL_PIN(246, "VISA2CH1_CLK"),
};

static const struct intel_community lbg_communities[] = {
	LBG_COMMUNITY(0, 0, 71),
	LBG_COMMUNITY(1, 72, 132),
	LBG_COMMUNITY(3, 133, 144),
	LBG_COMMUNITY(4, 145, 180),
	LBG_COMMUNITY(5, 181, 246),
};

static const struct intel_pinctrl_soc_data lbg_soc_data = {
	.pins = lbg_pins,
	.npins = ARRAY_SIZE(lbg_pins),
	.communities = lbg_communities,
	.ncommunities = ARRAY_SIZE(lbg_communities),
};

static int lbg_pinctrl_probe(struct platform_device *pdev)
{
	return intel_pinctrl_probe(pdev, &lbg_soc_data);
}

static const struct dev_pm_ops lbg_pinctrl_pm_ops = {
	SET_LATE_SYSTEM_SLEEP_PM_OPS(intel_pinctrl_suspend,
				     intel_pinctrl_resume)
};

static const struct acpi_device_id lbg_pinctrl_acpi_match[] = {
	{ "INT3536" },
	{ }
};
MODULE_DEVICE_TABLE(acpi, lbg_pinctrl_acpi_match);

static struct platform_driver lbg_pinctrl_driver = {
	.probe = lbg_pinctrl_probe,
	.driver = {
		.name = "lewisburg-pinctrl",
		.acpi_match_table = lbg_pinctrl_acpi_match,
		.pm = &lbg_pinctrl_pm_ops,
	},
};

module_platform_driver(lbg_pinctrl_driver);

MODULE_AUTHOR("Mika Westerberg <mika.westerberg@linux.intel.com>");
MODULE_DESCRIPTION("Intel Lewisburg pinctrl/GPIO driver");
MODULE_LICENSE("GPL v2");
