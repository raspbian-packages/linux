/*
 * Copyright (C) 2016-2017 Socionext Inc.
 *   Author: Masahiro Yamada <yamada.masahiro@socionext.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/platform_device.h>

#include "pinctrl-uniphier.h"

static const struct pinctrl_pin_desc uniphier_ld20_pins[] = {
	UNIPHIER_PINCTRL_PIN(0, "XECS1", UNIPHIER_PIN_IECTRL_EXIST,
			     0, UNIPHIER_PIN_DRV_3BIT,
			     0, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(1, "ERXW", UNIPHIER_PIN_IECTRL_EXIST,
			     1, UNIPHIER_PIN_DRV_3BIT,
			     1, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(2, "XERWE1", UNIPHIER_PIN_IECTRL_EXIST,
			     2, UNIPHIER_PIN_DRV_3BIT,
			     2, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(3, "XNFWP", UNIPHIER_PIN_IECTRL_EXIST,
			     3, UNIPHIER_PIN_DRV_3BIT,
			     3, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(4, "XNFCE0", UNIPHIER_PIN_IECTRL_EXIST,
			     4, UNIPHIER_PIN_DRV_3BIT,
			     4, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(5, "NFRYBY0", UNIPHIER_PIN_IECTRL_EXIST,
			     5, UNIPHIER_PIN_DRV_3BIT,
			     5, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(6, "XNFRE", UNIPHIER_PIN_IECTRL_EXIST,
			     6, UNIPHIER_PIN_DRV_3BIT,
			     6, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(7, "XNFWE", UNIPHIER_PIN_IECTRL_EXIST,
			     7, UNIPHIER_PIN_DRV_3BIT,
			     7, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(8, "NFALE", UNIPHIER_PIN_IECTRL_EXIST,
			     8, UNIPHIER_PIN_DRV_3BIT,
			     8, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(9, "NFCLE", UNIPHIER_PIN_IECTRL_EXIST,
			     9, UNIPHIER_PIN_DRV_3BIT,
			     9, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(10, "NFD0", UNIPHIER_PIN_IECTRL_EXIST,
			     10, UNIPHIER_PIN_DRV_3BIT,
			     10, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(11, "NFD1", UNIPHIER_PIN_IECTRL_EXIST,
			     11, UNIPHIER_PIN_DRV_3BIT,
			     11, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(12, "NFD2", UNIPHIER_PIN_IECTRL_EXIST,
			     12, UNIPHIER_PIN_DRV_3BIT,
			     12, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(13, "NFD3", UNIPHIER_PIN_IECTRL_EXIST,
			     13, UNIPHIER_PIN_DRV_3BIT,
			     13, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(14, "NFD4", UNIPHIER_PIN_IECTRL_EXIST,
			     14, UNIPHIER_PIN_DRV_3BIT,
			     14, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(15, "NFD5", UNIPHIER_PIN_IECTRL_EXIST,
			     15, UNIPHIER_PIN_DRV_3BIT,
			     15, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(16, "NFD6", UNIPHIER_PIN_IECTRL_EXIST,
			     16, UNIPHIER_PIN_DRV_3BIT,
			     16, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(17, "NFD7", UNIPHIER_PIN_IECTRL_EXIST,
			     17, UNIPHIER_PIN_DRV_3BIT,
			     17, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(18, "XERST", UNIPHIER_PIN_IECTRL_EXIST,
			     0, UNIPHIER_PIN_DRV_2BIT,
			     18, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(19, "MMCCLK", UNIPHIER_PIN_IECTRL_EXIST,
			     1, UNIPHIER_PIN_DRV_2BIT,
			     19, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(20, "MMCCMD", UNIPHIER_PIN_IECTRL_EXIST,
			     2, UNIPHIER_PIN_DRV_2BIT,
			     20, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(21, "MMCDS", UNIPHIER_PIN_IECTRL_EXIST,
			     3, UNIPHIER_PIN_DRV_2BIT,
			     21, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(22, "MMCDAT0", UNIPHIER_PIN_IECTRL_EXIST,
			     4, UNIPHIER_PIN_DRV_2BIT,
			     22, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(23, "MMCDAT1", UNIPHIER_PIN_IECTRL_EXIST,
			     5, UNIPHIER_PIN_DRV_2BIT,
			     23, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(24, "MMCDAT2", UNIPHIER_PIN_IECTRL_EXIST,
			     6, UNIPHIER_PIN_DRV_2BIT,
			     24, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(25, "MMCDAT3", UNIPHIER_PIN_IECTRL_EXIST,
			     7, UNIPHIER_PIN_DRV_2BIT,
			     25, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(26, "MMCDAT4", UNIPHIER_PIN_IECTRL_EXIST,
			     8, UNIPHIER_PIN_DRV_2BIT,
			     26, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(27, "MMCDAT5", UNIPHIER_PIN_IECTRL_EXIST,
			     9, UNIPHIER_PIN_DRV_2BIT,
			     27, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(28, "MMCDAT6", UNIPHIER_PIN_IECTRL_EXIST,
			     10, UNIPHIER_PIN_DRV_2BIT,
			     28, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(29, "MMCDAT7", UNIPHIER_PIN_IECTRL_EXIST,
			     11, UNIPHIER_PIN_DRV_2BIT,
			     29, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(30, "MDC", UNIPHIER_PIN_IECTRL_EXIST,
			     18, UNIPHIER_PIN_DRV_3BIT,
			     30, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(31, "MDIO", UNIPHIER_PIN_IECTRL_EXIST,
			     19, UNIPHIER_PIN_DRV_3BIT,
			     31, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(32, "MDIO_INTL", UNIPHIER_PIN_IECTRL_EXIST,
			     20, UNIPHIER_PIN_DRV_3BIT,
			     32, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(33, "PHYRSTL", UNIPHIER_PIN_IECTRL_EXIST,
			     21, UNIPHIER_PIN_DRV_3BIT,
			     33, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(34, "RGMII_RXCLK", UNIPHIER_PIN_IECTRL_EXIST,
			     22, UNIPHIER_PIN_DRV_3BIT,
			     34, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(35, "RGMII_RXD0", UNIPHIER_PIN_IECTRL_EXIST,
			     23, UNIPHIER_PIN_DRV_3BIT,
			     35, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(36, "RGMII_RXD1", UNIPHIER_PIN_IECTRL_EXIST,
			     24, UNIPHIER_PIN_DRV_3BIT,
			     36, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(37, "RGMII_RXD2", UNIPHIER_PIN_IECTRL_EXIST,
			     25, UNIPHIER_PIN_DRV_3BIT,
			     37, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(38, "RGMII_RXD3", UNIPHIER_PIN_IECTRL_EXIST,
			     26, UNIPHIER_PIN_DRV_3BIT,
			     38, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(39, "RGMII_RXCTL", UNIPHIER_PIN_IECTRL_EXIST,
			     27, UNIPHIER_PIN_DRV_3BIT,
			     39, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(40, "RGMII_TXCLK", UNIPHIER_PIN_IECTRL_EXIST,
			     28, UNIPHIER_PIN_DRV_3BIT,
			     40, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(41, "RGMII_TXD0", UNIPHIER_PIN_IECTRL_EXIST,
			     29, UNIPHIER_PIN_DRV_3BIT,
			     41, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(42, "RGMII_TXD1", UNIPHIER_PIN_IECTRL_EXIST,
			     30, UNIPHIER_PIN_DRV_3BIT,
			     42, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(43, "RGMII_TXD2", UNIPHIER_PIN_IECTRL_EXIST,
			     31, UNIPHIER_PIN_DRV_3BIT,
			     43, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(44, "RGMII_TXD3", UNIPHIER_PIN_IECTRL_EXIST,
			     32, UNIPHIER_PIN_DRV_3BIT,
			     44, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(45, "RGMII_TXCTL", UNIPHIER_PIN_IECTRL_EXIST,
			     33, UNIPHIER_PIN_DRV_3BIT,
			     45, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(46, "USB0VBUS", UNIPHIER_PIN_IECTRL_EXIST,
			     34, UNIPHIER_PIN_DRV_3BIT,
			     46, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(47, "USB0OD", UNIPHIER_PIN_IECTRL_EXIST,
			     35, UNIPHIER_PIN_DRV_3BIT,
			     47, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(48, "USB1VBUS", UNIPHIER_PIN_IECTRL_EXIST,
			     36, UNIPHIER_PIN_DRV_3BIT,
			     48, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(49, "USB1OD", UNIPHIER_PIN_IECTRL_EXIST,
			     37, UNIPHIER_PIN_DRV_3BIT,
			     49, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(50, "USB2VBUS", UNIPHIER_PIN_IECTRL_EXIST,
			     38, UNIPHIER_PIN_DRV_3BIT,
			     50, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(51, "USB2OD", UNIPHIER_PIN_IECTRL_EXIST,
			     39, UNIPHIER_PIN_DRV_3BIT,
			     51, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(52, "USB3VBUS", UNIPHIER_PIN_IECTRL_EXIST,
			     40, UNIPHIER_PIN_DRV_3BIT,
			     52, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(53, "USB3OD", UNIPHIER_PIN_IECTRL_EXIST,
			     41, UNIPHIER_PIN_DRV_3BIT,
			     53, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(54, "TXD0", UNIPHIER_PIN_IECTRL_EXIST,
			     42, UNIPHIER_PIN_DRV_3BIT,
			     54, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(55, "RXD0", UNIPHIER_PIN_IECTRL_EXIST,
			     43, UNIPHIER_PIN_DRV_3BIT,
			     55, UNIPHIER_PIN_PULL_UP),
	UNIPHIER_PINCTRL_PIN(56, "SPISYNC0", UNIPHIER_PIN_IECTRL_EXIST,
			     44, UNIPHIER_PIN_DRV_3BIT,
			     56, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(57, "SPISCLK0", UNIPHIER_PIN_IECTRL_EXIST,
			     45, UNIPHIER_PIN_DRV_3BIT,
			     57, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(58, "SPITXD0", UNIPHIER_PIN_IECTRL_EXIST,
			     46, UNIPHIER_PIN_DRV_3BIT,
			     58, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(59, "SPIRXD0", UNIPHIER_PIN_IECTRL_EXIST,
			     47, UNIPHIER_PIN_DRV_3BIT,
			     59, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(60, "AGCI", UNIPHIER_PIN_IECTRL_EXIST,
			     48, UNIPHIER_PIN_DRV_3BIT,
			     60, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(61, "DMDSDA0", UNIPHIER_PIN_IECTRL_EXIST,
			     -1, UNIPHIER_PIN_DRV_FIXED4,
			     -1, UNIPHIER_PIN_PULL_NONE),
	UNIPHIER_PINCTRL_PIN(62, "DMDSCL0", UNIPHIER_PIN_IECTRL_EXIST,
			     -1, UNIPHIER_PIN_DRV_FIXED4,
			     -1, UNIPHIER_PIN_PULL_NONE),
	UNIPHIER_PINCTRL_PIN(63, "SDA0", UNIPHIER_PIN_IECTRL_EXIST,
			     -1, UNIPHIER_PIN_DRV_FIXED4,
			     -1, UNIPHIER_PIN_PULL_NONE),
	UNIPHIER_PINCTRL_PIN(64, "SCL0", UNIPHIER_PIN_IECTRL_EXIST,
			     -1, UNIPHIER_PIN_DRV_FIXED4,
			     -1, UNIPHIER_PIN_PULL_NONE),
	UNIPHIER_PINCTRL_PIN(65, "SDA1", UNIPHIER_PIN_IECTRL_EXIST,
			     -1, UNIPHIER_PIN_DRV_FIXED4,
			     -1, UNIPHIER_PIN_PULL_NONE),
	UNIPHIER_PINCTRL_PIN(66, "SCL1", UNIPHIER_PIN_IECTRL_EXIST,
			     -1, UNIPHIER_PIN_DRV_FIXED4,
			     -1, UNIPHIER_PIN_PULL_NONE),
	UNIPHIER_PINCTRL_PIN(67, "HIN", UNIPHIER_PIN_IECTRL_EXIST,
			     -1, UNIPHIER_PIN_DRV_FIXED4,
			     -1, UNIPHIER_PIN_PULL_NONE),
	UNIPHIER_PINCTRL_PIN(68, "VIN", UNIPHIER_PIN_IECTRL_EXIST,
			     -1, UNIPHIER_PIN_DRV_FIXED4,
			     -1, UNIPHIER_PIN_PULL_NONE),
	UNIPHIER_PINCTRL_PIN(69, "PCA00", UNIPHIER_PIN_IECTRL_EXIST,
			     49, UNIPHIER_PIN_DRV_3BIT,
			     69, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(70, "PCA01", UNIPHIER_PIN_IECTRL_EXIST,
			     50, UNIPHIER_PIN_DRV_3BIT,
			     70, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(71, "PCA02", UNIPHIER_PIN_IECTRL_EXIST,
			     51, UNIPHIER_PIN_DRV_3BIT,
			     71, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(72, "PCA03", UNIPHIER_PIN_IECTRL_EXIST,
			     52, UNIPHIER_PIN_DRV_3BIT,
			     72, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(73, "PCA04", UNIPHIER_PIN_IECTRL_EXIST,
			     53, UNIPHIER_PIN_DRV_3BIT,
			     73, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(74, "PCA05", UNIPHIER_PIN_IECTRL_EXIST,
			     54, UNIPHIER_PIN_DRV_3BIT,
			     74, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(75, "PCA06", UNIPHIER_PIN_IECTRL_EXIST,
			     55, UNIPHIER_PIN_DRV_3BIT,
			     75, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(76, "PCA07", UNIPHIER_PIN_IECTRL_EXIST,
			     56, UNIPHIER_PIN_DRV_3BIT,
			     76, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(77, "PCA08", UNIPHIER_PIN_IECTRL_EXIST,
			     57, UNIPHIER_PIN_DRV_3BIT,
			     77, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(78, "PCA09", UNIPHIER_PIN_IECTRL_EXIST,
			     58, UNIPHIER_PIN_DRV_3BIT,
			     78, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(79, "PCA10", UNIPHIER_PIN_IECTRL_EXIST,
			     59, UNIPHIER_PIN_DRV_3BIT,
			     79, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(80, "PCA11", UNIPHIER_PIN_IECTRL_EXIST,
			     60, UNIPHIER_PIN_DRV_3BIT,
			     80, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(81, "PCA12", UNIPHIER_PIN_IECTRL_EXIST,
			     61, UNIPHIER_PIN_DRV_3BIT,
			     81, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(82, "PCA13", UNIPHIER_PIN_IECTRL_EXIST,
			     62, UNIPHIER_PIN_DRV_3BIT,
			     82, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(83, "PCA14", UNIPHIER_PIN_IECTRL_EXIST,
			     63, UNIPHIER_PIN_DRV_3BIT,
			     83, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(84, "PC0READY", UNIPHIER_PIN_IECTRL_EXIST,
			     0, UNIPHIER_PIN_DRV_1BIT,
			     84, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(85, "PC0CD1", UNIPHIER_PIN_IECTRL_EXIST,
			     1, UNIPHIER_PIN_DRV_1BIT,
			     85, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(86, "PC0CD2", UNIPHIER_PIN_IECTRL_EXIST,
			     2, UNIPHIER_PIN_DRV_1BIT,
			     86, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(87, "PC0WAIT", UNIPHIER_PIN_IECTRL_EXIST,
			     3, UNIPHIER_PIN_DRV_1BIT,
			     87, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(88, "PC0RESET", UNIPHIER_PIN_IECTRL_EXIST,
			     4, UNIPHIER_PIN_DRV_1BIT,
			     88, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(89, "PC0CE1", UNIPHIER_PIN_IECTRL_EXIST,
			     5, UNIPHIER_PIN_DRV_1BIT,
			     89, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(90, "PC0WE", UNIPHIER_PIN_IECTRL_EXIST,
			     6, UNIPHIER_PIN_DRV_1BIT,
			     90, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(91, "PC0OE", UNIPHIER_PIN_IECTRL_EXIST,
			     7, UNIPHIER_PIN_DRV_1BIT,
			     91, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(92, "PC0IOWR", UNIPHIER_PIN_IECTRL_EXIST,
			     8, UNIPHIER_PIN_DRV_1BIT,
			     92, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(93, "PC0IORD", UNIPHIER_PIN_IECTRL_EXIST,
			     9, UNIPHIER_PIN_DRV_1BIT,
			     93, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(94, "PCD00", UNIPHIER_PIN_IECTRL_EXIST,
			     10, UNIPHIER_PIN_DRV_1BIT,
			     94, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(95, "PCD01", UNIPHIER_PIN_IECTRL_EXIST,
			     11, UNIPHIER_PIN_DRV_1BIT,
			     95, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(96, "PCD02", UNIPHIER_PIN_IECTRL_EXIST,
			     12, UNIPHIER_PIN_DRV_1BIT,
			     96, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(97, "PCD03", UNIPHIER_PIN_IECTRL_EXIST,
			     13, UNIPHIER_PIN_DRV_1BIT,
			     97, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(98, "PCD04", UNIPHIER_PIN_IECTRL_EXIST,
			     14, UNIPHIER_PIN_DRV_1BIT,
			     98, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(99, "PCD05", UNIPHIER_PIN_IECTRL_EXIST,
			     15, UNIPHIER_PIN_DRV_1BIT,
			     99, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(100, "PCD06", UNIPHIER_PIN_IECTRL_EXIST,
			     16, UNIPHIER_PIN_DRV_1BIT,
			     100, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(101, "PCD07", UNIPHIER_PIN_IECTRL_EXIST,
			     17, UNIPHIER_PIN_DRV_1BIT,
			     101, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(102, "HS0BCLKIN", UNIPHIER_PIN_IECTRL_EXIST,
			     18, UNIPHIER_PIN_DRV_1BIT,
			     102, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(103, "HS0SYNCIN", UNIPHIER_PIN_IECTRL_EXIST,
			     19, UNIPHIER_PIN_DRV_1BIT,
			     103, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(104, "HS0VALIN", UNIPHIER_PIN_IECTRL_EXIST,
			     20, UNIPHIER_PIN_DRV_1BIT,
			     104, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(105, "HS0DIN0", UNIPHIER_PIN_IECTRL_EXIST,
			     21, UNIPHIER_PIN_DRV_1BIT,
			     105, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(106, "HS0DIN1", UNIPHIER_PIN_IECTRL_EXIST,
			     22, UNIPHIER_PIN_DRV_1BIT,
			     106, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(107, "HS0DIN2", UNIPHIER_PIN_IECTRL_EXIST,
			     23, UNIPHIER_PIN_DRV_1BIT,
			     107, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(108, "HS0DIN3", UNIPHIER_PIN_IECTRL_EXIST,
			     24, UNIPHIER_PIN_DRV_1BIT,
			     108, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(109, "HS0DIN4", UNIPHIER_PIN_IECTRL_EXIST,
			     25, UNIPHIER_PIN_DRV_1BIT,
			     109, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(110, "HS0DIN5", UNIPHIER_PIN_IECTRL_EXIST,
			     26, UNIPHIER_PIN_DRV_1BIT,
			     110, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(111, "HS0DIN6", UNIPHIER_PIN_IECTRL_EXIST,
			     27, UNIPHIER_PIN_DRV_1BIT,
			     111, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(112, "HS0DIN7", UNIPHIER_PIN_IECTRL_EXIST,
			     28, UNIPHIER_PIN_DRV_1BIT,
			     112, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(113, "HS0BCLKOUT", UNIPHIER_PIN_IECTRL_EXIST,
			     64, UNIPHIER_PIN_DRV_3BIT,
			     113, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(114, "HS0SYNCOUT", UNIPHIER_PIN_IECTRL_EXIST,
			     65, UNIPHIER_PIN_DRV_3BIT,
			     114, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(115, "HS0VALOUT", UNIPHIER_PIN_IECTRL_EXIST,
			     66, UNIPHIER_PIN_DRV_3BIT,
			     115, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(116, "HS0DOUT0", UNIPHIER_PIN_IECTRL_EXIST,
			     67, UNIPHIER_PIN_DRV_3BIT,
			     116, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(117, "HS0DOUT1", UNIPHIER_PIN_IECTRL_EXIST,
			     68, UNIPHIER_PIN_DRV_3BIT,
			     117, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(118, "HS0DOUT2", UNIPHIER_PIN_IECTRL_EXIST,
			     69, UNIPHIER_PIN_DRV_3BIT,
			     118, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(119, "HS0DOUT3", UNIPHIER_PIN_IECTRL_EXIST,
			     70, UNIPHIER_PIN_DRV_3BIT,
			     119, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(120, "HS0DOUT4", UNIPHIER_PIN_IECTRL_EXIST,
			     71, UNIPHIER_PIN_DRV_3BIT,
			     120, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(121, "HS0DOUT5", UNIPHIER_PIN_IECTRL_EXIST,
			     72, UNIPHIER_PIN_DRV_3BIT,
			     121, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(122, "HS0DOUT6", UNIPHIER_PIN_IECTRL_EXIST,
			     73, UNIPHIER_PIN_DRV_3BIT,
			     122, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(123, "HS0DOUT7", UNIPHIER_PIN_IECTRL_EXIST,
			     74, UNIPHIER_PIN_DRV_3BIT,
			     123, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(124, "HS1BCLKIN", UNIPHIER_PIN_IECTRL_EXIST,
			     75, UNIPHIER_PIN_DRV_3BIT,
			     124, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(125, "HS1SYNCIN", UNIPHIER_PIN_IECTRL_EXIST,
			     76, UNIPHIER_PIN_DRV_3BIT,
			     125, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(126, "HS1VALIN", UNIPHIER_PIN_IECTRL_EXIST,
			     77, UNIPHIER_PIN_DRV_3BIT,
			     126, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(127, "HS1DIN0", UNIPHIER_PIN_IECTRL_EXIST,
			     78, UNIPHIER_PIN_DRV_3BIT,
			     127, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(128, "HS1DIN1", UNIPHIER_PIN_IECTRL_EXIST,
			     79, UNIPHIER_PIN_DRV_3BIT,
			     128, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(129, "HS1DIN2", UNIPHIER_PIN_IECTRL_EXIST,
			     80, UNIPHIER_PIN_DRV_3BIT,
			     129, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(130, "HS1DIN3", UNIPHIER_PIN_IECTRL_EXIST,
			     81, UNIPHIER_PIN_DRV_3BIT,
			     130, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(131, "HS1DIN4", UNIPHIER_PIN_IECTRL_EXIST,
			     82, UNIPHIER_PIN_DRV_3BIT,
			     131, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(132, "HS1DIN5", UNIPHIER_PIN_IECTRL_EXIST,
			     83, UNIPHIER_PIN_DRV_3BIT,
			     132, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(133, "HS1DIN6", UNIPHIER_PIN_IECTRL_EXIST,
			     84, UNIPHIER_PIN_DRV_3BIT,
			     133, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(134, "HS1DIN7", UNIPHIER_PIN_IECTRL_EXIST,
			     85, UNIPHIER_PIN_DRV_3BIT,
			     134, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(135, "AO1IEC", UNIPHIER_PIN_IECTRL_EXIST,
			     86, UNIPHIER_PIN_DRV_3BIT,
			     135, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(136, "AO1ARC", UNIPHIER_PIN_IECTRL_EXIST,
			     87, UNIPHIER_PIN_DRV_3BIT,
			     136, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(137, "AO1DACCK", UNIPHIER_PIN_IECTRL_EXIST,
			     88, UNIPHIER_PIN_DRV_3BIT,
			     137, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(138, "AO1BCK", UNIPHIER_PIN_IECTRL_EXIST,
			     89, UNIPHIER_PIN_DRV_3BIT,
			     138, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(139, "AO1LRCK", UNIPHIER_PIN_IECTRL_EXIST,
			     90, UNIPHIER_PIN_DRV_3BIT,
			     139, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(140, "AO1D0", UNIPHIER_PIN_IECTRL_EXIST,
			     91, UNIPHIER_PIN_DRV_3BIT,
			     140, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(141, "AO1D1", UNIPHIER_PIN_IECTRL_EXIST,
			     92, UNIPHIER_PIN_DRV_3BIT,
			     141, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(142, "AO1D2", UNIPHIER_PIN_IECTRL_EXIST,
			     93, UNIPHIER_PIN_DRV_3BIT,
			     142, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(143, "HTPDN0", UNIPHIER_PIN_IECTRL_EXIST,
			     94, UNIPHIER_PIN_DRV_3BIT,
			     143, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(144, "LOCKN0", UNIPHIER_PIN_IECTRL_EXIST,
			     95, UNIPHIER_PIN_DRV_3BIT,
			     144, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(145, "HTPDN1", UNIPHIER_PIN_IECTRL_EXIST,
			     96, UNIPHIER_PIN_DRV_3BIT,
			     145, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(146, "LOCKN1", UNIPHIER_PIN_IECTRL_EXIST,
			     97, UNIPHIER_PIN_DRV_3BIT,
			     146, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(147, "PWMA", UNIPHIER_PIN_IECTRL_EXIST,
			     98, UNIPHIER_PIN_DRV_3BIT,
			     147, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(148, "LR_GOUT", UNIPHIER_PIN_IECTRL_EXIST,
			     99, UNIPHIER_PIN_DRV_3BIT,
			     148, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(149, "XIRQ0", UNIPHIER_PIN_IECTRL_EXIST,
			     100, UNIPHIER_PIN_DRV_3BIT,
			     149, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(150, "XIRQ1", UNIPHIER_PIN_IECTRL_EXIST,
			     101, UNIPHIER_PIN_DRV_3BIT,
			     150, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(151, "XIRQ2", UNIPHIER_PIN_IECTRL_EXIST,
			     102, UNIPHIER_PIN_DRV_3BIT,
			     151, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(152, "XIRQ3", UNIPHIER_PIN_IECTRL_EXIST,
			     103, UNIPHIER_PIN_DRV_3BIT,
			     152, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(153, "XIRQ4", UNIPHIER_PIN_IECTRL_EXIST,
			     104, UNIPHIER_PIN_DRV_3BIT,
			     153, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(154, "XIRQ5", UNIPHIER_PIN_IECTRL_EXIST,
			     105, UNIPHIER_PIN_DRV_3BIT,
			     154, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(155, "XIRQ6", UNIPHIER_PIN_IECTRL_EXIST,
			     106, UNIPHIER_PIN_DRV_3BIT,
			     155, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(156, "XIRQ7", UNIPHIER_PIN_IECTRL_EXIST,
			     107, UNIPHIER_PIN_DRV_3BIT,
			     156, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(157, "XIRQ8", UNIPHIER_PIN_IECTRL_EXIST,
			     108, UNIPHIER_PIN_DRV_3BIT,
			     157, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(158, "XIRQ9", UNIPHIER_PIN_IECTRL_EXIST,
			     109, UNIPHIER_PIN_DRV_3BIT,
			     158, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(159, "XIRQ10", UNIPHIER_PIN_IECTRL_EXIST,
			     110, UNIPHIER_PIN_DRV_3BIT,
			     159, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(160, "XIRQ11", UNIPHIER_PIN_IECTRL_EXIST,
			     111, UNIPHIER_PIN_DRV_3BIT,
			     160, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(161, "XIRQ13", UNIPHIER_PIN_IECTRL_EXIST,
			     112, UNIPHIER_PIN_DRV_3BIT,
			     161, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(162, "XIRQ14", UNIPHIER_PIN_IECTRL_EXIST,
			     113, UNIPHIER_PIN_DRV_3BIT,
			     162, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(163, "XIRQ16", UNIPHIER_PIN_IECTRL_EXIST,
			     114, UNIPHIER_PIN_DRV_3BIT,
			     163, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(164, "XIRQ17", UNIPHIER_PIN_IECTRL_EXIST,
			     115, UNIPHIER_PIN_DRV_3BIT,
			     164, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(165, "XIRQ18", UNIPHIER_PIN_IECTRL_EXIST,
			     116, UNIPHIER_PIN_DRV_3BIT,
			     165, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(166, "XIRQ19", UNIPHIER_PIN_IECTRL_EXIST,
			     117, UNIPHIER_PIN_DRV_3BIT,
			     166, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(167, "XIRQ20", UNIPHIER_PIN_IECTRL_EXIST,
			     118, UNIPHIER_PIN_DRV_3BIT,
			     167, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(168, "PORT00", UNIPHIER_PIN_IECTRL_EXIST,
			     119, UNIPHIER_PIN_DRV_3BIT,
			     168, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(169, "PORT01", UNIPHIER_PIN_IECTRL_EXIST,
			     120, UNIPHIER_PIN_DRV_3BIT,
			     169, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(170, "PORT02", UNIPHIER_PIN_IECTRL_EXIST,
			     121, UNIPHIER_PIN_DRV_3BIT,
			     170, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(171, "PORT03", UNIPHIER_PIN_IECTRL_EXIST,
			     122, UNIPHIER_PIN_DRV_3BIT,
			     171, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(172, "PORT04", UNIPHIER_PIN_IECTRL_EXIST,
			     123, UNIPHIER_PIN_DRV_3BIT,
			     172, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(173, "CK27FO", UNIPHIER_PIN_IECTRL_EXIST,
			     124, UNIPHIER_PIN_DRV_3BIT,
			     173, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(174, "PHSYNCO", UNIPHIER_PIN_IECTRL_EXIST,
			     125, UNIPHIER_PIN_DRV_3BIT,
			     174, UNIPHIER_PIN_PULL_DOWN),
	UNIPHIER_PINCTRL_PIN(175, "PVSYNCO", UNIPHIER_PIN_IECTRL_EXIST,
			     126, UNIPHIER_PIN_DRV_3BIT,
			     175, UNIPHIER_PIN_PULL_DOWN),
};

static const unsigned aout1_pins[] = {137, 138, 139, 140, 141, 142};
static const int aout1_muxvals[] = {0, 0, 0, 0, 0, 0};
static const unsigned aoutiec1_pins[] = {135, 136};
static const int aoutiec1_muxvals[] = {0, 0};
static const unsigned int emmc_pins[] = {19, 20, 21, 22, 23, 24, 25};
static const int emmc_muxvals[] = {0, 0, 0, 0, 0, 0, 0};
static const unsigned emmc_dat8_pins[] = {26, 27, 28, 29};
static const int emmc_dat8_muxvals[] = {0, 0, 0, 0};
static const unsigned ether_rgmii_pins[] = {30, 31, 32, 33, 34, 35, 36, 37, 38,
					    39, 40, 41, 42, 43, 44, 45};
static const int ether_rgmii_muxvals[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					  0, 0, 0, 0};
static const unsigned ether_rmii_pins[] = {30, 31, 32, 33, 34, 35, 36, 37, 39,
					   41, 42, 45};
static const int ether_rmii_muxvals[] = {0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1};
static const unsigned i2c0_pins[] = {63, 64};
static const int i2c0_muxvals[] = {0, 0};
static const unsigned i2c1_pins[] = {65, 66};
static const int i2c1_muxvals[] = {0, 0};
static const unsigned i2c3_pins[] = {67, 68};
static const int i2c3_muxvals[] = {1, 1};
static const unsigned i2c4_pins[] = {61, 62};
static const int i2c4_muxvals[] = {1, 1};
static const unsigned nand_pins[] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
				     15, 16, 17};
static const int nand_muxvals[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const unsigned sd_pins[] = {10, 11, 12, 13, 14, 15, 16, 17};
static const int sd_muxvals[] = {3, 3, 3, 3, 3, 3, 3, 3};  /* No SDVOLC */
static const unsigned system_bus_pins[] = {1, 2, 6, 7, 8, 9, 10, 11, 12, 13,
					   14, 15, 16, 17};
static const int system_bus_muxvals[] = {0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
					 2};
static const unsigned system_bus_cs1_pins[] = {0};
static const int system_bus_cs1_muxvals[] = {0};
static const unsigned uart0_pins[] = {54, 55};
static const int uart0_muxvals[] = {0, 0};
static const unsigned uart1_pins[] = {58, 59};
static const int uart1_muxvals[] = {1, 1};
static const unsigned uart2_pins[] = {90, 91};
static const int uart2_muxvals[] = {1, 1};
static const unsigned uart3_pins[] = {94, 95};
static const int uart3_muxvals[] = {1, 1};
static const unsigned uart3_ctsrts_pins[] = {96, 97, 98, 99, 100, 101};
static const int uart3_ctsrts_muxvals[] = {1, 1, 1, 1, 1, 1};
static const unsigned usb0_pins[] = {46, 47};
static const int usb0_muxvals[] = {0, 0};
static const unsigned usb1_pins[] = {48, 49};
static const int usb1_muxvals[] = {0, 0};
static const unsigned usb2_pins[] = {50, 51};
static const int usb2_muxvals[] = {0, 0};
static const unsigned usb3_pins[] = {52, 53};
static const int usb3_muxvals[] = {0, 0};
static const unsigned int gpio_range0_pins[] = {
	168, 169, 170, 171, 172, 173, 174, 175,		/* PORT0x */
	0, 1, 2, 3, 4, 5, 6, 7,				/* PORT1x */
	8, 9, 10, 11, 12, 13, 14, 15,			/* PORT2x */
	16, 17, 18, 30, 31, 32, 33, 34,			/* PORT3x */
	35, 36, 37, 38, 39, 40, 41, 42,			/* PORT4x */
	43, 44, 45, 46, 47, 48, 49, 50,			/* PORT5x */
	51, 52, 53, 54, 55, 56, 57, 58,			/* PORT6x */
	59, 60, 69, 70, 71, 72, 73, 74,			/* PORT7x */
	75, 76, 77, 78, 79, 80, 81, 82,			/* PORT8x */
	83, 84, 85, 86, 87, 88, 89, 90,			/* PORT9x */
	91, 92, 93, 94, 95, 96, 97, 98,			/* PORT10x */
};
static const unsigned int gpio_range1_pins[] = {
	99, 100, 101, 102, 103, 104, 105, 106,		/* PORT12x */
	107, 108, 109, 110, 111, 112, 113, 114,		/* PORT13x */
	115, 116, 117, 118, 119, 120, 121, 122,		/* PORT14x */
	149, 150, 151, 152, 153, 154, 155, 156,		/* XIRQ0-7 */
	157, 158, 159, 160, 85, 161, 162, 84,		/* XIRQ8-15 */
	163, 164, 165, 166, 167, 146, 52, 53,		/* XIRQ16-23 */
	61, 62, 63, 64, 65, 66, 67, 68,			/* PORT18x */
};
static const unsigned int gpio_range2_pins[] = {
	123, 124, 125, 126, 127, 128, 129, 130,		/* PORT20x */
	131, 132, 133, 134, 135, 136, 137, 138,		/* PORT21x */
	139, 140, 141, 142, 143, 144, 145, 146,		/* PORT22x */
	147, 148, 149, 150, 151, 152, 153, 154,		/* PORT23x */
	155, 156, 157, 158, 159, 160, 161, 162,		/* PORT24x */
	163, 164, 165, 166, 167,			/* PORT250-254 */
};

static const struct uniphier_pinctrl_group uniphier_ld20_groups[] = {
	UNIPHIER_PINCTRL_GROUP(aout1),
	UNIPHIER_PINCTRL_GROUP(aoutiec1),
	UNIPHIER_PINCTRL_GROUP(emmc),
	UNIPHIER_PINCTRL_GROUP(emmc_dat8),
	UNIPHIER_PINCTRL_GROUP(ether_rgmii),
	UNIPHIER_PINCTRL_GROUP(ether_rmii),
	UNIPHIER_PINCTRL_GROUP(i2c0),
	UNIPHIER_PINCTRL_GROUP(i2c1),
	UNIPHIER_PINCTRL_GROUP(i2c3),
	UNIPHIER_PINCTRL_GROUP(i2c4),
	UNIPHIER_PINCTRL_GROUP(nand),
	UNIPHIER_PINCTRL_GROUP(sd),
	UNIPHIER_PINCTRL_GROUP(system_bus),
	UNIPHIER_PINCTRL_GROUP(system_bus_cs1),
	UNIPHIER_PINCTRL_GROUP(uart0),
	UNIPHIER_PINCTRL_GROUP(uart1),
	UNIPHIER_PINCTRL_GROUP(uart2),
	UNIPHIER_PINCTRL_GROUP(uart3),
	UNIPHIER_PINCTRL_GROUP(uart3_ctsrts),
	UNIPHIER_PINCTRL_GROUP(usb0),
	UNIPHIER_PINCTRL_GROUP(usb1),
	UNIPHIER_PINCTRL_GROUP(usb2),
	UNIPHIER_PINCTRL_GROUP(usb3),
	UNIPHIER_PINCTRL_GROUP_GPIO(gpio_range0),
	UNIPHIER_PINCTRL_GROUP_GPIO(gpio_range1),
	UNIPHIER_PINCTRL_GROUP_GPIO(gpio_range2),
};

static const char * const aout1_groups[] = {"aout1"};
static const char * const aoutiec1_groups[] = {"aoutiec1"};
static const char * const emmc_groups[] = {"emmc", "emmc_dat8"};
static const char * const ether_rgmii_groups[] = {"ether_rgmii"};
static const char * const ether_rmii_groups[] = {"ether_rmii"};
static const char * const i2c0_groups[] = {"i2c0"};
static const char * const i2c1_groups[] = {"i2c1"};
static const char * const i2c3_groups[] = {"i2c3"};
static const char * const i2c4_groups[] = {"i2c4"};
static const char * const nand_groups[] = {"nand"};
static const char * const sd_groups[] = {"sd"};
static const char * const system_bus_groups[] = {"system_bus",
						 "system_bus_cs1"};
static const char * const uart0_groups[] = {"uart0"};
static const char * const uart1_groups[] = {"uart1"};
static const char * const uart2_groups[] = {"uart2"};
static const char * const uart3_groups[] = {"uart3", "uart3_ctsrts"};
static const char * const usb0_groups[] = {"usb0"};
static const char * const usb1_groups[] = {"usb1"};
static const char * const usb2_groups[] = {"usb2"};
static const char * const usb3_groups[] = {"usb3"};

static const struct uniphier_pinmux_function uniphier_ld20_functions[] = {
	UNIPHIER_PINMUX_FUNCTION(aout1),
	UNIPHIER_PINMUX_FUNCTION(aoutiec1),
	UNIPHIER_PINMUX_FUNCTION(emmc),
	UNIPHIER_PINMUX_FUNCTION(ether_rgmii),
	UNIPHIER_PINMUX_FUNCTION(ether_rmii),
	UNIPHIER_PINMUX_FUNCTION(i2c0),
	UNIPHIER_PINMUX_FUNCTION(i2c1),
	UNIPHIER_PINMUX_FUNCTION(i2c3),
	UNIPHIER_PINMUX_FUNCTION(i2c4),
	UNIPHIER_PINMUX_FUNCTION(nand),
	UNIPHIER_PINMUX_FUNCTION(sd),
	UNIPHIER_PINMUX_FUNCTION(system_bus),
	UNIPHIER_PINMUX_FUNCTION(uart0),
	UNIPHIER_PINMUX_FUNCTION(uart1),
	UNIPHIER_PINMUX_FUNCTION(uart2),
	UNIPHIER_PINMUX_FUNCTION(uart3),
	UNIPHIER_PINMUX_FUNCTION(usb0),
	UNIPHIER_PINMUX_FUNCTION(usb1),
	UNIPHIER_PINMUX_FUNCTION(usb2),
	UNIPHIER_PINMUX_FUNCTION(usb3),
};

static int uniphier_ld20_get_gpio_muxval(unsigned int pin,
					 unsigned int gpio_offset)
{
	if (gpio_offset == 132 || gpio_offset == 135)	/* XIRQ12, 15 */
		return 13;

	if (gpio_offset >= 120 && gpio_offset <= 143)	/* XIRQx */
		return 14;

	return 15;
}

static struct uniphier_pinctrl_socdata uniphier_ld20_pindata = {
	.pins = uniphier_ld20_pins,
	.npins = ARRAY_SIZE(uniphier_ld20_pins),
	.groups = uniphier_ld20_groups,
	.groups_count = ARRAY_SIZE(uniphier_ld20_groups),
	.functions = uniphier_ld20_functions,
	.functions_count = ARRAY_SIZE(uniphier_ld20_functions),
	.get_gpio_muxval = uniphier_ld20_get_gpio_muxval,
	.caps = UNIPHIER_PINCTRL_CAPS_PERPIN_IECTRL,
};

static int uniphier_ld20_pinctrl_probe(struct platform_device *pdev)
{
	return uniphier_pinctrl_probe(pdev, &uniphier_ld20_pindata);
}

static const struct of_device_id uniphier_ld20_pinctrl_match[] = {
	{ .compatible = "socionext,uniphier-ld20-pinctrl" },
	{ /* sentinel */ }
};

static struct platform_driver uniphier_ld20_pinctrl_driver = {
	.probe = uniphier_ld20_pinctrl_probe,
	.driver = {
		.name = "uniphier-ld20-pinctrl",
		.of_match_table = uniphier_ld20_pinctrl_match,
		.pm = &uniphier_pinctrl_pm_ops,
	},
};
builtin_platform_driver(uniphier_ld20_pinctrl_driver);
