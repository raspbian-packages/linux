/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) ST-Ericsson SA 2010
 * Author: Mattias Nilsson <mattias.i.nilsson@stericsson.com> for ST Ericsson.
 */
#ifndef __AB8500_SYSCTRL_H
#define __AB8500_SYSCTRL_H

#include <linux/bitops.h>

#ifdef CONFIG_AB8500_CORE

int ab8500_sysctrl_read(u16 reg, u8 *value);
int ab8500_sysctrl_write(u16 reg, u8 mask, u8 value);

#else

static inline int ab8500_sysctrl_read(u16 reg, u8 *value)
{
	return 0;
}

static inline int ab8500_sysctrl_write(u16 reg, u8 mask, u8 value)
{
	return 0;
}

#endif /* CONFIG_AB8500_CORE */

static inline int ab8500_sysctrl_set(u16 reg, u8 bits)
{
	return ab8500_sysctrl_write(reg, bits, bits);
}

static inline int ab8500_sysctrl_clear(u16 reg, u8 bits)
{
	return ab8500_sysctrl_write(reg, bits, 0);
}

/* Registers */
#define AB8500_TURNONSTATUS		0x100
#define AB8500_RESETSTATUS		0x101
#define AB8500_PONKEY1PRESSSTATUS	0x102
#define AB8500_SYSCLKREQSTATUS		0x142
#define AB8500_STW4500CTRL1		0x180
#define AB8500_STW4500CTRL2		0x181
#define AB8500_STW4500CTRL3		0x200
#define AB8500_MAINWDOGCTRL		0x201
#define AB8500_MAINWDOGTIMER		0x202
#define AB8500_LOWBAT			0x203
#define AB8500_BATTOK			0x204
#define AB8500_SYSCLKTIMER		0x205
#define AB8500_SMPSCLKCTRL		0x206
#define AB8500_SMPSCLKSEL1		0x207
#define AB8500_SMPSCLKSEL2		0x208
#define AB8500_SMPSCLKSEL3		0x209
#define AB8500_SYSULPCLKCONF		0x20A
#define AB8500_SYSULPCLKCTRL1		0x20B
#define AB8500_SYSCLKCTRL		0x20C
#define AB8500_SYSCLKREQ1VALID		0x20D
#define AB8500_SYSTEMCTRLSUP		0x20F
#define AB8500_SYSCLKREQ1RFCLKBUF	0x210
#define AB8500_SYSCLKREQ2RFCLKBUF	0x211
#define AB8500_SYSCLKREQ3RFCLKBUF	0x212
#define AB8500_SYSCLKREQ4RFCLKBUF	0x213
#define AB8500_SYSCLKREQ5RFCLKBUF	0x214
#define AB8500_SYSCLKREQ6RFCLKBUF	0x215
#define AB8500_SYSCLKREQ7RFCLKBUF	0x216
#define AB8500_SYSCLKREQ8RFCLKBUF	0x217
#define AB8500_DITHERCLKCTRL		0x220
#define AB8500_SWATCTRL			0x230
#define AB8500_HIQCLKCTRL		0x232
#define AB8500_VSIMSYSCLKCTRL		0x233
#define AB9540_SYSCLK12BUFCTRL		0x234
#define AB9540_SYSCLK12CONFCTRL		0x235
#define AB9540_SYSCLK12BUFCTRL2		0x236
#define AB9540_SYSCLK12BUF1VALID	0x237
#define AB9540_SYSCLK12BUF2VALID	0x238
#define AB9540_SYSCLK12BUF3VALID	0x239
#define AB9540_SYSCLK12BUF4VALID	0x23A

/* Bits */
#define AB8500_TURNONSTATUS_PORNVBAT BIT(0)
#define AB8500_TURNONSTATUS_PONKEY1DBF BIT(1)
#define AB8500_TURNONSTATUS_PONKEY2DBF BIT(2)
#define AB8500_TURNONSTATUS_RTCALARM BIT(3)
#define AB8500_TURNONSTATUS_MAINCHDET BIT(4)
#define AB8500_TURNONSTATUS_VBUSDET BIT(5)
#define AB8500_TURNONSTATUS_USBIDDETECT BIT(6)

#define AB8500_RESETSTATUS_RESETN4500NSTATUS BIT(0)
#define AB8500_RESETSTATUS_SWRESETN4500NSTATUS BIT(2)

#define AB8500_PONKEY1PRESSSTATUS_PONKEY1PRESSTIME_MASK 0x7F
#define AB8500_PONKEY1PRESSSTATUS_PONKEY1PRESSTIME_SHIFT 0

#define AB8500_SYSCLKREQSTATUS_SYSCLKREQ1STATUS BIT(0)
#define AB8500_SYSCLKREQSTATUS_SYSCLKREQ2STATUS BIT(1)
#define AB8500_SYSCLKREQSTATUS_SYSCLKREQ3STATUS BIT(2)
#define AB8500_SYSCLKREQSTATUS_SYSCLKREQ4STATUS BIT(3)
#define AB8500_SYSCLKREQSTATUS_SYSCLKREQ5STATUS BIT(4)
#define AB8500_SYSCLKREQSTATUS_SYSCLKREQ6STATUS BIT(5)
#define AB8500_SYSCLKREQSTATUS_SYSCLKREQ7STATUS BIT(6)
#define AB8500_SYSCLKREQSTATUS_SYSCLKREQ8STATUS BIT(7)

#define AB8500_STW4500CTRL1_SWOFF BIT(0)
#define AB8500_STW4500CTRL1_SWRESET4500N BIT(1)
#define AB8500_STW4500CTRL1_THDB8500SWOFF BIT(2)

#define AB8500_STW4500CTRL2_RESETNVAUX1VALID BIT(0)
#define AB8500_STW4500CTRL2_RESETNVAUX2VALID BIT(1)
#define AB8500_STW4500CTRL2_RESETNVAUX3VALID BIT(2)
#define AB8500_STW4500CTRL2_RESETNVMODVALID BIT(3)
#define AB8500_STW4500CTRL2_RESETNVEXTSUPPLY1VALID BIT(4)
#define AB8500_STW4500CTRL2_RESETNVEXTSUPPLY2VALID BIT(5)
#define AB8500_STW4500CTRL2_RESETNVEXTSUPPLY3VALID BIT(6)
#define AB8500_STW4500CTRL2_RESETNVSMPS1VALID BIT(7)

#define AB8500_STW4500CTRL3_CLK32KOUT2DIS BIT(0)
#define AB8500_STW4500CTRL3_RESETAUDN BIT(1)
#define AB8500_STW4500CTRL3_RESETDENCN BIT(2)
#define AB8500_STW4500CTRL3_THSDENA BIT(3)

#define AB8500_MAINWDOGCTRL_MAINWDOGENA BIT(0)
#define AB8500_MAINWDOGCTRL_MAINWDOGKICK BIT(1)
#define AB8500_MAINWDOGCTRL_WDEXPTURNONVALID BIT(4)

#define AB8500_MAINWDOGTIMER_MAINWDOGTIMER_MASK 0x7F
#define AB8500_MAINWDOGTIMER_MAINWDOGTIMER_SHIFT 0

#define AB8500_LOWBAT_LOWBATENA BIT(0)
#define AB8500_LOWBAT_LOWBAT_MASK 0x7E
#define AB8500_LOWBAT_LOWBAT_SHIFT 1

#define AB8500_BATTOK_BATTOKSEL0THF_MASK 0x0F
#define AB8500_BATTOK_BATTOKSEL0THF_SHIFT 0
#define AB8500_BATTOK_BATTOKSEL1THF_MASK 0xF0
#define AB8500_BATTOK_BATTOKSEL1THF_SHIFT 4

#define AB8500_SYSCLKTIMER_SYSCLKTIMER_MASK 0x0F
#define AB8500_SYSCLKTIMER_SYSCLKTIMER_SHIFT 0
#define AB8500_SYSCLKTIMER_SYSCLKTIMERADJ_MASK 0xF0
#define AB8500_SYSCLKTIMER_SYSCLKTIMERADJ_SHIFT 4

#define AB8500_SMPSCLKCTRL_SMPSCLKINTSEL_MASK 0x03
#define AB8500_SMPSCLKCTRL_SMPSCLKINTSEL_SHIFT 0
#define AB8500_SMPSCLKCTRL_3M2CLKINTENA BIT(2)

#define AB8500_SMPSCLKSEL1_VARMCLKSEL_MASK 0x07
#define AB8500_SMPSCLKSEL1_VARMCLKSEL_SHIFT 0
#define AB8500_SMPSCLKSEL1_VAPECLKSEL_MASK 0x38
#define AB8500_SMPSCLKSEL1_VAPECLKSEL_SHIFT 3

#define AB8500_SMPSCLKSEL2_VMODCLKSEL_MASK 0x07
#define AB8500_SMPSCLKSEL2_VMODCLKSEL_SHIFT 0
#define AB8500_SMPSCLKSEL2_VSMPS1CLKSEL_MASK 0x38
#define AB8500_SMPSCLKSEL2_VSMPS1CLKSEL_SHIFT 3

#define AB8500_SMPSCLKSEL3_VSMPS2CLKSEL_MASK 0x07
#define AB8500_SMPSCLKSEL3_VSMPS2CLKSEL_SHIFT 0
#define AB8500_SMPSCLKSEL3_VSMPS3CLKSEL_MASK 0x38
#define AB8500_SMPSCLKSEL3_VSMPS3CLKSEL_SHIFT 3

#define AB8500_SYSULPCLKCONF_ULPCLKCONF_MASK 0x03
#define AB8500_SYSULPCLKCONF_ULPCLKCONF_SHIFT 0
#define AB8500_SYSULPCLKCONF_CLK27MHZSTRE BIT(2)
#define AB8500_SYSULPCLKCONF_TVOUTCLKDELN BIT(3)
#define AB8500_SYSULPCLKCONF_TVOUTCLKINV BIT(4)
#define AB8500_SYSULPCLKCONF_ULPCLKSTRE BIT(5)
#define AB8500_SYSULPCLKCONF_CLK27MHZBUFENA BIT(6)
#define AB8500_SYSULPCLKCONF_CLK27MHZPDENA BIT(7)

#define AB8500_SYSULPCLKCTRL1_SYSULPCLKINTSEL_MASK 0x03
#define AB8500_SYSULPCLKCTRL1_SYSULPCLKINTSEL_SHIFT 0
#define AB8500_SYSULPCLKCTRL1_ULPCLKREQ BIT(2)
#define AB8500_SYSULPCLKCTRL1_4500SYSCLKREQ BIT(3)
#define AB8500_SYSULPCLKCTRL1_AUDIOCLKENA BIT(4)
#define AB8500_SYSULPCLKCTRL1_SYSCLKBUF2REQ BIT(5)
#define AB8500_SYSULPCLKCTRL1_SYSCLKBUF3REQ BIT(6)
#define AB8500_SYSULPCLKCTRL1_SYSCLKBUF4REQ BIT(7)

#define AB8500_SYSCLKCTRL_TVOUTPLLENA BIT(0)
#define AB8500_SYSCLKCTRL_TVOUTCLKENA BIT(1)
#define AB8500_SYSCLKCTRL_USBCLKENA BIT(2)

#define AB8500_SYSCLKREQ1VALID_SYSCLKREQ1VALID BIT(0)
#define AB8500_SYSCLKREQ1VALID_ULPCLKREQ1VALID BIT(1)
#define AB8500_SYSCLKREQ1VALID_USBSYSCLKREQ1VALID BIT(2)

#define AB8500_SYSTEMCTRLSUP_EXTSUP12LPNCLKSEL_MASK 0x03
#define AB8500_SYSTEMCTRLSUP_EXTSUP12LPNCLKSEL_SHIFT 0
#define AB8500_SYSTEMCTRLSUP_EXTSUP3LPNCLKSEL_MASK 0x0C
#define AB8500_SYSTEMCTRLSUP_EXTSUP3LPNCLKSEL_SHIFT 2
#define AB8500_SYSTEMCTRLSUP_INTDB8500NOD BIT(4)

#define AB8500_SYSCLKREQ1RFCLKBUF_SYSCLKREQ1RFCLKBUF2 BIT(2)
#define AB8500_SYSCLKREQ1RFCLKBUF_SYSCLKREQ1RFCLKBUF3 BIT(3)
#define AB8500_SYSCLKREQ1RFCLKBUF_SYSCLKREQ1RFCLKBUF4 BIT(4)

#define AB8500_SYSCLKREQ2RFCLKBUF_SYSCLKREQ2RFCLKBUF2 BIT(2)
#define AB8500_SYSCLKREQ2RFCLKBUF_SYSCLKREQ2RFCLKBUF3 BIT(3)
#define AB8500_SYSCLKREQ2RFCLKBUF_SYSCLKREQ2RFCLKBUF4 BIT(4)

#define AB8500_SYSCLKREQ3RFCLKBUF_SYSCLKREQ3RFCLKBUF2 BIT(2)
#define AB8500_SYSCLKREQ3RFCLKBUF_SYSCLKREQ3RFCLKBUF3 BIT(3)
#define AB8500_SYSCLKREQ3RFCLKBUF_SYSCLKREQ3RFCLKBUF4 BIT(4)

#define AB8500_SYSCLKREQ4RFCLKBUF_SYSCLKREQ4RFCLKBUF2 BIT(2)
#define AB8500_SYSCLKREQ4RFCLKBUF_SYSCLKREQ4RFCLKBUF3 BIT(3)
#define AB8500_SYSCLKREQ4RFCLKBUF_SYSCLKREQ4RFCLKBUF4 BIT(4)

#define AB8500_SYSCLKREQ5RFCLKBUF_SYSCLKREQ5RFCLKBUF2 BIT(2)
#define AB8500_SYSCLKREQ5RFCLKBUF_SYSCLKREQ5RFCLKBUF3 BIT(3)
#define AB8500_SYSCLKREQ5RFCLKBUF_SYSCLKREQ5RFCLKBUF4 BIT(4)

#define AB8500_SYSCLKREQ6RFCLKBUF_SYSCLKREQ6RFCLKBUF2 BIT(2)
#define AB8500_SYSCLKREQ6RFCLKBUF_SYSCLKREQ6RFCLKBUF3 BIT(3)
#define AB8500_SYSCLKREQ6RFCLKBUF_SYSCLKREQ6RFCLKBUF4 BIT(4)

#define AB8500_SYSCLKREQ7RFCLKBUF_SYSCLKREQ7RFCLKBUF2 BIT(2)
#define AB8500_SYSCLKREQ7RFCLKBUF_SYSCLKREQ7RFCLKBUF3 BIT(3)
#define AB8500_SYSCLKREQ7RFCLKBUF_SYSCLKREQ7RFCLKBUF4 BIT(4)

#define AB8500_SYSCLKREQ8RFCLKBUF_SYSCLKREQ8RFCLKBUF2 BIT(2)
#define AB8500_SYSCLKREQ8RFCLKBUF_SYSCLKREQ8RFCLKBUF3 BIT(3)
#define AB8500_SYSCLKREQ8RFCLKBUF_SYSCLKREQ8RFCLKBUF4 BIT(4)

#define AB8500_DITHERCLKCTRL_VARMDITHERENA BIT(0)
#define AB8500_DITHERCLKCTRL_VSMPS3DITHERENA BIT(1)
#define AB8500_DITHERCLKCTRL_VSMPS1DITHERENA BIT(2)
#define AB8500_DITHERCLKCTRL_VSMPS2DITHERENA BIT(3)
#define AB8500_DITHERCLKCTRL_VMODDITHERENA BIT(4)
#define AB8500_DITHERCLKCTRL_VAPEDITHERENA BIT(5)
#define AB8500_DITHERCLKCTRL_DITHERDEL_MASK 0xC0
#define AB8500_DITHERCLKCTRL_DITHERDEL_SHIFT 6

#define AB8500_SWATCTRL_UPDATERF BIT(0)
#define AB8500_SWATCTRL_SWATENABLE BIT(1)
#define AB8500_SWATCTRL_RFOFFTIMER_MASK 0x1C
#define AB8500_SWATCTRL_RFOFFTIMER_SHIFT 2
#define AB8500_SWATCTRL_SWATBIT5 BIT(6)

#define AB8500_HIQCLKCTRL_SYSCLKREQ1HIQENAVALID BIT(0)
#define AB8500_HIQCLKCTRL_SYSCLKREQ2HIQENAVALID BIT(1)
#define AB8500_HIQCLKCTRL_SYSCLKREQ3HIQENAVALID BIT(2)
#define AB8500_HIQCLKCTRL_SYSCLKREQ4HIQENAVALID BIT(3)
#define AB8500_HIQCLKCTRL_SYSCLKREQ5HIQENAVALID BIT(4)
#define AB8500_HIQCLKCTRL_SYSCLKREQ6HIQENAVALID BIT(5)
#define AB8500_HIQCLKCTRL_SYSCLKREQ7HIQENAVALID BIT(6)
#define AB8500_HIQCLKCTRL_SYSCLKREQ8HIQENAVALID BIT(7)

#define AB8500_VSIMSYSCLKCTRL_VSIMSYSCLKREQ1VALID BIT(0)
#define AB8500_VSIMSYSCLKCTRL_VSIMSYSCLKREQ2VALID BIT(1)
#define AB8500_VSIMSYSCLKCTRL_VSIMSYSCLKREQ3VALID BIT(2)
#define AB8500_VSIMSYSCLKCTRL_VSIMSYSCLKREQ4VALID BIT(3)
#define AB8500_VSIMSYSCLKCTRL_VSIMSYSCLKREQ5VALID BIT(4)
#define AB8500_VSIMSYSCLKCTRL_VSIMSYSCLKREQ6VALID BIT(5)
#define AB8500_VSIMSYSCLKCTRL_VSIMSYSCLKREQ7VALID BIT(6)
#define AB8500_VSIMSYSCLKCTRL_VSIMSYSCLKREQ8VALID BIT(7)

#define AB9540_SYSCLK12BUFCTRL_SYSCLK12BUF1ENA BIT(0)
#define AB9540_SYSCLK12BUFCTRL_SYSCLK12BUF2ENA BIT(1)
#define AB9540_SYSCLK12BUFCTRL_SYSCLK12BUF3ENA BIT(2)
#define AB9540_SYSCLK12BUFCTRL_SYSCLK12BUF4ENA BIT(3)
#define AB9540_SYSCLK12BUFCTRL_SYSCLK12BUFENA_MASK 0x0F
#define AB9540_SYSCLK12BUFCTRL_SYSCLK12BUF1STRE BIT(4)
#define AB9540_SYSCLK12BUFCTRL_SYSCLK12BUF2STRE BIT(5)
#define AB9540_SYSCLK12BUFCTRL_SYSCLK12BUF3STRE BIT(6)
#define AB9540_SYSCLK12BUFCTRL_SYSCLK12BUF4STRE BIT(7)
#define AB9540_SYSCLK12BUFCTRL_SYSCLK12BUFSTRE_MASK 0xF0

#define AB9540_SYSCLK12CONFCTRL_PLL26TO38ENA BIT(0)
#define AB9540_SYSCLK12CONFCTRL_SYSCLK12USBMUXSEL BIT(1)
#define AB9540_SYSCLK12CONFCTRL_INT384MHZMUXSEL0 BIT(2)
#define AB9540_SYSCLK12CONFCTRL_INT384MHZMUXSEL1 BIT(3)
#define AB9540_SYSCLK12CONFCTRL_SYSCLK12BUFMUX BIT(4)
#define AB9540_SYSCLK12CONFCTRL_SYSCLK12PLLMUX BIT(5)
#define AB9540_SYSCLK12CONFCTRL_SYSCLK2MUXVALID BIT(6)

#define AB9540_SYSCLK12BUFCTRL2_SYSCLK12BUF1PDENA BIT(0)
#define AB9540_SYSCLK12BUFCTRL2_SYSCLK12BUF2PDENA BIT(1)
#define AB9540_SYSCLK12BUFCTRL2_SYSCLK12BUF3PDENA BIT(2)
#define AB9540_SYSCLK12BUFCTRL2_SYSCLK12BUF4PDENA BIT(3)

#define AB9540_SYSCLK12BUF1VALID_SYSCLK12BUF1VALID_MASK 0xFF
#define AB9540_SYSCLK12BUF1VALID_SYSCLK12BUF1VALID_SHIFT 0

#define AB9540_SYSCLK12BUF2VALID_SYSCLK12BUF2VALID_MASK 0xFF
#define AB9540_SYSCLK12BUF2VALID_SYSCLK12BUF2VALID_SHIFT 0

#define AB9540_SYSCLK12BUF3VALID_SYSCLK12BUF3VALID_MASK 0xFF
#define AB9540_SYSCLK12BUF3VALID_SYSCLK12BUF3VALID_SHIFT 0

#define AB9540_SYSCLK12BUF4VALID_SYSCLK12BUF4VALID_MASK 0xFF
#define AB9540_SYSCLK12BUF4VALID_SYSCLK12BUF4VALID_SHIFT 0

#define AB8500_ENABLE_WD 0x1
#define AB8500_KICK_WD 0x2
#define AB8500_WD_RESTART_ON_EXPIRE 0x10

#endif /* __AB8500_SYSCTRL_H */
