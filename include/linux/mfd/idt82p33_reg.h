/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Register Map - Based on AN888_SMUforIEEE_SynchEther_82P33xxx_RevH.pdf
 *
 * Copyright (C) 2021 Integrated Device Technology, Inc., a Renesas Company.
 */
#ifndef HAVE_IDT82P33_REG
#define HAVE_IDT82P33_REG

/* Register address */
#define DPLL1_TOD_CNFG 0x134
#define DPLL2_TOD_CNFG 0x1B4

#define DPLL1_TOD_STS 0x10B
#define DPLL2_TOD_STS 0x18B

#define DPLL1_TOD_TRIGGER 0x115
#define DPLL2_TOD_TRIGGER 0x195

#define DPLL1_OPERATING_MODE_CNFG 0x120
#define DPLL2_OPERATING_MODE_CNFG 0x1A0

#define DPLL1_HOLDOVER_FREQ_CNFG 0x12C
#define DPLL2_HOLDOVER_FREQ_CNFG 0x1AC

#define DPLL1_PHASE_OFFSET_CNFG 0x143
#define DPLL2_PHASE_OFFSET_CNFG 0x1C3

#define DPLL1_SYNC_EDGE_CNFG 0x140
#define DPLL2_SYNC_EDGE_CNFG 0x1C0

#define DPLL1_INPUT_MODE_CNFG 0x116
#define DPLL2_INPUT_MODE_CNFG 0x196

#define DPLL1_OPERATING_STS 0x102
#define DPLL2_OPERATING_STS 0x182

#define DPLL1_CURRENT_FREQ_STS 0x103
#define DPLL2_CURRENT_FREQ_STS 0x183

#define REG_SOFT_RESET 0X381

#define OUT_MUX_CNFG(outn) REG_ADDR(0x6, (0xC * (outn)))

/* Register bit definitions */
#define SYNC_TOD BIT(1)
#define PH_OFFSET_EN BIT(7)
#define SQUELCH_ENABLE BIT(5)

/* Bit definitions for the DPLL_MODE register */
#define PLL_MODE_SHIFT		(0)
#define PLL_MODE_MASK		(0x1F)
#define COMBO_MODE_EN		BIT(5)
#define COMBO_MODE_SHIFT	(6)
#define COMBO_MODE_MASK		(0x3)

/* Bit definitions for DPLL_OPERATING_STS register */
#define OPERATING_STS_MASK	(0x7)
#define OPERATING_STS_SHIFT	(0x0)

/* Bit definitions for DPLL_TOD_TRIGGER register */
#define READ_TRIGGER_MASK	(0xF)
#define READ_TRIGGER_SHIFT	(0x0)
#define WRITE_TRIGGER_MASK	(0xF0)
#define WRITE_TRIGGER_SHIFT	(0x4)

/* Bit definitions for REG_SOFT_RESET register */
#define SOFT_RESET_EN		BIT(7)

enum pll_mode {
	PLL_MODE_MIN = 0,
	PLL_MODE_AUTOMATIC = PLL_MODE_MIN,
	PLL_MODE_FORCE_FREERUN = 1,
	PLL_MODE_FORCE_HOLDOVER = 2,
	PLL_MODE_FORCE_LOCKED = 4,
	PLL_MODE_FORCE_PRE_LOCKED2 = 5,
	PLL_MODE_FORCE_PRE_LOCKED = 6,
	PLL_MODE_FORCE_LOST_PHASE = 7,
	PLL_MODE_DCO = 10,
	PLL_MODE_WPH = 18,
	PLL_MODE_MAX = PLL_MODE_WPH,
};

enum hw_tod_trig_sel {
	HW_TOD_TRIG_SEL_MIN = 0,
	HW_TOD_TRIG_SEL_NO_WRITE = HW_TOD_TRIG_SEL_MIN,
	HW_TOD_TRIG_SEL_NO_READ = HW_TOD_TRIG_SEL_MIN,
	HW_TOD_TRIG_SEL_SYNC_SEL = 1,
	HW_TOD_TRIG_SEL_IN12 = 2,
	HW_TOD_TRIG_SEL_IN13 = 3,
	HW_TOD_TRIG_SEL_IN14 = 4,
	HW_TOD_TRIG_SEL_TOD_PPS = 5,
	HW_TOD_TRIG_SEL_TIMER_INTERVAL = 6,
	HW_TOD_TRIG_SEL_MSB_PHASE_OFFSET_CNFG = 7,
	HW_TOD_TRIG_SEL_MSB_HOLDOVER_FREQ_CNFG = 8,
	HW_TOD_WR_TRIG_SEL_MSB_TOD_CNFG = 9,
	HW_TOD_RD_TRIG_SEL_LSB_TOD_STS = HW_TOD_WR_TRIG_SEL_MSB_TOD_CNFG,
	WR_TRIG_SEL_MAX = HW_TOD_WR_TRIG_SEL_MSB_TOD_CNFG,
};

/** @brief Enumerated type listing DPLL operational modes */
enum dpll_state {
	DPLL_STATE_FREERUN = 1,
	DPLL_STATE_HOLDOVER = 2,
	DPLL_STATE_LOCKED = 4,
	DPLL_STATE_PRELOCKED2 = 5,
	DPLL_STATE_PRELOCKED = 6,
	DPLL_STATE_LOSTPHASE = 7,
	DPLL_STATE_MAX
};

#endif
