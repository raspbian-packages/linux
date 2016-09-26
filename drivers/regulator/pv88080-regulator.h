/*
 * pv88080-regulator.h - Regulator definitions for PV88080
 * Copyright (C) 2016 Powerventure Semiconductor Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __PV88080_REGISTERS_H__
#define __PV88080_REGISTERS_H__

/* System Control and Event Registers */
#define	PV88080_REG_EVENT_A			0x04
#define	PV88080_REG_MASK_A			0x09
#define	PV88080_REG_MASK_B			0x0a
#define	PV88080_REG_MASK_C			0x0b

/* Regulator Registers */
#define	PV88080_REG_BUCK1_CONF0			0x27
#define	PV88080_REG_BUCK1_CONF1			0x28
#define	PV88080_REG_BUCK1_CONF2			0x59
#define	PV88080_REG_BUCK1_CONF5			0x5c
#define	PV88080_REG_BUCK2_CONF0			0x29
#define	PV88080_REG_BUCK2_CONF1			0x2a
#define	PV88080_REG_BUCK2_CONF2			0x61
#define	PV88080_REG_BUCK2_CONF5			0x64
#define	PV88080_REG_BUCK3_CONF0			0x2b
#define	PV88080_REG_BUCK3_CONF1			0x2c
#define	PV88080_REG_BUCK3_CONF2			0x69
#define	PV88080_REG_BUCK3_CONF5			0x6c

/* PV88080_REG_EVENT_A (addr=0x04) */
#define	PV88080_E_VDD_FLT				0x01
#define	PV88080_E_OVER_TEMP			0x02

/* PV88080_REG_MASK_A (addr=0x09) */
#define	PV88080_M_VDD_FLT				0x01
#define	PV88080_M_OVER_TEMP			0x02

/* PV88080_REG_BUCK1_CONF0 (addr=0x27) */
#define	PV88080_BUCK1_EN				0x80
#define PV88080_VBUCK1_MASK			0x7F
/* PV88080_REG_BUCK2_CONF0 (addr=0x29) */
#define	PV88080_BUCK2_EN				0x80
#define PV88080_VBUCK2_MASK			0x7F
/* PV88080_REG_BUCK3_CONF0 (addr=0x2b) */
#define	PV88080_BUCK3_EN				0x80
#define PV88080_VBUCK3_MASK			0x7F

/* PV88080_REG_BUCK1_CONF1 (addr=0x28) */
#define PV88080_BUCK1_ILIM_SHIFT			2
#define PV88080_BUCK1_ILIM_MASK			0x0C
#define PV88080_BUCK1_MODE_MASK			0x03

/* PV88080_REG_BUCK2_CONF1 (addr=0x2a) */
#define PV88080_BUCK2_ILIM_SHIFT			2
#define PV88080_BUCK2_ILIM_MASK			0x0C
#define PV88080_BUCK2_MODE_MASK			0x03

/* PV88080_REG_BUCK3_CONF1 (addr=0x2c) */
#define PV88080_BUCK3_ILIM_SHIFT			2
#define PV88080_BUCK3_ILIM_MASK			0x0C
#define PV88080_BUCK3_MODE_MASK			0x03

#define	PV88080_BUCK_MODE_SLEEP			0x00
#define	PV88080_BUCK_MODE_AUTO			0x01
#define	PV88080_BUCK_MODE_SYNC			0x02

/* PV88080_REG_BUCK2_CONF2 (addr=0x61) */
/* PV88080_REG_BUCK3_CONF2 (addr=0x69) */
#define PV88080_BUCK_VDAC_RANGE_SHIFT			7
#define PV88080_BUCK_VDAC_RANGE_MASK			0x01

#define PV88080_BUCK_VDAC_RANGE_1			0x00
#define PV88080_BUCK_VDAC_RANGE_2			0x01

/* PV88080_REG_BUCK2_CONF5 (addr=0x64) */
/* PV88080_REG_BUCK3_CONF5 (addr=0x6c) */
#define PV88080_BUCK_VRANGE_GAIN_SHIFT			0
#define PV88080_BUCK_VRANGE_GAIN_MASK			0x01

#define PV88080_BUCK_VRANGE_GAIN_1			0x00
#define PV88080_BUCK_VRANGE_GAIN_2			0x01

#endif	/* __PV88080_REGISTERS_H__ */
