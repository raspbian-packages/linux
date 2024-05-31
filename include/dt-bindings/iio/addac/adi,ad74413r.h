/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _DT_BINDINGS_ADI_AD74413R_H
#define _DT_BINDINGS_ADI_AD74413R_H

#define CH_FUNC_HIGH_IMPEDANCE			0x0
#define CH_FUNC_VOLTAGE_OUTPUT			0x1
#define CH_FUNC_CURRENT_OUTPUT			0x2
#define CH_FUNC_VOLTAGE_INPUT			0x3
#define CH_FUNC_CURRENT_INPUT_EXT_POWER		0x4
#define CH_FUNC_CURRENT_INPUT_LOOP_POWER	0x5
#define CH_FUNC_RESISTANCE_INPUT		0x6
#define CH_FUNC_DIGITAL_INPUT_LOGIC		0x7
#define CH_FUNC_DIGITAL_INPUT_LOOP_POWER	0x8
#define CH_FUNC_CURRENT_INPUT_EXT_POWER_HART	0x9
#define CH_FUNC_CURRENT_INPUT_LOOP_POWER_HART	0xA

#define CH_FUNC_MIN	CH_FUNC_HIGH_IMPEDANCE
#define CH_FUNC_MAX	CH_FUNC_CURRENT_INPUT_LOOP_POWER_HART

#endif /* _DT_BINDINGS_ADI_AD74413R_H */
