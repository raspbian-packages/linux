/*
 * Copyright 2015 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef _TONGA_CLOCK_POWER_GATING_H_
#define _TONGA_CLOCK_POWER_GATING_H_

#include "tonga_hwmgr.h"
#include "pp_asicblocks.h"

extern int tonga_phm_set_asic_block_gating(struct pp_hwmgr *hwmgr, enum PHM_AsicBlock block, enum PHM_ClockGateSetting gating);
extern int tonga_phm_powergate_vce(struct pp_hwmgr *hwmgr, bool bgate);
extern int tonga_phm_powergate_uvd(struct pp_hwmgr *hwmgr, bool bgate);
extern int tonga_phm_powerdown_uvd(struct pp_hwmgr *hwmgr);
extern int tonga_phm_disable_clock_power_gating(struct pp_hwmgr *hwmgr);
extern int tonga_phm_update_clock_gatings(struct pp_hwmgr *hwmgr, const uint32_t *msg_id);
#endif /* _TONGA_CLOCK_POWER_GATING_H_ */
