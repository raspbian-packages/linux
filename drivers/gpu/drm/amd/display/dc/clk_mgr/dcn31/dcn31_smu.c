/*
 * Copyright 2012-16 Advanced Micro Devices, Inc.
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
 * Authors: AMD
 *
 */

#include <linux/delay.h>
#include "core_types.h"
#include "clk_mgr_internal.h"
#include "reg_helper.h"
#include "dm_helpers.h"
#include "dcn31_smu.h"

#include "yellow_carp_offset.h"
#include "mp/mp_13_0_2_offset.h"
#include "mp/mp_13_0_2_sh_mask.h"

#define REG(reg_name) \
	(MP0_BASE.instance[0].segment[reg ## reg_name ## _BASE_IDX] + reg ## reg_name)

#define FN(reg_name, field) \
	FD(reg_name##__##field)

#define VBIOSSMC_MSG_TestMessage                  0x1
#define VBIOSSMC_MSG_GetSmuVersion                0x2
#define VBIOSSMC_MSG_PowerUpGfx                   0x3
#define VBIOSSMC_MSG_SetDispclkFreq               0x4
#define VBIOSSMC_MSG_SetDprefclkFreq              0x5   //Not used. DPRef is constant
#define VBIOSSMC_MSG_SetDppclkFreq                0x6
#define VBIOSSMC_MSG_SetHardMinDcfclkByFreq       0x7
#define VBIOSSMC_MSG_SetMinDeepSleepDcfclk        0x8
#define VBIOSSMC_MSG_SetPhyclkVoltageByFreq       0x9	//Keep it in case VMIN dees not support phy clk
#define VBIOSSMC_MSG_GetFclkFrequency             0xA
#define VBIOSSMC_MSG_SetDisplayCount              0xB   //Not used anymore
#define VBIOSSMC_MSG_EnableTmdp48MHzRefclkPwrDown 0xC   //Not used anymore
#define VBIOSSMC_MSG_UpdatePmeRestore             0xD
#define VBIOSSMC_MSG_SetVbiosDramAddrHigh         0xE   //Used for WM table txfr
#define VBIOSSMC_MSG_SetVbiosDramAddrLow          0xF
#define VBIOSSMC_MSG_TransferTableSmu2Dram        0x10
#define VBIOSSMC_MSG_TransferTableDram2Smu        0x11
#define VBIOSSMC_MSG_SetDisplayIdleOptimizations  0x12
#define VBIOSSMC_MSG_GetDprefclkFreq              0x13
#define VBIOSSMC_MSG_GetDtbclkFreq                0x14
#define VBIOSSMC_MSG_AllowZstatesEntry            0x15
#define VBIOSSMC_MSG_DisallowZstatesEntry     	  0x16
#define VBIOSSMC_MSG_SetDtbClk                    0x17
#define VBIOSSMC_Message_Count                    0x18

#define VBIOSSMC_Status_BUSY                      0x0
#define VBIOSSMC_Result_OK                        0x1
#define VBIOSSMC_Result_Failed                    0xFF
#define VBIOSSMC_Result_UnknownCmd                0xFE
#define VBIOSSMC_Result_CmdRejectedPrereq         0xFD
#define VBIOSSMC_Result_CmdRejectedBusy           0xFC

/*
 * Function to be used instead of REG_WAIT macro because the wait ends when
 * the register is NOT EQUAL to zero, and because the translation in msg_if.h
 * won't work with REG_WAIT.
 */
static uint32_t dcn31_smu_wait_for_response(struct clk_mgr_internal *clk_mgr, unsigned int delay_us, unsigned int max_retries)
{
	uint32_t res_val = VBIOSSMC_Status_BUSY;

	do {
		res_val = REG_READ(MP1_SMN_C2PMSG_91);
		if (res_val != VBIOSSMC_Status_BUSY)
			break;

		if (delay_us >= 1000)
			msleep(delay_us/1000);
		else if (delay_us > 0)
			udelay(delay_us);
	} while (max_retries--);

	return res_val;
}

int dcn31_smu_send_msg_with_param(
		struct clk_mgr_internal *clk_mgr,
		unsigned int msg_id, unsigned int param)
{
	uint32_t result;

	result = dcn31_smu_wait_for_response(clk_mgr, 10, 200000);
	ASSERT(result == VBIOSSMC_Result_OK);

	if (result == VBIOSSMC_Status_BUSY) {
		return -1;
	}

	/* First clear response register */
	REG_WRITE(MP1_SMN_C2PMSG_91, VBIOSSMC_Status_BUSY);

	/* Set the parameter register for the SMU message, unit is Mhz */
	REG_WRITE(MP1_SMN_C2PMSG_83, param);

	/* Trigger the message transaction by writing the message ID */
	REG_WRITE(MP1_SMN_C2PMSG_67, msg_id);

	result = dcn31_smu_wait_for_response(clk_mgr, 10, 200000);

	if (result == VBIOSSMC_Result_Failed) {
		if (msg_id == VBIOSSMC_MSG_TransferTableDram2Smu &&
		    param == TABLE_WATERMARKS)
			DC_LOG_WARNING("Watermarks table not configured properly by SMU");
		else
			ASSERT(0);
		REG_WRITE(MP1_SMN_C2PMSG_91, VBIOSSMC_Result_OK);
		return -1;
	}

	if (IS_SMU_TIMEOUT(result)) {
		ASSERT(0);
		dm_helpers_smu_timeout(CTX, msg_id, param, 10 * 200000);
	}

	return REG_READ(MP1_SMN_C2PMSG_83);
}

int dcn31_smu_get_smu_version(struct clk_mgr_internal *clk_mgr)
{
	return dcn31_smu_send_msg_with_param(
			clk_mgr,
			VBIOSSMC_MSG_GetSmuVersion,
			0);
}


int dcn31_smu_set_dispclk(struct clk_mgr_internal *clk_mgr, int requested_dispclk_khz)
{
	int actual_dispclk_set_mhz = -1;

	if (!clk_mgr->smu_present)
		return requested_dispclk_khz;

	/*  Unit of SMU msg parameter is Mhz */
	actual_dispclk_set_mhz = dcn31_smu_send_msg_with_param(
			clk_mgr,
			VBIOSSMC_MSG_SetDispclkFreq,
			khz_to_mhz_ceil(requested_dispclk_khz));

	return actual_dispclk_set_mhz * 1000;
}

int dcn31_smu_set_dprefclk(struct clk_mgr_internal *clk_mgr)
{
	int actual_dprefclk_set_mhz = -1;

	if (!clk_mgr->smu_present)
		return clk_mgr->base.dprefclk_khz;

	actual_dprefclk_set_mhz = dcn31_smu_send_msg_with_param(
			clk_mgr,
			VBIOSSMC_MSG_SetDprefclkFreq,
			khz_to_mhz_ceil(clk_mgr->base.dprefclk_khz));

	/* TODO: add code for programing DP DTO, currently this is down by command table */

	return actual_dprefclk_set_mhz * 1000;
}

int dcn31_smu_set_hard_min_dcfclk(struct clk_mgr_internal *clk_mgr, int requested_dcfclk_khz)
{
	int actual_dcfclk_set_mhz = -1;

	if (!clk_mgr->base.ctx->dc->debug.pstate_enabled)
		return -1;

	if (!clk_mgr->smu_present)
		return requested_dcfclk_khz;

	actual_dcfclk_set_mhz = dcn31_smu_send_msg_with_param(
			clk_mgr,
			VBIOSSMC_MSG_SetHardMinDcfclkByFreq,
			khz_to_mhz_ceil(requested_dcfclk_khz));

	return actual_dcfclk_set_mhz * 1000;
}

int dcn31_smu_set_min_deep_sleep_dcfclk(struct clk_mgr_internal *clk_mgr, int requested_min_ds_dcfclk_khz)
{
	int actual_min_ds_dcfclk_mhz = -1;

	if (!clk_mgr->base.ctx->dc->debug.pstate_enabled)
		return -1;

	if (!clk_mgr->smu_present)
		return requested_min_ds_dcfclk_khz;

	actual_min_ds_dcfclk_mhz = dcn31_smu_send_msg_with_param(
			clk_mgr,
			VBIOSSMC_MSG_SetMinDeepSleepDcfclk,
			khz_to_mhz_ceil(requested_min_ds_dcfclk_khz));

	return actual_min_ds_dcfclk_mhz * 1000;
}

int dcn31_smu_set_dppclk(struct clk_mgr_internal *clk_mgr, int requested_dpp_khz)
{
	int actual_dppclk_set_mhz = -1;

	if (!clk_mgr->smu_present)
		return requested_dpp_khz;

	actual_dppclk_set_mhz = dcn31_smu_send_msg_with_param(
			clk_mgr,
			VBIOSSMC_MSG_SetDppclkFreq,
			khz_to_mhz_ceil(requested_dpp_khz));

	return actual_dppclk_set_mhz * 1000;
}

void dcn31_smu_set_display_idle_optimization(struct clk_mgr_internal *clk_mgr, uint32_t idle_info)
{
	if (!clk_mgr->base.ctx->dc->debug.pstate_enabled)
		return;

	if (!clk_mgr->smu_present)
		return;

	//TODO: Work with smu team to define optimization options.
	dcn31_smu_send_msg_with_param(
		clk_mgr,
		VBIOSSMC_MSG_SetDisplayIdleOptimizations,
		idle_info);
}

void dcn31_smu_enable_phy_refclk_pwrdwn(struct clk_mgr_internal *clk_mgr, bool enable)
{
	union display_idle_optimization_u idle_info = { 0 };

	if (!clk_mgr->smu_present)
		return;

	if (enable) {
		idle_info.idle_info.df_request_disabled = 1;
		idle_info.idle_info.phy_ref_clk_off = 1;
	}

	dcn31_smu_send_msg_with_param(
			clk_mgr,
			VBIOSSMC_MSG_SetDisplayIdleOptimizations,
			idle_info.data);
}

void dcn31_smu_enable_pme_wa(struct clk_mgr_internal *clk_mgr)
{
	if (!clk_mgr->smu_present)
		return;

	dcn31_smu_send_msg_with_param(
			clk_mgr,
			VBIOSSMC_MSG_UpdatePmeRestore,
			0);
}

void dcn31_smu_set_dram_addr_high(struct clk_mgr_internal *clk_mgr, uint32_t addr_high)
{
	if (!clk_mgr->smu_present)
		return;

	dcn31_smu_send_msg_with_param(clk_mgr,
			VBIOSSMC_MSG_SetVbiosDramAddrHigh, addr_high);
}

void dcn31_smu_set_dram_addr_low(struct clk_mgr_internal *clk_mgr, uint32_t addr_low)
{
	if (!clk_mgr->smu_present)
		return;

	dcn31_smu_send_msg_with_param(clk_mgr,
			VBIOSSMC_MSG_SetVbiosDramAddrLow, addr_low);
}

void dcn31_smu_transfer_dpm_table_smu_2_dram(struct clk_mgr_internal *clk_mgr)
{
	if (!clk_mgr->smu_present)
		return;

	dcn31_smu_send_msg_with_param(clk_mgr,
			VBIOSSMC_MSG_TransferTableSmu2Dram, TABLE_DPMCLOCKS);
}

void dcn31_smu_transfer_wm_table_dram_2_smu(struct clk_mgr_internal *clk_mgr)
{
	if (!clk_mgr->smu_present)
		return;

	dcn31_smu_send_msg_with_param(clk_mgr,
			VBIOSSMC_MSG_TransferTableDram2Smu, TABLE_WATERMARKS);
}

void dcn31_smu_set_Z9_support(struct clk_mgr_internal *clk_mgr, bool support)
{
	//TODO: Work with smu team to define optimization options.
	unsigned int msg_id;

	if (!clk_mgr->smu_present)
		return;

	if (support)
		msg_id = VBIOSSMC_MSG_AllowZstatesEntry;
	else
		msg_id = VBIOSSMC_MSG_DisallowZstatesEntry;

	dcn31_smu_send_msg_with_param(
		clk_mgr,
		msg_id,
		0);

}

/* Arg = 1: Turn DTB on; 0: Turn DTB CLK OFF. when it is on, it is 600MHZ */
void dcn31_smu_set_dtbclk(struct clk_mgr_internal *clk_mgr, bool enable)
{
	if (!clk_mgr->smu_present)
		return;

	dcn31_smu_send_msg_with_param(
			clk_mgr,
			VBIOSSMC_MSG_SetDtbClk,
			enable);
}
