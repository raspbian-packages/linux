/*
 * Copyright 2021 Advanced Micro Devices, Inc.
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

#ifndef __DC_MCIF_WB_DCN32_H__
#define __DC_MCIF_WB_DCN32_H__

#include "dcn20/dcn20_mmhubbub.h"
#include "dcn30/dcn30_mmhubbub.h"

#define MCIF_WB_COMMON_REG_LIST_DCN32(inst) \
	SRI2(MCIF_WB_BUFMGR_SW_CONTROL, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUFMGR_STATUS, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_PITCH, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_1_STATUS, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_1_STATUS2, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_2_STATUS, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_2_STATUS2, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_3_STATUS, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_3_STATUS2, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_4_STATUS, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_4_STATUS2, MCIF_WB, inst),\
	SRI2(MCIF_WB_ARBITRATION_CONTROL, MCIF_WB, inst),\
	SRI2(MCIF_WB_SCLK_CHANGE, MCIF_WB, inst),\
	SRI2(MCIF_WB_TEST_DEBUG_INDEX, MCIF_WB, inst),\
	SRI2(MCIF_WB_TEST_DEBUG_DATA, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_1_ADDR_Y, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_1_ADDR_C, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_2_ADDR_Y, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_2_ADDR_C, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_3_ADDR_Y, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_3_ADDR_C, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_4_ADDR_Y, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_4_ADDR_C, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUFMGR_VCE_CONTROL, MCIF_WB, inst),\
	SRI2(MCIF_WB_NB_PSTATE_LATENCY_WATERMARK, MMHUBBUB, inst),\
	SRI2(MCIF_WB_NB_PSTATE_CONTROL, MCIF_WB, inst),\
	SRI2(MCIF_WB_WATERMARK, MMHUBBUB, inst),\
	SRI2(MCIF_WB_CLOCK_GATER_CONTROL, MCIF_WB, inst),\
	SRI2(MCIF_WB_SELF_REFRESH_CONTROL, MCIF_WB, inst),\
	SRI2(MULTI_LEVEL_QOS_CTRL, MCIF_WB, inst),\
	SRI2(MCIF_WB_SECURITY_LEVEL, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_LUMA_SIZE, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_CHROMA_SIZE, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_1_ADDR_Y_HIGH, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_1_ADDR_C_HIGH, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_2_ADDR_Y_HIGH, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_2_ADDR_C_HIGH, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_3_ADDR_Y_HIGH, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_3_ADDR_C_HIGH, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_4_ADDR_Y_HIGH, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_4_ADDR_C_HIGH, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_1_RESOLUTION, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_2_RESOLUTION, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_3_RESOLUTION, MCIF_WB, inst),\
	SRI2(MCIF_WB_BUF_4_RESOLUTION, MCIF_WB, inst),\
	SRI2(MMHUBBUB_MEM_PWR_CNTL, MMHUBBUB, inst),\
	SRI2(MMHUBBUB_WARMUP_ADDR_REGION, MMHUBBUB, inst),\
	SRI2(MMHUBBUB_WARMUP_BASE_ADDR_HIGH, MMHUBBUB, inst),\
	SRI2(MMHUBBUB_WARMUP_BASE_ADDR_LOW, MMHUBBUB, inst),\
	SRI2(MMHUBBUB_WARMUP_CONTROL_STATUS, MMHUBBUB, inst)


#define MCIF_WB_COMMON_MASK_SH_LIST_DCN32(mask_sh) \
	SF(MCIF_WB_BUFMGR_SW_CONTROL, MCIF_WB_BUFMGR_ENABLE, mask_sh),\
	SF(MCIF_WB_BUFMGR_SW_CONTROL, MCIF_WB_BUFMGR_SW_INT_EN, mask_sh),\
	SF(MCIF_WB_BUFMGR_SW_CONTROL, MCIF_WB_BUFMGR_SW_INT_ACK, mask_sh),\
	SF(MCIF_WB_BUFMGR_SW_CONTROL, MCIF_WB_BUFMGR_SW_SLICE_INT_EN, mask_sh),\
	SF(MCIF_WB_BUFMGR_SW_CONTROL, MCIF_WB_BUFMGR_SW_OVERRUN_INT_EN, mask_sh),\
	SF(MCIF_WB_BUFMGR_SW_CONTROL, MCIF_WB_BUFMGR_SW_LOCK, mask_sh),\
	SF(MCIF_WB_BUFMGR_SW_CONTROL, MCIF_WB_BUF_ADDR_FENCE_EN, mask_sh),\
	SF(MCIF_WB_BUFMGR_STATUS, MCIF_WB_BUFMGR_SW_INT_STATUS, mask_sh),\
	SF(MCIF_WB_BUFMGR_STATUS, MCIF_WB_BUFMGR_SW_OVERRUN_INT_STATUS, mask_sh),\
	SF(MCIF_WB_BUFMGR_STATUS, MCIF_WB_BUFMGR_CUR_BUF, mask_sh),\
	SF(MCIF_WB_BUFMGR_STATUS, MCIF_WB_BUFMGR_BUFTAG, mask_sh),\
	SF(MCIF_WB_BUFMGR_STATUS, MCIF_WB_BUFMGR_CUR_LINE_L, mask_sh),\
	SF(MCIF_WB_BUFMGR_STATUS, MCIF_WB_BUFMGR_NEXT_BUF, mask_sh),\
	SF(MCIF_WB_BUF_PITCH, MCIF_WB_BUF_LUMA_PITCH, mask_sh),\
	SF(MCIF_WB_BUF_PITCH, MCIF_WB_BUF_CHROMA_PITCH, mask_sh),\
	SF(MCIF_WB_BUF_1_STATUS, MCIF_WB_BUF_1_ACTIVE, mask_sh),\
	SF(MCIF_WB_BUF_1_STATUS, MCIF_WB_BUF_1_SW_LOCKED, mask_sh),\
	SF(MCIF_WB_BUF_1_STATUS, MCIF_WB_BUF_1_OVERFLOW, mask_sh),\
	SF(MCIF_WB_BUF_1_STATUS, MCIF_WB_BUF_1_DISABLE, mask_sh),\
	SF(MCIF_WB_BUF_1_STATUS, MCIF_WB_BUF_1_MODE, mask_sh),\
	SF(MCIF_WB_BUF_1_STATUS, MCIF_WB_BUF_1_BUFTAG, mask_sh),\
	SF(MCIF_WB_BUF_1_STATUS, MCIF_WB_BUF_1_NXT_BUF, mask_sh),\
	SF(MCIF_WB_BUF_1_STATUS, MCIF_WB_BUF_1_CUR_LINE_L, mask_sh),\
	SF(MCIF_WB_BUF_1_STATUS2, MCIF_WB_BUF_1_NEW_CONTENT, mask_sh),\
	SF(MCIF_WB_BUF_1_STATUS2, MCIF_WB_BUF_1_COLOR_DEPTH, mask_sh),\
	SF(MCIF_WB_BUF_1_STATUS2, MCIF_WB_BUF_1_TMZ_BLACK_PIXEL, mask_sh),\
	SF(MCIF_WB_BUF_1_STATUS2, MCIF_WB_BUF_1_TMZ, mask_sh),\
	SF(MCIF_WB_BUF_1_STATUS2, MCIF_WB_BUF_1_Y_OVERRUN, mask_sh),\
	SF(MCIF_WB_BUF_1_STATUS2, MCIF_WB_BUF_1_C_OVERRUN, mask_sh),\
	SF(MCIF_WB_BUF_2_STATUS, MCIF_WB_BUF_2_ACTIVE, mask_sh),\
	SF(MCIF_WB_BUF_2_STATUS, MCIF_WB_BUF_2_SW_LOCKED, mask_sh),\
	SF(MCIF_WB_BUF_2_STATUS, MCIF_WB_BUF_2_OVERFLOW, mask_sh),\
	SF(MCIF_WB_BUF_2_STATUS, MCIF_WB_BUF_2_DISABLE, mask_sh),\
	SF(MCIF_WB_BUF_2_STATUS, MCIF_WB_BUF_2_MODE, mask_sh),\
	SF(MCIF_WB_BUF_2_STATUS, MCIF_WB_BUF_2_BUFTAG, mask_sh),\
	SF(MCIF_WB_BUF_2_STATUS, MCIF_WB_BUF_2_NXT_BUF, mask_sh),\
	SF(MCIF_WB_BUF_2_STATUS, MCIF_WB_BUF_2_CUR_LINE_L, mask_sh),\
	SF(MCIF_WB_BUF_2_STATUS2, MCIF_WB_BUF_2_NEW_CONTENT, mask_sh),\
	SF(MCIF_WB_BUF_2_STATUS2, MCIF_WB_BUF_2_COLOR_DEPTH, mask_sh),\
	SF(MCIF_WB_BUF_2_STATUS2, MCIF_WB_BUF_2_TMZ_BLACK_PIXEL, mask_sh),\
	SF(MCIF_WB_BUF_2_STATUS2, MCIF_WB_BUF_2_TMZ, mask_sh),\
	SF(MCIF_WB_BUF_2_STATUS2, MCIF_WB_BUF_2_Y_OVERRUN, mask_sh),\
	SF(MCIF_WB_BUF_2_STATUS2, MCIF_WB_BUF_2_C_OVERRUN, mask_sh),\
	SF(MCIF_WB_BUF_3_STATUS, MCIF_WB_BUF_3_ACTIVE, mask_sh),\
	SF(MCIF_WB_BUF_3_STATUS, MCIF_WB_BUF_3_SW_LOCKED, mask_sh),\
	SF(MCIF_WB_BUF_3_STATUS, MCIF_WB_BUF_3_OVERFLOW, mask_sh),\
	SF(MCIF_WB_BUF_3_STATUS, MCIF_WB_BUF_3_DISABLE, mask_sh),\
	SF(MCIF_WB_BUF_3_STATUS, MCIF_WB_BUF_3_MODE, mask_sh),\
	SF(MCIF_WB_BUF_3_STATUS, MCIF_WB_BUF_3_BUFTAG, mask_sh),\
	SF(MCIF_WB_BUF_3_STATUS, MCIF_WB_BUF_3_NXT_BUF, mask_sh),\
	SF(MCIF_WB_BUF_3_STATUS, MCIF_WB_BUF_3_CUR_LINE_L, mask_sh),\
	SF(MCIF_WB_BUF_3_STATUS2, MCIF_WB_BUF_3_NEW_CONTENT, mask_sh),\
	SF(MCIF_WB_BUF_3_STATUS2, MCIF_WB_BUF_3_COLOR_DEPTH, mask_sh),\
	SF(MCIF_WB_BUF_3_STATUS2, MCIF_WB_BUF_3_TMZ_BLACK_PIXEL, mask_sh),\
	SF(MCIF_WB_BUF_3_STATUS2, MCIF_WB_BUF_3_TMZ, mask_sh),\
	SF(MCIF_WB_BUF_3_STATUS2, MCIF_WB_BUF_3_Y_OVERRUN, mask_sh),\
	SF(MCIF_WB_BUF_3_STATUS2, MCIF_WB_BUF_3_C_OVERRUN, mask_sh),\
	SF(MCIF_WB_BUF_4_STATUS, MCIF_WB_BUF_4_ACTIVE, mask_sh),\
	SF(MCIF_WB_BUF_4_STATUS, MCIF_WB_BUF_4_SW_LOCKED, mask_sh),\
	SF(MCIF_WB_BUF_4_STATUS, MCIF_WB_BUF_4_OVERFLOW, mask_sh),\
	SF(MCIF_WB_BUF_4_STATUS, MCIF_WB_BUF_4_DISABLE, mask_sh),\
	SF(MCIF_WB_BUF_4_STATUS, MCIF_WB_BUF_4_MODE, mask_sh),\
	SF(MCIF_WB_BUF_4_STATUS, MCIF_WB_BUF_4_BUFTAG, mask_sh),\
	SF(MCIF_WB_BUF_4_STATUS, MCIF_WB_BUF_4_NXT_BUF, mask_sh),\
	SF(MCIF_WB_BUF_4_STATUS, MCIF_WB_BUF_4_CUR_LINE_L, mask_sh),\
	SF(MCIF_WB_BUF_4_STATUS2, MCIF_WB_BUF_4_NEW_CONTENT, mask_sh),\
	SF(MCIF_WB_BUF_4_STATUS2, MCIF_WB_BUF_4_COLOR_DEPTH, mask_sh),\
	SF(MCIF_WB_BUF_4_STATUS2, MCIF_WB_BUF_4_TMZ_BLACK_PIXEL, mask_sh),\
	SF(MCIF_WB_BUF_4_STATUS2, MCIF_WB_BUF_4_TMZ, mask_sh),\
	SF(MCIF_WB_BUF_4_STATUS2, MCIF_WB_BUF_4_Y_OVERRUN, mask_sh),\
	SF(MCIF_WB_BUF_4_STATUS2, MCIF_WB_BUF_4_C_OVERRUN, mask_sh),\
	SF(MCIF_WB_ARBITRATION_CONTROL, MCIF_WB_CLIENT_ARBITRATION_SLICE, mask_sh),\
	SF(MCIF_WB_ARBITRATION_CONTROL, MCIF_WB_TIME_PER_PIXEL, mask_sh),\
	SF(MCIF_WB_SCLK_CHANGE, WM_CHANGE_ACK_FORCE_ON, mask_sh),\
	SF(MCIF_WB_TEST_DEBUG_INDEX, MCIF_WB_TEST_DEBUG_INDEX, mask_sh),\
	SF(MCIF_WB_TEST_DEBUG_DATA, MCIF_WB_TEST_DEBUG_DATA, mask_sh),\
	SF(MCIF_WB_BUF_1_ADDR_Y, MCIF_WB_BUF_1_ADDR_Y, mask_sh),\
	SF(MCIF_WB_BUF_1_ADDR_C, MCIF_WB_BUF_1_ADDR_C, mask_sh),\
	SF(MCIF_WB_BUF_2_ADDR_Y, MCIF_WB_BUF_2_ADDR_Y, mask_sh),\
	SF(MCIF_WB_BUF_2_ADDR_C, MCIF_WB_BUF_2_ADDR_C, mask_sh),\
	SF(MCIF_WB_BUF_3_ADDR_Y, MCIF_WB_BUF_3_ADDR_Y, mask_sh),\
	SF(MCIF_WB_BUF_3_ADDR_C, MCIF_WB_BUF_3_ADDR_C, mask_sh),\
	SF(MCIF_WB_BUF_4_ADDR_Y, MCIF_WB_BUF_4_ADDR_Y, mask_sh),\
	SF(MCIF_WB_BUF_4_ADDR_C, MCIF_WB_BUF_4_ADDR_C, mask_sh),\
	SF(MCIF_WB_BUFMGR_VCE_CONTROL, MCIF_WB_BUFMGR_SLICE_SIZE, mask_sh),\
	SF(MCIF_WB_NB_PSTATE_LATENCY_WATERMARK, NB_PSTATE_CHANGE_REFRESH_WATERMARK, mask_sh),\
	SF(MCIF_WB_NB_PSTATE_LATENCY_WATERMARK, NB_PSTATE_CHANGE_WATERMARK_MASK, mask_sh),\
	SF(MCIF_WB_NB_PSTATE_CONTROL, NB_PSTATE_CHANGE_FORCE_ON, mask_sh),\
	SF(MCIF_WB_WATERMARK, MCIF_WB_CLI_WATERMARK, mask_sh),\
	SF(MCIF_WB_WATERMARK, MCIF_WB_CLI_WATERMARK_MASK, mask_sh),\
	SF(MCIF_WB_CLOCK_GATER_CONTROL, MCIF_WB_CLI_CLOCK_GATER_OVERRIDE, mask_sh),\
	SF(MCIF_WB_SELF_REFRESH_CONTROL, PERFRAME_SELF_REFRESH, mask_sh),\
	SF(MULTI_LEVEL_QOS_CTRL, MAX_SCALED_TIME_TO_URGENT, mask_sh),\
	SF(MCIF_WB_SECURITY_LEVEL, MCIF_WB_SECURITY_LEVEL, mask_sh),\
	SF(MCIF_WB_BUF_LUMA_SIZE, MCIF_WB_BUF_LUMA_SIZE, mask_sh),\
	SF(MCIF_WB_BUF_CHROMA_SIZE, MCIF_WB_BUF_CHROMA_SIZE, mask_sh),\
	SF(MCIF_WB_BUF_1_ADDR_Y_HIGH, MCIF_WB_BUF_1_ADDR_Y_HIGH, mask_sh),\
	SF(MCIF_WB_BUF_1_ADDR_C_HIGH, MCIF_WB_BUF_1_ADDR_C_HIGH, mask_sh),\
	SF(MCIF_WB_BUF_2_ADDR_Y_HIGH, MCIF_WB_BUF_2_ADDR_Y_HIGH, mask_sh),\
	SF(MCIF_WB_BUF_2_ADDR_C_HIGH, MCIF_WB_BUF_2_ADDR_C_HIGH, mask_sh),\
	SF(MCIF_WB_BUF_3_ADDR_Y_HIGH, MCIF_WB_BUF_3_ADDR_Y_HIGH, mask_sh),\
	SF(MCIF_WB_BUF_3_ADDR_C_HIGH, MCIF_WB_BUF_3_ADDR_C_HIGH, mask_sh),\
	SF(MCIF_WB_BUF_4_ADDR_Y_HIGH, MCIF_WB_BUF_4_ADDR_Y_HIGH, mask_sh),\
	SF(MCIF_WB_BUF_4_ADDR_C_HIGH, MCIF_WB_BUF_4_ADDR_C_HIGH, mask_sh),\
	SF(MCIF_WB_BUF_1_RESOLUTION, MCIF_WB_BUF_1_RESOLUTION_WIDTH, mask_sh),\
	SF(MCIF_WB_BUF_1_RESOLUTION, MCIF_WB_BUF_1_RESOLUTION_HEIGHT, mask_sh),\
	SF(MCIF_WB_BUF_2_RESOLUTION, MCIF_WB_BUF_2_RESOLUTION_WIDTH, mask_sh),\
	SF(MCIF_WB_BUF_2_RESOLUTION, MCIF_WB_BUF_2_RESOLUTION_HEIGHT, mask_sh),\
	SF(MCIF_WB_BUF_3_RESOLUTION, MCIF_WB_BUF_3_RESOLUTION_WIDTH, mask_sh),\
	SF(MCIF_WB_BUF_3_RESOLUTION, MCIF_WB_BUF_3_RESOLUTION_HEIGHT, mask_sh),\
	SF(MCIF_WB_BUF_4_RESOLUTION, MCIF_WB_BUF_4_RESOLUTION_WIDTH, mask_sh),\
	SF(MCIF_WB_BUF_4_RESOLUTION, MCIF_WB_BUF_4_RESOLUTION_HEIGHT, mask_sh),\
	SF(MMHUBBUB_WARMUP_ADDR_REGION, MMHUBBUB_WARMUP_ADDR_REGION, mask_sh),\
	SF(MMHUBBUB_WARMUP_BASE_ADDR_HIGH, MMHUBBUB_WARMUP_BASE_ADDR_HIGH, mask_sh),\
	SF(MMHUBBUB_WARMUP_BASE_ADDR_LOW, MMHUBBUB_WARMUP_BASE_ADDR_LOW, mask_sh),\
	SF(MMHUBBUB_WARMUP_CONTROL_STATUS, MMHUBBUB_WARMUP_EN, mask_sh),\
	SF(MMHUBBUB_WARMUP_CONTROL_STATUS, MMHUBBUB_WARMUP_SW_INT_EN, mask_sh),\
	SF(MMHUBBUB_WARMUP_CONTROL_STATUS, MMHUBBUB_WARMUP_SW_INT_STATUS, mask_sh),\
	SF(MMHUBBUB_WARMUP_CONTROL_STATUS, MMHUBBUB_WARMUP_SW_INT_ACK, mask_sh),\
	SF(MMHUBBUB_WARMUP_CONTROL_STATUS, MMHUBBUB_WARMUP_INC_ADDR, mask_sh)


void dcn32_mmhubbub_construct(struct dcn30_mmhubbub *mcif_wb30,
	struct dc_context *ctx,
	const struct dcn30_mmhubbub_registers *mcif_wb_regs,
	const struct dcn30_mmhubbub_shift *mcif_wb_shift,
	const struct dcn30_mmhubbub_mask *mcif_wb_mask,
	int inst);

#endif //__DC_MCIF_WB_DCN32_H__
