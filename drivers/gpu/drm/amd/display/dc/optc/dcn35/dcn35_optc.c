/* SPDX-License-Identifier: MIT */
/*
 * Copyright 2023 Advanced Micro Devices, Inc.
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

#include "dcn35_optc.h"

#include "dcn30/dcn30_optc.h"
#include "dcn31/dcn31_optc.h"
#include "dcn32/dcn32_optc.h"
#include "reg_helper.h"
#include "dc.h"
#include "dcn_calc_math.h"

#define REG(reg)\
	optc1->tg_regs->reg

#define CTX \
	optc1->base.ctx

#undef FN
#define FN(reg_name, field_name) \
	optc1->tg_shift->field_name, optc1->tg_mask->field_name

/**
 * optc35_set_odm_combine() - Enable CRTC - call ASIC Control Object to enable Timing generator.
 *
 * @optc: Output Pipe Timing Combine instance reference.
 * @opp_id: Output Plane Processor instance ID.
 * @opp_cnt: Output Plane Processor count.
 * @timing: Timing parameters used to configure DCN blocks.
 *
 * Return: void.
 */
static void optc35_set_odm_combine(struct timing_generator *optc, int *opp_id, int opp_cnt,
		struct dc_crtc_timing *timing)
{
	struct optc *optc1 = DCN10TG_FROM_TG(optc);
	uint32_t memory_mask = 0;
	int h_active = timing->h_addressable + timing->h_border_left + timing->h_border_right;
	int mpcc_hactive = h_active / opp_cnt;
	/* Each memory instance is 2048x(314x2) bits to support half line of 4096 */
	int odm_mem_count = (h_active + 2047) / 2048;

	/*
	 * display <= 4k : 2 memories + 2 pipes
	 * 4k < display <= 8k : 4 memories + 2 pipes
	 * 8k < display <= 12k : 6 memories + 4 pipes
	 */
	if (opp_cnt == 4) {
		if (odm_mem_count <= 2)
			memory_mask = 0x3;
		else if (odm_mem_count <= 4)
			memory_mask = 0xf;
		else
			memory_mask = 0x3f;
	} else {
		if (odm_mem_count <= 2)
			memory_mask = 0x1 << (opp_id[0] * 2) | 0x1 << (opp_id[1] * 2);
		else if (odm_mem_count <= 4)
			memory_mask = 0x3 << (opp_id[0] * 2) | 0x3 << (opp_id[1] * 2);
		else
			memory_mask = 0x77;
	}

	REG_SET(OPTC_MEMORY_CONFIG, 0,
		OPTC_MEM_SEL, memory_mask);

	if (opp_cnt == 2) {
		REG_SET_3(OPTC_DATA_SOURCE_SELECT, 0,
				OPTC_NUM_OF_INPUT_SEGMENT, 1,
				OPTC_SEG0_SRC_SEL, opp_id[0],
				OPTC_SEG1_SRC_SEL, opp_id[1]);
	} else if (opp_cnt == 4) {
		REG_SET_5(OPTC_DATA_SOURCE_SELECT, 0,
				OPTC_NUM_OF_INPUT_SEGMENT, 3,
				OPTC_SEG0_SRC_SEL, opp_id[0],
				OPTC_SEG1_SRC_SEL, opp_id[1],
				OPTC_SEG2_SRC_SEL, opp_id[2],
				OPTC_SEG3_SRC_SEL, opp_id[3]);
	}

	REG_UPDATE(OPTC_WIDTH_CONTROL,
			OPTC_SEGMENT_WIDTH, mpcc_hactive);

	REG_UPDATE(OTG_H_TIMING_CNTL, OTG_H_TIMING_DIV_MODE, opp_cnt - 1);
	optc1->opp_count = opp_cnt;
}

static bool optc35_enable_crtc(struct timing_generator *optc)
{
	struct optc *optc1 = DCN10TG_FROM_TG(optc);

	/* opp instance for OTG, 1 to 1 mapping and odm will adjust */
	REG_UPDATE(OPTC_DATA_SOURCE_SELECT,
			OPTC_SEG0_SRC_SEL, optc->inst);

	/* VTG enable first is for HW workaround */
	REG_UPDATE(CONTROL,
			VTG0_ENABLE, 1);

	REG_SEQ_START();

	/* Enable CRTC */
	REG_UPDATE_2(OTG_CONTROL,
			OTG_DISABLE_POINT_CNTL, 2,
			OTG_MASTER_EN, 1);

	REG_SEQ_SUBMIT();
	REG_SEQ_WAIT_DONE();

	return true;
}

/* disable_crtc */
static bool optc35_disable_crtc(struct timing_generator *optc)
{
	struct optc *optc1 = DCN10TG_FROM_TG(optc);

	REG_UPDATE_5(OPTC_DATA_SOURCE_SELECT,
			OPTC_SEG0_SRC_SEL, 0xf,
			OPTC_SEG1_SRC_SEL, 0xf,
			OPTC_SEG2_SRC_SEL, 0xf,
			OPTC_SEG3_SRC_SEL, 0xf,
			OPTC_NUM_OF_INPUT_SEGMENT, 0);

	REG_UPDATE(OPTC_MEMORY_CONFIG,
			OPTC_MEM_SEL, 0);

	/* disable otg request until end of the first line
	 * in the vertical blank region
	 */
	REG_UPDATE(OTG_CONTROL,
			OTG_MASTER_EN, 0);

	REG_UPDATE(CONTROL,
			VTG0_ENABLE, 0);

	/* CRTC disabled, so disable  clock. */
	REG_WAIT(OTG_CLOCK_CONTROL,
			OTG_BUSY, 0,
			1, 100000);
	optc1_clear_optc_underflow(optc);

	return true;
}

static void optc35_phantom_crtc_post_enable(struct timing_generator *optc)
{
	struct optc *optc1 = DCN10TG_FROM_TG(optc);

	/* Disable immediately. */
	REG_UPDATE_2(OTG_CONTROL, OTG_DISABLE_POINT_CNTL, 0, OTG_MASTER_EN, 0);

	/* CRTC disabled, so disable  clock. */
	REG_WAIT(OTG_CLOCK_CONTROL, OTG_BUSY, 0, 1, 100000);
}

static bool optc35_configure_crc(struct timing_generator *optc,
				 const struct crc_params *params)
{
	struct optc *optc1 = DCN10TG_FROM_TG(optc);

	if (!optc1_is_tg_enabled(optc))
		return false;
	REG_WRITE(OTG_CRC_CNTL, 0);
	if (!params->enable)
		return true;
	REG_UPDATE_2(OTG_CRC0_WINDOWA_X_CONTROL,
			OTG_CRC0_WINDOWA_X_START, params->windowa_x_start,
			OTG_CRC0_WINDOWA_X_END, params->windowa_x_end);
	REG_UPDATE_2(OTG_CRC0_WINDOWA_Y_CONTROL,
			OTG_CRC0_WINDOWA_Y_START, params->windowa_y_start,
			OTG_CRC0_WINDOWA_Y_END, params->windowa_y_end);
	REG_UPDATE_2(OTG_CRC0_WINDOWB_X_CONTROL,
			OTG_CRC0_WINDOWB_X_START, params->windowb_x_start,
			OTG_CRC0_WINDOWB_X_END, params->windowb_x_end);
	REG_UPDATE_2(OTG_CRC0_WINDOWB_Y_CONTROL,
			OTG_CRC0_WINDOWB_Y_START, params->windowb_y_start,
			OTG_CRC0_WINDOWB_Y_END, params->windowb_y_end);
	if (optc1->base.ctx->dc->debug.otg_crc_db && optc1->tg_mask->OTG_CRC_WINDOW_DB_EN != 0) {
		REG_UPDATE_4(OTG_CRC_CNTL,
				OTG_CRC_CONT_EN, params->continuous_mode ? 1 : 0,
				OTG_CRC0_SELECT, params->selection,
				OTG_CRC_EN, 1,
				OTG_CRC_WINDOW_DB_EN, 1);
	} else
		REG_UPDATE_3(OTG_CRC_CNTL,
				OTG_CRC_CONT_EN, params->continuous_mode ? 1 : 0,
				OTG_CRC0_SELECT, params->selection,
				OTG_CRC_EN, 1);
	return true;
}

static struct timing_generator_funcs dcn35_tg_funcs = {
		.validate_timing = optc1_validate_timing,
		.program_timing = optc1_program_timing,
		.setup_vertical_interrupt0 = optc1_setup_vertical_interrupt0,
		.setup_vertical_interrupt1 = optc1_setup_vertical_interrupt1,
		.setup_vertical_interrupt2 = optc1_setup_vertical_interrupt2,
		.program_global_sync = optc1_program_global_sync,
		.enable_crtc = optc35_enable_crtc,
		.disable_crtc = optc35_disable_crtc,
		.immediate_disable_crtc = optc31_immediate_disable_crtc,
		.phantom_crtc_post_enable = optc35_phantom_crtc_post_enable,
		/* used by enable_timing_synchronization. Not need for FPGA */
		.is_counter_moving = optc1_is_counter_moving,
		.get_position = optc1_get_position,
		.get_frame_count = optc1_get_vblank_counter,
		.get_scanoutpos = optc1_get_crtc_scanoutpos,
		.get_otg_active_size = optc1_get_otg_active_size,
		.set_early_control = optc1_set_early_control,
		/* used by enable_timing_synchronization. Not need for FPGA */
		.wait_for_state = optc1_wait_for_state,
		.set_blank_color = optc3_program_blank_color,
		.did_triggered_reset_occur = optc1_did_triggered_reset_occur,
		.triplebuffer_lock = optc3_triplebuffer_lock,
		.triplebuffer_unlock = optc2_triplebuffer_unlock,
		.enable_reset_trigger = optc1_enable_reset_trigger,
		.enable_crtc_reset = optc1_enable_crtc_reset,
		.disable_reset_trigger = optc1_disable_reset_trigger,
		.lock = optc3_lock,
		.unlock = optc1_unlock,
		.lock_doublebuffer_enable = optc3_lock_doublebuffer_enable,
		.lock_doublebuffer_disable = optc3_lock_doublebuffer_disable,
		.enable_optc_clock = optc1_enable_optc_clock,
		.set_drr = optc31_set_drr,
		.get_last_used_drr_vtotal = optc2_get_last_used_drr_vtotal,
		.set_vtotal_min_max = optc1_set_vtotal_min_max,
		.set_static_screen_control = optc1_set_static_screen_control,
		.program_stereo = optc1_program_stereo,
		.is_stereo_left_eye = optc1_is_stereo_left_eye,
		.tg_init = optc3_tg_init,
		.is_tg_enabled = optc1_is_tg_enabled,
		.is_optc_underflow_occurred = optc1_is_optc_underflow_occurred,
		.clear_optc_underflow = optc1_clear_optc_underflow,
		.setup_global_swap_lock = NULL,
		.get_crc = optc1_get_crc,
		.configure_crc = optc35_configure_crc,
		.set_dsc_config = optc3_set_dsc_config,
		.get_dsc_status = optc2_get_dsc_status,
		.set_dwb_source = NULL,
		.set_odm_bypass = optc32_set_odm_bypass,
		.set_odm_combine = optc35_set_odm_combine,
		.get_optc_source = optc2_get_optc_source,
		.set_h_timing_div_manual_mode = optc32_set_h_timing_div_manual_mode,
		.set_out_mux = optc3_set_out_mux,
		.set_drr_trigger_window = optc3_set_drr_trigger_window,
		.set_vtotal_change_limit = optc3_set_vtotal_change_limit,
		.set_gsl = optc2_set_gsl,
		.set_gsl_source_select = optc2_set_gsl_source_select,
		.set_vtg_params = optc1_set_vtg_params,
		.program_manual_trigger = optc2_program_manual_trigger,
		.setup_manual_trigger = optc2_setup_manual_trigger,
		.get_hw_timing = optc1_get_hw_timing,
		.init_odm = optc3_init_odm,
};

void dcn35_timing_generator_init(struct optc *optc1)
{
	optc1->base.funcs = &dcn35_tg_funcs;

	optc1->max_h_total = optc1->tg_mask->OTG_H_TOTAL + 1;
	optc1->max_v_total = optc1->tg_mask->OTG_V_TOTAL + 1;

	optc1->min_h_blank = 32;
	optc1->min_v_blank = 3;
	optc1->min_v_blank_interlace = 5;
	optc1->min_h_sync_width = 4;
	optc1->min_v_sync_width = 1;

	dcn35_timing_generator_set_fgcg(
		optc1, CTX->dc->debug.enable_fine_grain_clock_gating.bits.optc);
}

void dcn35_timing_generator_set_fgcg(struct optc *optc1, bool enable)
{
	REG_UPDATE(OPTC_CLOCK_CONTROL, OPTC_FGCG_REP_DIS, !enable);
}
