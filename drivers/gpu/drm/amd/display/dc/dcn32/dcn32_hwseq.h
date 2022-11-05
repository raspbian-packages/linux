/*
* Copyright 2016 Advanced Micro Devices, Inc.
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

#ifndef __DC_HWSS_DCN32_H__
#define __DC_HWSS_DCN32_H__

#include "hw_sequencer_private.h"

struct dc;

void dcn32_dsc_pg_control(
		struct dce_hwseq *hws,
		unsigned int dsc_inst,
		bool power_on);

void dcn32_enable_power_gating_plane(
	struct dce_hwseq *hws,
	bool enable);

void dcn32_hubp_pg_control(struct dce_hwseq *hws, unsigned int hubp_inst, bool power_on);

bool dcn32_apply_idle_power_optimizations(struct dc *dc, bool enable);

void dcn32_cab_for_ss_control(struct dc *dc, bool enable);

void dcn32_commit_subvp_config(struct dc *dc, struct dc_state *context);

bool dcn32_set_mcm_luts(struct pipe_ctx *pipe_ctx,
				const struct dc_plane_state *plane_state);

bool dcn32_set_input_transfer_func(struct dc *dc,
				struct pipe_ctx *pipe_ctx,
				const struct dc_plane_state *plane_state);

bool dcn32_set_output_transfer_func(struct dc *dc,
				struct pipe_ctx *pipe_ctx,
				const struct dc_stream_state *stream);

void dcn32_init_hw(struct dc *dc);

void dcn32_program_mall_pipe_config(struct dc *dc, struct dc_state *context);

void dcn32_update_mall_sel(struct dc *dc, struct dc_state *context);

void dcn32_subvp_update_force_pstate(struct dc *dc, struct dc_state *context);

void dcn32_update_odm(struct dc *dc, struct dc_state *context, struct pipe_ctx *pipe_ctx);

unsigned int dcn32_calculate_dccg_k1_k2_values(struct pipe_ctx *pipe_ctx, unsigned int *k1_div, unsigned int *k2_div);

void dcn32_set_pixels_per_cycle(struct pipe_ctx *pipe_ctx);

void dcn32_subvp_pipe_control_lock(struct dc *dc,
		struct dc_state *context,
		bool lock,
		bool should_lock_all_pipes,
		struct pipe_ctx *top_pipe_to_program,
		bool subvp_prev_use);

void dcn32_unblank_stream(struct pipe_ctx *pipe_ctx,
		struct dc_link_settings *link_settings);

bool dcn32_is_dp_dig_pixel_rate_div_policy(struct pipe_ctx *pipe_ctx);

#endif /* __DC_HWSS_DCN32_H__ */
