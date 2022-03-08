/* Copyright 2015 Advanced Micro Devices, Inc. */


#include "dm_services.h"
#include "dc.h"
#include "inc/core_types.h"
#include "include/ddc_service_types.h"
#include "include/i2caux_interface.h"
#include "link_hwss.h"
#include "hw_sequencer.h"
#include "dc_link_dp.h"
#include "dc_link_ddc.h"
#include "dm_helpers.h"
#include "dpcd_defs.h"
#include "dsc.h"
#include "resource.h"
#include "link_enc_cfg.h"
#include "clk_mgr.h"
#include "inc/link_dpcd.h"
#include "dccg.h"

static uint8_t convert_to_count(uint8_t lttpr_repeater_count)
{
	switch (lttpr_repeater_count) {
	case 0x80: // 1 lttpr repeater
		return 1;
	case 0x40: // 2 lttpr repeaters
		return 2;
	case 0x20: // 3 lttpr repeaters
		return 3;
	case 0x10: // 4 lttpr repeaters
		return 4;
	case 0x08: // 5 lttpr repeaters
		return 5;
	case 0x04: // 6 lttpr repeaters
		return 6;
	case 0x02: // 7 lttpr repeaters
		return 7;
	case 0x01: // 8 lttpr repeaters
		return 8;
	default:
		break;
	}
	return 0; // invalid value
}

static inline bool is_immediate_downstream(struct dc_link *link, uint32_t offset)
{
	return (convert_to_count(link->dpcd_caps.lttpr_caps.phy_repeater_cnt) == offset);
}

void dp_receiver_power_ctrl(struct dc_link *link, bool on)
{
	uint8_t state;

	state = on ? DP_POWER_STATE_D0 : DP_POWER_STATE_D3;

	if (link->sync_lt_in_progress)
		return;

	core_link_write_dpcd(link, DP_SET_POWER, &state,
			sizeof(state));
}

void dp_source_sequence_trace(struct dc_link *link, uint8_t dp_test_mode)
{
	if (link != NULL && link->dc->debug.enable_driver_sequence_debug)
		core_link_write_dpcd(link, DP_SOURCE_SEQUENCE,
					&dp_test_mode, sizeof(dp_test_mode));
}

void dp_enable_link_phy(
	struct dc_link *link,
	enum signal_type signal,
	enum clock_source_id clock_source,
	const struct dc_link_settings *link_settings)
{
	struct link_encoder *link_enc;
	struct dc  *dc = link->ctx->dc;
	struct dmcu *dmcu = dc->res_pool->dmcu;

	struct pipe_ctx *pipes =
			link->dc->current_state->res_ctx.pipe_ctx;
	struct clock_source *dp_cs =
			link->dc->res_pool->dp_clock_source;
	unsigned int i;

	/* Link should always be assigned encoder when en-/disabling. */
	if (link->is_dig_mapping_flexible && dc->res_pool->funcs->link_encs_assign)
		link_enc = link_enc_cfg_get_link_enc_used_by_link(dc, link);
	else
		link_enc = link->link_enc;
	ASSERT(link_enc);

	if (link->connector_signal == SIGNAL_TYPE_EDP) {
		link->dc->hwss.edp_power_control(link, true);
		link->dc->hwss.edp_wait_for_hpd_ready(link, true);
	}

	/* If the current pixel clock source is not DTO(happens after
	 * switching from HDMI passive dongle to DP on the same connector),
	 * switch the pixel clock source to DTO.
	 */
	for (i = 0; i < MAX_PIPES; i++) {
		if (pipes[i].stream != NULL &&
			pipes[i].stream->link == link) {
			if (pipes[i].clock_source != NULL &&
					pipes[i].clock_source->id != CLOCK_SOURCE_ID_DP_DTO) {
				pipes[i].clock_source = dp_cs;
				pipes[i].stream_res.pix_clk_params.requested_pix_clk_100hz =
						pipes[i].stream->timing.pix_clk_100hz;
				pipes[i].clock_source->funcs->program_pix_clk(
							pipes[i].clock_source,
							&pipes[i].stream_res.pix_clk_params,
							&pipes[i].pll_settings);
			}
		}
	}

	link->cur_link_settings = *link_settings;

#if defined(CONFIG_DRM_AMD_DC_DCN)
	if (dp_get_link_encoding_format(link_settings) == DP_128b_132b_ENCODING) {
		/* TODO - DP2.0 HW: notify link rate change here */
	} else if (dp_get_link_encoding_format(link_settings) == DP_8b_10b_ENCODING) {
		if (dc->clk_mgr->funcs->notify_link_rate_change)
			dc->clk_mgr->funcs->notify_link_rate_change(dc->clk_mgr, link);
	}
#else
	if (dc->clk_mgr->funcs->notify_link_rate_change)
		dc->clk_mgr->funcs->notify_link_rate_change(dc->clk_mgr, link);
#endif
	if (dmcu != NULL && dmcu->funcs->lock_phy)
		dmcu->funcs->lock_phy(dmcu);

#if defined(CONFIG_DRM_AMD_DC_DCN)
	if (dp_get_link_encoding_format(link_settings) == DP_128b_132b_ENCODING) {
		enable_dp_hpo_output(link, link_settings);
	} else if (dp_get_link_encoding_format(link_settings) == DP_8b_10b_ENCODING) {
		if (dc_is_dp_sst_signal(signal)) {
			link_enc->funcs->enable_dp_output(
							link_enc,
							link_settings,
							clock_source);
		} else {
			link_enc->funcs->enable_dp_mst_output(
							link_enc,
							link_settings,
							clock_source);
		}
	}
#else
	if (dc_is_dp_sst_signal(signal)) {
		link_enc->funcs->enable_dp_output(
						link_enc,
						link_settings,
						clock_source);
	} else {
		link_enc->funcs->enable_dp_mst_output(
						link_enc,
						link_settings,
						clock_source);
	}
#endif
	if (dmcu != NULL && dmcu->funcs->unlock_phy)
		dmcu->funcs->unlock_phy(dmcu);

	dp_source_sequence_trace(link, DPCD_SOURCE_SEQ_AFTER_ENABLE_LINK_PHY);
	dp_receiver_power_ctrl(link, true);
}

void edp_add_delay_for_T9(struct dc_link *link)
{
	if (link->local_sink &&
			link->local_sink->edid_caps.panel_patch.extra_delay_backlight_off > 0)
		udelay(link->local_sink->edid_caps.panel_patch.extra_delay_backlight_off * 1000);
}

bool edp_receiver_ready_T9(struct dc_link *link)
{
	unsigned int tries = 0;
	unsigned char sinkstatus = 0;
	unsigned char edpRev = 0;
	enum dc_status result;

	result = core_link_read_dpcd(link, DP_EDP_DPCD_REV, &edpRev, sizeof(edpRev));

    /* start from eDP version 1.2, SINK_STAUS indicate the sink is ready.*/
	if (result == DC_OK && edpRev >= DP_EDP_12) {
		do {
			sinkstatus = 1;
			result = core_link_read_dpcd(link, DP_SINK_STATUS, &sinkstatus, sizeof(sinkstatus));
			if (sinkstatus == 0)
				break;
			if (result != DC_OK)
				break;
			udelay(100); //MAx T9
		} while (++tries < 50);
	}

	return result;
}
bool edp_receiver_ready_T7(struct dc_link *link)
{
	unsigned char sinkstatus = 0;
	unsigned char edpRev = 0;
	enum dc_status result;

	/* use absolute time stamp to constrain max T7*/
	unsigned long long enter_timestamp = 0;
	unsigned long long finish_timestamp = 0;
	unsigned long long time_taken_in_ns = 0;

	result = core_link_read_dpcd(link, DP_EDP_DPCD_REV, &edpRev, sizeof(edpRev));

	if (result == DC_OK && edpRev >= DP_EDP_12) {
		/* start from eDP version 1.2, SINK_STAUS indicate the sink is ready.*/
		enter_timestamp = dm_get_timestamp(link->ctx);
		do {
			sinkstatus = 0;
			result = core_link_read_dpcd(link, DP_SINK_STATUS, &sinkstatus, sizeof(sinkstatus));
			if (sinkstatus == 1)
				break;
			if (result != DC_OK)
				break;
			udelay(25);
			finish_timestamp = dm_get_timestamp(link->ctx);
			time_taken_in_ns = dm_get_elapse_time_in_ns(link->ctx, finish_timestamp, enter_timestamp);
		} while (time_taken_in_ns < 50 * 1000000); //MAx T7 is 50ms
	}

	if (link->local_sink &&
			link->local_sink->edid_caps.panel_patch.extra_t7_ms > 0)
		udelay(link->local_sink->edid_caps.panel_patch.extra_t7_ms * 1000);

	return result;
}

void dp_disable_link_phy(struct dc_link *link, enum signal_type signal)
{
	struct dc  *dc = link->ctx->dc;
	struct dmcu *dmcu = dc->res_pool->dmcu;
#if defined(CONFIG_DRM_AMD_DC_DCN)
	struct hpo_dp_link_encoder *hpo_link_enc = link->hpo_dp_link_enc;
#endif
	struct link_encoder *link_enc;

	/* Link should always be assigned encoder when en-/disabling. */
	if (link->is_dig_mapping_flexible && dc->res_pool->funcs->link_encs_assign)
		link_enc = link_enc_cfg_get_link_enc_used_by_link(dc, link);
	else
		link_enc = link->link_enc;
	ASSERT(link_enc);

	if (!link->wa_flags.dp_keep_receiver_powered)
		dp_receiver_power_ctrl(link, false);

	if (signal == SIGNAL_TYPE_EDP) {
		if (link->dc->hwss.edp_backlight_control)
			link->dc->hwss.edp_backlight_control(link, false);
#if defined(CONFIG_DRM_AMD_DC_DCN)
		if (dp_get_link_encoding_format(&link->cur_link_settings) == DP_128b_132b_ENCODING)
			disable_dp_hpo_output(link, signal);
		else
			link_enc->funcs->disable_output(link_enc, signal);
#else
		link_enc->funcs->disable_output(link_enc, signal);
#endif
		link->dc->hwss.edp_power_control(link, false);
	} else {
		if (dmcu != NULL && dmcu->funcs->lock_phy)
			dmcu->funcs->lock_phy(dmcu);

#if defined(CONFIG_DRM_AMD_DC_DCN)
		if (dp_get_link_encoding_format(&link->cur_link_settings) == DP_128b_132b_ENCODING &&
				hpo_link_enc)
			disable_dp_hpo_output(link, signal);
		else
			link_enc->funcs->disable_output(link_enc, signal);
#else
		link_enc->funcs->disable_output(link_enc, signal);
#endif
		if (dmcu != NULL && dmcu->funcs->unlock_phy)
			dmcu->funcs->unlock_phy(dmcu);
	}

	dp_source_sequence_trace(link, DPCD_SOURCE_SEQ_AFTER_DISABLE_LINK_PHY);

	/* Clear current link setting.*/
	memset(&link->cur_link_settings, 0,
			sizeof(link->cur_link_settings));

	if (dc->clk_mgr->funcs->notify_link_rate_change)
		dc->clk_mgr->funcs->notify_link_rate_change(dc->clk_mgr, link);
}

void dp_disable_link_phy_mst(struct dc_link *link, enum signal_type signal)
{
	/* MST disable link only when no stream use the link */
	if (link->mst_stream_alloc_table.stream_count > 0)
		return;

	dp_disable_link_phy(link, signal);

	/* set the sink to SST mode after disabling the link */
	dp_enable_mst_on_sink(link, false);
}

bool dp_set_hw_training_pattern(
	struct dc_link *link,
	enum dc_dp_training_pattern pattern,
	uint32_t offset)
{
	enum dp_test_pattern test_pattern = DP_TEST_PATTERN_UNSUPPORTED;

	switch (pattern) {
	case DP_TRAINING_PATTERN_SEQUENCE_1:
		test_pattern = DP_TEST_PATTERN_TRAINING_PATTERN1;
		break;
	case DP_TRAINING_PATTERN_SEQUENCE_2:
		test_pattern = DP_TEST_PATTERN_TRAINING_PATTERN2;
		break;
	case DP_TRAINING_PATTERN_SEQUENCE_3:
		test_pattern = DP_TEST_PATTERN_TRAINING_PATTERN3;
		break;
	case DP_TRAINING_PATTERN_SEQUENCE_4:
		test_pattern = DP_TEST_PATTERN_TRAINING_PATTERN4;
		break;
#if defined(CONFIG_DRM_AMD_DC_DCN)
	case DP_128b_132b_TPS1:
		test_pattern = DP_TEST_PATTERN_128b_132b_TPS1_TRAINING_MODE;
		break;
	case DP_128b_132b_TPS2:
		test_pattern = DP_TEST_PATTERN_128b_132b_TPS2_TRAINING_MODE;
		break;
#endif
	default:
		break;
	}

	dp_set_hw_test_pattern(link, test_pattern, NULL, 0);

	return true;
}

#if defined(CONFIG_DRM_AMD_DC_DCN)
#define DC_LOGGER \
	link->ctx->logger
#endif
void dp_set_hw_lane_settings(
	struct dc_link *link,
	const struct link_training_settings *link_settings,
	uint32_t offset)
{
	struct link_encoder *encoder = link->link_enc;

	if ((link->lttpr_mode == LTTPR_MODE_NON_TRANSPARENT) && !is_immediate_downstream(link, offset))
		return;

	/* call Encoder to set lane settings */
#if defined(CONFIG_DRM_AMD_DC_DCN)
	if (dp_get_link_encoding_format(&link_settings->link_settings) ==
			DP_128b_132b_ENCODING) {
		link->hpo_dp_link_enc->funcs->set_ffe(
				link->hpo_dp_link_enc,
				&link_settings->link_settings,
				link_settings->lane_settings[0].FFE_PRESET.raw);
	} else if (dp_get_link_encoding_format(&link_settings->link_settings)
			== DP_8b_10b_ENCODING) {
		encoder->funcs->dp_set_lane_settings(encoder, link_settings);
	}
#else
	encoder->funcs->dp_set_lane_settings(encoder, link_settings);
#endif
	memmove(link->cur_lane_setting,
			link_settings->lane_settings,
			sizeof(link->cur_lane_setting));
}

void dp_set_hw_test_pattern(
	struct dc_link *link,
	enum dp_test_pattern test_pattern,
	uint8_t *custom_pattern,
	uint32_t custom_pattern_size)
{
	struct encoder_set_dp_phy_pattern_param pattern_param = {0};
	struct link_encoder *encoder;
#if defined(CONFIG_DRM_AMD_DC_DCN)
	enum dp_link_encoding link_encoding_format = dp_get_link_encoding_format(&link->cur_link_settings);
#endif

	/* Access link encoder based on whether it is statically
	 * or dynamically assigned to a link.
	 */
	if (link->is_dig_mapping_flexible &&
			link->dc->res_pool->funcs->link_encs_assign)
		encoder = link_enc_cfg_get_link_enc_used_by_link(link->ctx->dc, link);
	else
		encoder = link->link_enc;

	pattern_param.dp_phy_pattern = test_pattern;
	pattern_param.custom_pattern = custom_pattern;
	pattern_param.custom_pattern_size = custom_pattern_size;
	pattern_param.dp_panel_mode = dp_get_panel_mode(link);

#if defined(CONFIG_DRM_AMD_DC_DCN)
	switch (link_encoding_format) {
	case DP_128b_132b_ENCODING:
		link->hpo_dp_link_enc->funcs->set_link_test_pattern(
				link->hpo_dp_link_enc, &pattern_param);
		break;
	case DP_8b_10b_ENCODING:
		ASSERT(encoder);
		encoder->funcs->dp_set_phy_pattern(encoder, &pattern_param);
		break;
	default:
		DC_LOG_ERROR("%s: Unknown link encoding format.", __func__);
		break;
	}
#else
	encoder->funcs->dp_set_phy_pattern(encoder, &pattern_param);
#endif
	dp_source_sequence_trace(link, DPCD_SOURCE_SEQ_AFTER_SET_SOURCE_PATTERN);
}
#if defined(CONFIG_DRM_AMD_DC_DCN)
#undef DC_LOGGER
#endif

void dp_retrain_link_dp_test(struct dc_link *link,
			struct dc_link_settings *link_setting,
			bool skip_video_pattern)
{
	struct pipe_ctx *pipes =
			&link->dc->current_state->res_ctx.pipe_ctx[0];
	unsigned int i;

	for (i = 0; i < MAX_PIPES; i++) {
		if (pipes[i].stream != NULL &&
			!pipes[i].top_pipe && !pipes[i].prev_odm_pipe &&
			pipes[i].stream->link != NULL &&
			pipes[i].stream_res.stream_enc != NULL &&
			pipes[i].stream->link == link) {
			udelay(100);

			pipes[i].stream_res.stream_enc->funcs->dp_blank(link,
					pipes[i].stream_res.stream_enc);

			/* disable any test pattern that might be active */
			dp_set_hw_test_pattern(link,
					DP_TEST_PATTERN_VIDEO_MODE, NULL, 0);

			dp_receiver_power_ctrl(link, false);

			link->dc->hwss.disable_stream(&pipes[i]);
			if ((&pipes[i])->stream_res.audio && !link->dc->debug.az_endpoint_mute_only)
				(&pipes[i])->stream_res.audio->funcs->az_disable((&pipes[i])->stream_res.audio);

			if (link->link_enc)
				link->link_enc->funcs->disable_output(
						link->link_enc,
						SIGNAL_TYPE_DISPLAY_PORT);

			/* Clear current link setting. */
			memset(&link->cur_link_settings, 0,
				sizeof(link->cur_link_settings));

			perform_link_training_with_retries(
					link_setting,
					skip_video_pattern,
					LINK_TRAINING_ATTEMPTS,
					&pipes[i],
					SIGNAL_TYPE_DISPLAY_PORT,
					false);

			link->dc->hwss.enable_stream(&pipes[i]);

			link->dc->hwss.unblank_stream(&pipes[i],
					link_setting);

			if (pipes[i].stream_res.audio) {
				/* notify audio driver for
				 * audio modes of monitor */
				pipes[i].stream_res.audio->funcs->az_enable(
						pipes[i].stream_res.audio);

				/* un-mute audio */
				/* TODO: audio should be per stream rather than
				 * per link */
				pipes[i].stream_res.stream_enc->funcs->
				audio_mute_control(
					pipes[i].stream_res.stream_enc, false);
			}
		}
	}
}

#define DC_LOGGER \
	dsc->ctx->logger
static void dsc_optc_config_log(struct display_stream_compressor *dsc,
		struct dsc_optc_config *config)
{
	uint32_t precision = 1 << 28;
	uint32_t bytes_per_pixel_int = config->bytes_per_pixel / precision;
	uint32_t bytes_per_pixel_mod = config->bytes_per_pixel % precision;
	uint64_t ll_bytes_per_pix_fraq = bytes_per_pixel_mod;

	/* 7 fractional digits decimal precision for bytes per pixel is enough because DSC
	 * bits per pixel precision is 1/16th of a pixel, which means bytes per pixel precision is
	 * 1/16/8 = 1/128 of a byte, or 0.0078125 decimal
	 */
	ll_bytes_per_pix_fraq *= 10000000;
	ll_bytes_per_pix_fraq /= precision;

	DC_LOG_DSC("\tbytes_per_pixel 0x%08x (%d.%07d)",
			config->bytes_per_pixel, bytes_per_pixel_int, (uint32_t)ll_bytes_per_pix_fraq);
	DC_LOG_DSC("\tis_pixel_format_444 %d", config->is_pixel_format_444);
	DC_LOG_DSC("\tslice_width %d", config->slice_width);
}

bool dp_set_dsc_on_rx(struct pipe_ctx *pipe_ctx, bool enable)
{
	struct dc *dc = pipe_ctx->stream->ctx->dc;
	struct dc_stream_state *stream = pipe_ctx->stream;
	bool result = false;

	if (dc_is_virtual_signal(stream->signal) || IS_FPGA_MAXIMUS_DC(dc->ctx->dce_environment))
		result = true;
	else
		result = dm_helpers_dp_write_dsc_enable(dc->ctx, stream, enable);
	return result;
}

/* The stream with these settings can be sent (unblanked) only after DSC was enabled on RX first,
 * i.e. after dp_enable_dsc_on_rx() had been called
 */
void dp_set_dsc_on_stream(struct pipe_ctx *pipe_ctx, bool enable)
{
	struct display_stream_compressor *dsc = pipe_ctx->stream_res.dsc;
	struct dc *dc = pipe_ctx->stream->ctx->dc;
	struct dc_stream_state *stream = pipe_ctx->stream;
	struct pipe_ctx *odm_pipe;
	int opp_cnt = 1;

	for (odm_pipe = pipe_ctx->next_odm_pipe; odm_pipe; odm_pipe = odm_pipe->next_odm_pipe)
		opp_cnt++;

	if (enable) {
		struct dsc_config dsc_cfg;
		struct dsc_optc_config dsc_optc_cfg;
		enum optc_dsc_mode optc_dsc_mode;

		/* Enable DSC hw block */
		dsc_cfg.pic_width = (stream->timing.h_addressable + stream->timing.h_border_left + stream->timing.h_border_right) / opp_cnt;
		dsc_cfg.pic_height = stream->timing.v_addressable + stream->timing.v_border_top + stream->timing.v_border_bottom;
		dsc_cfg.pixel_encoding = stream->timing.pixel_encoding;
		dsc_cfg.color_depth = stream->timing.display_color_depth;
		dsc_cfg.is_odm = pipe_ctx->next_odm_pipe ? true : false;
		dsc_cfg.dc_dsc_cfg = stream->timing.dsc_cfg;
		ASSERT(dsc_cfg.dc_dsc_cfg.num_slices_h % opp_cnt == 0);
		dsc_cfg.dc_dsc_cfg.num_slices_h /= opp_cnt;

		dsc->funcs->dsc_set_config(dsc, &dsc_cfg, &dsc_optc_cfg);
		dsc->funcs->dsc_enable(dsc, pipe_ctx->stream_res.opp->inst);
		for (odm_pipe = pipe_ctx->next_odm_pipe; odm_pipe; odm_pipe = odm_pipe->next_odm_pipe) {
			struct display_stream_compressor *odm_dsc = odm_pipe->stream_res.dsc;

			odm_dsc->funcs->dsc_set_config(odm_dsc, &dsc_cfg, &dsc_optc_cfg);
			odm_dsc->funcs->dsc_enable(odm_dsc, odm_pipe->stream_res.opp->inst);
		}
		dsc_cfg.dc_dsc_cfg.num_slices_h *= opp_cnt;
		dsc_cfg.pic_width *= opp_cnt;

		optc_dsc_mode = dsc_optc_cfg.is_pixel_format_444 ? OPTC_DSC_ENABLED_444 : OPTC_DSC_ENABLED_NATIVE_SUBSAMPLED;

		/* Enable DSC in encoder */
#if defined(CONFIG_DRM_AMD_DC_DCN)
		if (dc_is_dp_signal(stream->signal) && !IS_FPGA_MAXIMUS_DC(dc->ctx->dce_environment)
				&& !is_dp_128b_132b_signal(pipe_ctx)) {
#else
		if (dc_is_dp_signal(stream->signal) && !IS_FPGA_MAXIMUS_DC(dc->ctx->dce_environment)) {
#endif
			DC_LOG_DSC("Setting stream encoder DSC config for engine %d:", (int)pipe_ctx->stream_res.stream_enc->id);
			dsc_optc_config_log(dsc, &dsc_optc_cfg);
			pipe_ctx->stream_res.stream_enc->funcs->dp_set_dsc_config(pipe_ctx->stream_res.stream_enc,
									optc_dsc_mode,
									dsc_optc_cfg.bytes_per_pixel,
									dsc_optc_cfg.slice_width);

			/* PPS SDP is set elsewhere because it has to be done after DIG FE is connected to DIG BE */
		}

		/* Enable DSC in OPTC */
		DC_LOG_DSC("Setting optc DSC config for tg instance %d:", pipe_ctx->stream_res.tg->inst);
		dsc_optc_config_log(dsc, &dsc_optc_cfg);
		pipe_ctx->stream_res.tg->funcs->set_dsc_config(pipe_ctx->stream_res.tg,
							optc_dsc_mode,
							dsc_optc_cfg.bytes_per_pixel,
							dsc_optc_cfg.slice_width);
	} else {
		/* disable DSC in OPTC */
		pipe_ctx->stream_res.tg->funcs->set_dsc_config(
				pipe_ctx->stream_res.tg,
				OPTC_DSC_DISABLED, 0, 0);

		/* disable DSC in stream encoder */
		if (dc_is_dp_signal(stream->signal)) {

#if defined(CONFIG_DRM_AMD_DC_DCN)
			if (is_dp_128b_132b_signal(pipe_ctx))
				pipe_ctx->stream_res.hpo_dp_stream_enc->funcs->dp_set_dsc_pps_info_packet(
										pipe_ctx->stream_res.hpo_dp_stream_enc,
										false,
										NULL,
										true);
			else
#endif
				if (!IS_FPGA_MAXIMUS_DC(dc->ctx->dce_environment)) {
					pipe_ctx->stream_res.stream_enc->funcs->dp_set_dsc_config(
							pipe_ctx->stream_res.stream_enc,
							OPTC_DSC_DISABLED, 0, 0);
					pipe_ctx->stream_res.stream_enc->funcs->dp_set_dsc_pps_info_packet(
								pipe_ctx->stream_res.stream_enc, false, NULL, true);
				}
		}

		/* disable DSC block */
		pipe_ctx->stream_res.dsc->funcs->dsc_disable(pipe_ctx->stream_res.dsc);
		for (odm_pipe = pipe_ctx->next_odm_pipe; odm_pipe; odm_pipe = odm_pipe->next_odm_pipe)
			odm_pipe->stream_res.dsc->funcs->dsc_disable(odm_pipe->stream_res.dsc);
	}
}

bool dp_set_dsc_enable(struct pipe_ctx *pipe_ctx, bool enable)
{
	struct display_stream_compressor *dsc = pipe_ctx->stream_res.dsc;
	bool result = false;

	if (!pipe_ctx->stream->timing.flags.DSC)
		goto out;
	if (!dsc)
		goto out;

	if (enable) {
		{
			dp_set_dsc_on_stream(pipe_ctx, true);
			result = true;
		}
	} else {
		dp_set_dsc_on_rx(pipe_ctx, false);
		dp_set_dsc_on_stream(pipe_ctx, false);
		result = true;
	}
out:
	return result;
}

/*
 * For dynamic bpp change case, dsc is programmed with MASTER_UPDATE_LOCK enabled;
 * hence PPS info packet update need to use frame update instead of immediate update.
 * Added parameter immediate_update for this purpose.
 * The decision to use frame update is hard-coded in function dp_update_dsc_config(),
 * which is the only place where a "false" would be passed in for param immediate_update.
 *
 * immediate_update is only applicable when DSC is enabled.
 */
bool dp_set_dsc_pps_sdp(struct pipe_ctx *pipe_ctx, bool enable, bool immediate_update)
{
	struct display_stream_compressor *dsc = pipe_ctx->stream_res.dsc;
	struct dc_stream_state *stream = pipe_ctx->stream;

	if (!pipe_ctx->stream->timing.flags.DSC || !dsc)
		return false;

	if (enable) {
		struct dsc_config dsc_cfg;
		uint8_t dsc_packed_pps[128];

		memset(&dsc_cfg, 0, sizeof(dsc_cfg));
		memset(dsc_packed_pps, 0, 128);

		/* Enable DSC hw block */
		dsc_cfg.pic_width = stream->timing.h_addressable + stream->timing.h_border_left + stream->timing.h_border_right;
		dsc_cfg.pic_height = stream->timing.v_addressable + stream->timing.v_border_top + stream->timing.v_border_bottom;
		dsc_cfg.pixel_encoding = stream->timing.pixel_encoding;
		dsc_cfg.color_depth = stream->timing.display_color_depth;
		dsc_cfg.is_odm = pipe_ctx->next_odm_pipe ? true : false;
		dsc_cfg.dc_dsc_cfg = stream->timing.dsc_cfg;

		DC_LOG_DSC(" ");
		dsc->funcs->dsc_get_packed_pps(dsc, &dsc_cfg, &dsc_packed_pps[0]);
		if (dc_is_dp_signal(stream->signal)) {
			DC_LOG_DSC("Setting stream encoder DSC PPS SDP for engine %d\n", (int)pipe_ctx->stream_res.stream_enc->id);
#if defined(CONFIG_DRM_AMD_DC_DCN)
			if (is_dp_128b_132b_signal(pipe_ctx))
				pipe_ctx->stream_res.hpo_dp_stream_enc->funcs->dp_set_dsc_pps_info_packet(
										pipe_ctx->stream_res.hpo_dp_stream_enc,
										true,
										&dsc_packed_pps[0],
										immediate_update);
			else
#endif
				pipe_ctx->stream_res.stream_enc->funcs->dp_set_dsc_pps_info_packet(
										pipe_ctx->stream_res.stream_enc,
										true,
										&dsc_packed_pps[0],
										immediate_update);
		}
	} else {
		/* disable DSC PPS in stream encoder */
		if (dc_is_dp_signal(stream->signal)) {
#if defined(CONFIG_DRM_AMD_DC_DCN)
			if (is_dp_128b_132b_signal(pipe_ctx))
				pipe_ctx->stream_res.hpo_dp_stream_enc->funcs->dp_set_dsc_pps_info_packet(
										pipe_ctx->stream_res.hpo_dp_stream_enc,
										false,
										NULL,
										true);
			else
#endif
				pipe_ctx->stream_res.stream_enc->funcs->dp_set_dsc_pps_info_packet(
							pipe_ctx->stream_res.stream_enc, false, NULL, true);
		}
	}

	return true;
}


bool dp_update_dsc_config(struct pipe_ctx *pipe_ctx)
{
	struct display_stream_compressor *dsc = pipe_ctx->stream_res.dsc;

	if (!pipe_ctx->stream->timing.flags.DSC)
		return false;
	if (!dsc)
		return false;

	dp_set_dsc_on_stream(pipe_ctx, true);
	dp_set_dsc_pps_sdp(pipe_ctx, true, false);
	return true;
}

#if defined(CONFIG_DRM_AMD_DC_DCN)
#undef DC_LOGGER
#define DC_LOGGER \
	link->ctx->logger

static enum phyd32clk_clock_source get_phyd32clk_src(struct dc_link *link)
{
	switch (link->link_enc->transmitter) {
	case TRANSMITTER_UNIPHY_A:
		return PHYD32CLKA;
	case TRANSMITTER_UNIPHY_B:
		return PHYD32CLKB;
	case TRANSMITTER_UNIPHY_C:
		return PHYD32CLKC;
	case TRANSMITTER_UNIPHY_D:
		return PHYD32CLKD;
	case TRANSMITTER_UNIPHY_E:
		return PHYD32CLKE;
	default:
		return PHYD32CLKA;
	}
}

void enable_dp_hpo_output(struct dc_link *link, const struct dc_link_settings *link_settings)
{
	const struct dc *dc = link->dc;
	enum phyd32clk_clock_source phyd32clk;

	/* Enable PHY PLL at target bit rate
	 *   UHBR10 = 10Gbps (SYMCLK32 = 312.5MHz)
	 *   UBR13.5 = 13.5Gbps (SYMCLK32 = 421.875MHz)
	 *   UHBR20 = 20Gbps (SYMCLK32 = 625MHz)
	 */
	if (IS_FPGA_MAXIMUS_DC(dc->ctx->dce_environment)) {
		switch (link_settings->link_rate) {
		case LINK_RATE_UHBR10:
			dm_set_phyd32clk(dc->ctx, 312500);
			break;
		case LINK_RATE_UHBR13_5:
			dm_set_phyd32clk(dc->ctx, 412875);
			break;
		case LINK_RATE_UHBR20:
			dm_set_phyd32clk(dc->ctx, 625000);
			break;
		default:
			return;
		}
	} else {
		/* DP2.0 HW: call transmitter control to enable PHY */
		link->hpo_dp_link_enc->funcs->enable_link_phy(
				link->hpo_dp_link_enc,
				link_settings,
				link->link_enc->transmitter);
	}

	/* DCCG muxing and DTBCLK DTO */
	if (IS_FPGA_MAXIMUS_DC(dc->ctx->dce_environment)) {
		dc->res_pool->dccg->funcs->set_physymclk(
				dc->res_pool->dccg,
				link->link_enc_hw_inst,
				PHYSYMCLK_FORCE_SRC_PHYD32CLK,
				true);

		phyd32clk = get_phyd32clk_src(link);
		dc->res_pool->dccg->funcs->enable_symclk32_le(
				dc->res_pool->dccg,
				link->hpo_dp_link_enc->inst,
				phyd32clk);
		link->hpo_dp_link_enc->funcs->link_enable(
					link->hpo_dp_link_enc,
					link_settings->lane_count);
	}
}

void disable_dp_hpo_output(struct dc_link *link, enum signal_type signal)
{
	const struct dc *dc = link->dc;

	link->hpo_dp_link_enc->funcs->link_disable(link->hpo_dp_link_enc);

	if (IS_FPGA_MAXIMUS_DC(dc->ctx->dce_environment)) {
		dc->res_pool->dccg->funcs->disable_symclk32_le(
					dc->res_pool->dccg,
					link->hpo_dp_link_enc->inst);

		dc->res_pool->dccg->funcs->set_physymclk(
					dc->res_pool->dccg,
					link->link_enc_hw_inst,
					PHYSYMCLK_FORCE_SRC_SYMCLK,
					false);

		dm_set_phyd32clk(dc->ctx, 0);
	} else {
		/* DP2.0 HW: call transmitter control to disable PHY */
		link->hpo_dp_link_enc->funcs->disable_link_phy(
				link->hpo_dp_link_enc,
				signal);
	}
}

void setup_dp_hpo_stream(struct pipe_ctx *pipe_ctx, bool enable)
{
	struct dc_stream_state *stream = pipe_ctx->stream;
	struct dc *dc = pipe_ctx->stream->ctx->dc;
	struct pipe_ctx *odm_pipe;
	int odm_combine_num_segments = 1;
	enum phyd32clk_clock_source phyd32clk;

	if (enable) {
		for (odm_pipe = pipe_ctx->next_odm_pipe; odm_pipe; odm_pipe = odm_pipe->next_odm_pipe)
				odm_combine_num_segments++;

		dc->res_pool->dccg->funcs->set_dpstreamclk(
				dc->res_pool->dccg,
				DTBCLK0,
				pipe_ctx->stream_res.tg->inst);

		phyd32clk = get_phyd32clk_src(stream->link);
		dc->res_pool->dccg->funcs->enable_symclk32_se(
				dc->res_pool->dccg,
				pipe_ctx->stream_res.hpo_dp_stream_enc->inst,
				phyd32clk);

		dc->res_pool->dccg->funcs->set_dtbclk_dto(
				dc->res_pool->dccg,
				pipe_ctx->stream_res.tg->inst,
				stream->phy_pix_clk,
				odm_combine_num_segments,
				&stream->timing);
	} else {
		dc->res_pool->dccg->funcs->set_dtbclk_dto(
				dc->res_pool->dccg,
				pipe_ctx->stream_res.tg->inst,
				0,
				0,
				&stream->timing);
		dc->res_pool->dccg->funcs->disable_symclk32_se(
				dc->res_pool->dccg,
				pipe_ctx->stream_res.hpo_dp_stream_enc->inst);
		dc->res_pool->dccg->funcs->set_dpstreamclk(
				dc->res_pool->dccg,
				REFCLK,
				pipe_ctx->stream_res.tg->inst);
	}
}

void reset_dp_hpo_stream_encoders_for_link(struct dc_link *link)
{
	const struct dc *dc = link->dc;
	struct dc_state *state = dc->current_state;
	uint8_t i;

	for (i = 0; i < MAX_PIPES; i++) {
		if (state->res_ctx.pipe_ctx[i].stream_res.hpo_dp_stream_enc &&
				state->res_ctx.pipe_ctx[i].stream &&
				state->res_ctx.pipe_ctx[i].stream->link == link &&
				!state->res_ctx.pipe_ctx[i].stream->dpms_off) {
			setup_dp_hpo_stream(&state->res_ctx.pipe_ctx[i], false);
		}
	}
}

#undef DC_LOGGER
#endif
