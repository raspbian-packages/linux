/*
 * Copyright (C) 2012 Russell King
 *  Rewritten from the dovefb driver, and Armada510 manuals.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <drm/drmP.h>
#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_plane_helper.h>
#include "armada_crtc.h"
#include "armada_drm.h"
#include "armada_fb.h"
#include "armada_gem.h"
#include "armada_hw.h"
#include "armada_plane.h"
#include "armada_trace.h"

static const uint32_t armada_primary_formats[] = {
	DRM_FORMAT_UYVY,
	DRM_FORMAT_YUYV,
	DRM_FORMAT_VYUY,
	DRM_FORMAT_YVYU,
	DRM_FORMAT_ARGB8888,
	DRM_FORMAT_ABGR8888,
	DRM_FORMAT_XRGB8888,
	DRM_FORMAT_XBGR8888,
	DRM_FORMAT_RGB888,
	DRM_FORMAT_BGR888,
	DRM_FORMAT_ARGB1555,
	DRM_FORMAT_ABGR1555,
	DRM_FORMAT_RGB565,
	DRM_FORMAT_BGR565,
};

void armada_drm_plane_calc(struct drm_plane_state *state, u32 addrs[2][3],
	u16 pitches[3], bool interlaced)
{
	struct drm_framebuffer *fb = state->fb;
	const struct drm_format_info *format = fb->format;
	unsigned int num_planes = format->num_planes;
	unsigned int x = state->src.x1 >> 16;
	unsigned int y = state->src.y1 >> 16;
	u32 addr = drm_fb_obj(fb)->dev_addr;
	int i;

	DRM_DEBUG_KMS("pitch %u x %d y %d bpp %d\n",
		      fb->pitches[0], x, y, format->cpp[0] * 8);

	if (num_planes > 3)
		num_planes = 3;

	addrs[0][0] = addr + fb->offsets[0] + y * fb->pitches[0] +
		      x * format->cpp[0];
	pitches[0] = fb->pitches[0];

	y /= format->vsub;
	x /= format->hsub;

	for (i = 1; i < num_planes; i++) {
		addrs[0][i] = addr + fb->offsets[i] + y * fb->pitches[i] +
			      x * format->cpp[i];
		pitches[i] = fb->pitches[i];
	}
	for (; i < 3; i++) {
		addrs[0][i] = 0;
		pitches[i] = 0;
	}
	if (interlaced) {
		for (i = 0; i < 3; i++) {
			addrs[1][i] = addrs[0][i] + pitches[i];
			pitches[i] *= 2;
		}
	} else {
		for (i = 0; i < 3; i++)
			addrs[1][i] = addrs[0][i];
	}
}

static unsigned armada_drm_crtc_calc_fb(struct drm_plane_state *state,
	struct armada_regs *regs, bool interlaced)
{
	u16 pitches[3];
	u32 addrs[2][3];
	unsigned i = 0;

	armada_drm_plane_calc(state, addrs, pitches, interlaced);

	/* write offset, base, and pitch */
	armada_reg_queue_set(regs, i, addrs[0][0], LCD_CFG_GRA_START_ADDR0);
	armada_reg_queue_set(regs, i, addrs[1][0], LCD_CFG_GRA_START_ADDR1);
	armada_reg_queue_mod(regs, i, pitches[0], 0xffff, LCD_CFG_GRA_PITCH);

	return i;
}

int armada_drm_plane_prepare_fb(struct drm_plane *plane,
	struct drm_plane_state *state)
{
	DRM_DEBUG_KMS("[PLANE:%d:%s] [FB:%d]\n",
		plane->base.id, plane->name,
		state->fb ? state->fb->base.id : 0);

	/*
	 * Take a reference on the new framebuffer - we want to
	 * hold on to it while the hardware is displaying it.
	 */
	if (state->fb)
		drm_framebuffer_get(state->fb);
	return 0;
}

void armada_drm_plane_cleanup_fb(struct drm_plane *plane,
	struct drm_plane_state *old_state)
{
	DRM_DEBUG_KMS("[PLANE:%d:%s] [FB:%d]\n",
		plane->base.id, plane->name,
		old_state->fb ? old_state->fb->base.id : 0);

	if (old_state->fb)
		drm_framebuffer_put(old_state->fb);
}

int armada_drm_plane_atomic_check(struct drm_plane *plane,
	struct drm_plane_state *state)
{
	if (state->fb && !WARN_ON(!state->crtc)) {
		struct drm_crtc *crtc = state->crtc;
		struct drm_crtc_state *crtc_state;

		if (state->state)
			crtc_state = drm_atomic_get_existing_crtc_state(state->state, crtc);
		else
			crtc_state = crtc->state;
		return drm_atomic_helper_check_plane_state(state, crtc_state,
							   0, INT_MAX,
							   true, false);
	} else {
		state->visible = false;
	}
	return 0;
}

static void armada_drm_primary_plane_atomic_update(struct drm_plane *plane,
	struct drm_plane_state *old_state)
{
	struct drm_plane_state *state = plane->state;
	struct armada_crtc *dcrtc;
	struct armada_regs *regs;
	u32 cfg, cfg_mask, val;
	unsigned int idx;

	DRM_DEBUG_KMS("[PLANE:%d:%s]\n", plane->base.id, plane->name);

	if (!state->fb || WARN_ON(!state->crtc))
		return;

	DRM_DEBUG_KMS("[PLANE:%d:%s] is on [CRTC:%d:%s] with [FB:%d] visible %u->%u\n",
		plane->base.id, plane->name,
		state->crtc->base.id, state->crtc->name,
		state->fb->base.id,
		old_state->visible, state->visible);

	dcrtc = drm_to_armada_crtc(state->crtc);
	regs = dcrtc->regs + dcrtc->regs_idx;

	idx = 0;
	if (!old_state->visible && state->visible) {
		val = CFG_PDWN64x66;
		if (drm_fb_to_armada_fb(state->fb)->fmt > CFG_420)
			val |= CFG_PDWN256x24;
		armada_reg_queue_mod(regs, idx, 0, val, LCD_SPU_SRAM_PARA1);
	}
	val = armada_rect_hw_fp(&state->src);
	if (armada_rect_hw_fp(&old_state->src) != val)
		armada_reg_queue_set(regs, idx, val, LCD_SPU_GRA_HPXL_VLN);
	val = armada_rect_yx(&state->dst);
	if (armada_rect_yx(&old_state->dst) != val)
		armada_reg_queue_set(regs, idx, val, LCD_SPU_GRA_OVSA_HPXL_VLN);
	val = armada_rect_hw(&state->dst);
	if (armada_rect_hw(&old_state->dst) != val)
		armada_reg_queue_set(regs, idx, val, LCD_SPU_GZM_HPXL_VLN);
	if (old_state->src.x1 != state->src.x1 ||
	    old_state->src.y1 != state->src.y1 ||
	    old_state->fb != state->fb ||
	    state->crtc->state->mode_changed) {
		idx += armada_drm_crtc_calc_fb(state, regs + idx,
					       dcrtc->interlaced);
	}
	if (old_state->fb != state->fb ||
	    state->crtc->state->mode_changed) {
		cfg = CFG_GRA_FMT(drm_fb_to_armada_fb(state->fb)->fmt) |
		      CFG_GRA_MOD(drm_fb_to_armada_fb(state->fb)->mod);
		if (drm_fb_to_armada_fb(state->fb)->fmt > CFG_420)
			cfg |= CFG_PALETTE_ENA;
		if (state->visible)
			cfg |= CFG_GRA_ENA;
		if (dcrtc->interlaced)
			cfg |= CFG_GRA_FTOGGLE;
		cfg_mask = CFG_GRAFORMAT |
			   CFG_GRA_MOD(CFG_SWAPRB | CFG_SWAPUV |
				       CFG_SWAPYU | CFG_YUV2RGB) |
			   CFG_PALETTE_ENA | CFG_GRA_FTOGGLE |
			   CFG_GRA_ENA;
	} else if (old_state->visible != state->visible) {
		cfg = state->visible ? CFG_GRA_ENA : 0;
		cfg_mask = CFG_GRA_ENA;
	} else {
		cfg = cfg_mask = 0;
	}
	if (drm_rect_width(&old_state->src) != drm_rect_width(&state->src) ||
	    drm_rect_width(&old_state->dst) != drm_rect_width(&state->dst)) {
		cfg_mask |= CFG_GRA_HSMOOTH;
		if (drm_rect_width(&state->src) >> 16 !=
		    drm_rect_width(&state->dst))
			cfg |= CFG_GRA_HSMOOTH;
	}

	if (cfg_mask)
		armada_reg_queue_mod(regs, idx, cfg, cfg_mask,
				     LCD_SPU_DMA_CTRL0);

	dcrtc->regs_idx += idx;
}

static void armada_drm_primary_plane_atomic_disable(struct drm_plane *plane,
	struct drm_plane_state *old_state)
{
	struct armada_crtc *dcrtc;
	struct armada_regs *regs;
	unsigned int idx = 0;

	DRM_DEBUG_KMS("[PLANE:%d:%s]\n", plane->base.id, plane->name);

	if (!old_state->crtc)
		return;

	DRM_DEBUG_KMS("[PLANE:%d:%s] was on [CRTC:%d:%s] with [FB:%d]\n",
		plane->base.id, plane->name,
		old_state->crtc->base.id, old_state->crtc->name,
		old_state->fb->base.id);

	dcrtc = drm_to_armada_crtc(old_state->crtc);
	regs = dcrtc->regs + dcrtc->regs_idx;

	/* Disable plane and power down most RAMs and FIFOs */
	armada_reg_queue_mod(regs, idx, 0, CFG_GRA_ENA, LCD_SPU_DMA_CTRL0);
	armada_reg_queue_mod(regs, idx, CFG_PDWN256x32 | CFG_PDWN256x24 |
			     CFG_PDWN256x8 | CFG_PDWN32x32 | CFG_PDWN64x66,
			     0, LCD_SPU_SRAM_PARA1);

	dcrtc->regs_idx += idx;
}

static const struct drm_plane_helper_funcs armada_primary_plane_helper_funcs = {
	.prepare_fb	= armada_drm_plane_prepare_fb,
	.cleanup_fb	= armada_drm_plane_cleanup_fb,
	.atomic_check	= armada_drm_plane_atomic_check,
	.atomic_update	= armada_drm_primary_plane_atomic_update,
	.atomic_disable	= armada_drm_primary_plane_atomic_disable,
};

static const struct drm_plane_funcs armada_primary_plane_funcs = {
	.update_plane	= drm_atomic_helper_update_plane,
	.disable_plane	= drm_atomic_helper_disable_plane,
	.destroy	= drm_primary_helper_destroy,
	.reset		= drm_atomic_helper_plane_reset,
	.atomic_duplicate_state = drm_atomic_helper_plane_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_plane_destroy_state,
};

int armada_drm_primary_plane_init(struct drm_device *drm,
	struct drm_plane *primary)
{
	int ret;

	drm_plane_helper_add(primary, &armada_primary_plane_helper_funcs);

	ret = drm_universal_plane_init(drm, primary, 0,
				       &armada_primary_plane_funcs,
				       armada_primary_formats,
				       ARRAY_SIZE(armada_primary_formats),
				       NULL,
				       DRM_PLANE_TYPE_PRIMARY, NULL);

	return ret;
}
