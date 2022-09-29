// SPDX-License-Identifier: GPL-2.0 OR MIT
/**************************************************************************
 *
 * Copyright 2009-2015 VMware, Inc., Palo Alto, CA., USA
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sub license, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS, AUTHORS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 **************************************************************************/

#include "vmwgfx_kms.h"
#include <drm/drm_plane_helper.h>
#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_rect.h>

/* Might need a hrtimer here? */
#define VMWGFX_PRESENT_RATE ((HZ / 60 > 0) ? HZ / 60 : 1)

void vmw_du_cleanup(struct vmw_display_unit *du)
{
	drm_plane_cleanup(&du->primary);
	drm_plane_cleanup(&du->cursor);

	drm_connector_unregister(&du->connector);
	drm_crtc_cleanup(&du->crtc);
	drm_encoder_cleanup(&du->encoder);
	drm_connector_cleanup(&du->connector);
}

/*
 * Display Unit Cursor functions
 */

static int vmw_cursor_update_image(struct vmw_private *dev_priv,
				   u32 *image, u32 width, u32 height,
				   u32 hotspotX, u32 hotspotY)
{
	struct {
		u32 cmd;
		SVGAFifoCmdDefineAlphaCursor cursor;
	} *cmd;
	u32 image_size = width * height * 4;
	u32 cmd_size = sizeof(*cmd) + image_size;

	if (!image)
		return -EINVAL;

	cmd = vmw_fifo_reserve(dev_priv, cmd_size);
	if (unlikely(cmd == NULL)) {
		DRM_ERROR("Fifo reserve failed.\n");
		return -ENOMEM;
	}

	memset(cmd, 0, sizeof(*cmd));

	memcpy(&cmd[1], image, image_size);

	cmd->cmd = SVGA_CMD_DEFINE_ALPHA_CURSOR;
	cmd->cursor.id = 0;
	cmd->cursor.width = width;
	cmd->cursor.height = height;
	cmd->cursor.hotspotX = hotspotX;
	cmd->cursor.hotspotY = hotspotY;

	vmw_fifo_commit_flush(dev_priv, cmd_size);

	return 0;
}

static int vmw_cursor_update_bo(struct vmw_private *dev_priv,
				struct vmw_buffer_object *bo,
				u32 width, u32 height,
				u32 hotspotX, u32 hotspotY)
{
	struct ttm_bo_kmap_obj map;
	unsigned long kmap_offset;
	unsigned long kmap_num;
	void *virtual;
	bool dummy;
	int ret;

	kmap_offset = 0;
	kmap_num = (width*height*4 + PAGE_SIZE - 1) >> PAGE_SHIFT;

	ret = ttm_bo_reserve(&bo->base, true, false, NULL);
	if (unlikely(ret != 0)) {
		DRM_ERROR("reserve failed\n");
		return -EINVAL;
	}

	ret = ttm_bo_kmap(&bo->base, kmap_offset, kmap_num, &map);
	if (unlikely(ret != 0))
		goto err_unreserve;

	virtual = ttm_kmap_obj_virtual(&map, &dummy);
	ret = vmw_cursor_update_image(dev_priv, virtual, width, height,
				      hotspotX, hotspotY);

	ttm_bo_kunmap(&map);
err_unreserve:
	ttm_bo_unreserve(&bo->base);

	return ret;
}


static void vmw_cursor_update_position(struct vmw_private *dev_priv,
				       bool show, int x, int y)
{
	u32 *fifo_mem = dev_priv->mmio_virt;
	uint32_t count;

	spin_lock(&dev_priv->cursor_lock);
	vmw_mmio_write(show ? 1 : 0, fifo_mem + SVGA_FIFO_CURSOR_ON);
	vmw_mmio_write(x, fifo_mem + SVGA_FIFO_CURSOR_X);
	vmw_mmio_write(y, fifo_mem + SVGA_FIFO_CURSOR_Y);
	count = vmw_mmio_read(fifo_mem + SVGA_FIFO_CURSOR_COUNT);
	vmw_mmio_write(++count, fifo_mem + SVGA_FIFO_CURSOR_COUNT);
	spin_unlock(&dev_priv->cursor_lock);
}


void vmw_kms_cursor_snoop(struct vmw_surface *srf,
			  struct ttm_object_file *tfile,
			  struct ttm_buffer_object *bo,
			  SVGA3dCmdHeader *header)
{
	struct ttm_bo_kmap_obj map;
	unsigned long kmap_offset;
	unsigned long kmap_num;
	SVGA3dCopyBox *box;
	unsigned box_count;
	void *virtual;
	bool dummy;
	struct vmw_dma_cmd {
		SVGA3dCmdHeader header;
		SVGA3dCmdSurfaceDMA dma;
	} *cmd;
	int i, ret;

	cmd = container_of(header, struct vmw_dma_cmd, header);

	/* No snooper installed */
	if (!srf->snooper.image)
		return;

	if (cmd->dma.host.face != 0 || cmd->dma.host.mipmap != 0) {
		DRM_ERROR("face and mipmap for cursors should never != 0\n");
		return;
	}

	if (cmd->header.size < 64) {
		DRM_ERROR("at least one full copy box must be given\n");
		return;
	}

	box = (SVGA3dCopyBox *)&cmd[1];
	box_count = (cmd->header.size - sizeof(SVGA3dCmdSurfaceDMA)) /
			sizeof(SVGA3dCopyBox);

	if (cmd->dma.guest.ptr.offset % PAGE_SIZE ||
	    box->x != 0    || box->y != 0    || box->z != 0    ||
	    box->srcx != 0 || box->srcy != 0 || box->srcz != 0 ||
	    box->d != 1    || box_count != 1) {
		/* TODO handle none page aligned offsets */
		/* TODO handle more dst & src != 0 */
		/* TODO handle more then one copy */
		DRM_ERROR("Cant snoop dma request for cursor!\n");
		DRM_ERROR("(%u, %u, %u) (%u, %u, %u) (%ux%ux%u) %u %u\n",
			  box->srcx, box->srcy, box->srcz,
			  box->x, box->y, box->z,
			  box->w, box->h, box->d, box_count,
			  cmd->dma.guest.ptr.offset);
		return;
	}

	kmap_offset = cmd->dma.guest.ptr.offset >> PAGE_SHIFT;
	kmap_num = (64*64*4) >> PAGE_SHIFT;

	ret = ttm_bo_reserve(bo, true, false, NULL);
	if (unlikely(ret != 0)) {
		DRM_ERROR("reserve failed\n");
		return;
	}

	ret = ttm_bo_kmap(bo, kmap_offset, kmap_num, &map);
	if (unlikely(ret != 0))
		goto err_unreserve;

	virtual = ttm_kmap_obj_virtual(&map, &dummy);

	if (box->w == 64 && cmd->dma.guest.pitch == 64*4) {
		memcpy(srf->snooper.image, virtual, 64*64*4);
	} else {
		/* Image is unsigned pointer. */
		for (i = 0; i < box->h; i++)
			memcpy(srf->snooper.image + i * 64,
			       virtual + i * cmd->dma.guest.pitch,
			       box->w * 4);
	}

	srf->snooper.age++;

	ttm_bo_kunmap(&map);
err_unreserve:
	ttm_bo_unreserve(bo);
}

/**
 * vmw_kms_legacy_hotspot_clear - Clear legacy hotspots
 *
 * @dev_priv: Pointer to the device private struct.
 *
 * Clears all legacy hotspots.
 */
void vmw_kms_legacy_hotspot_clear(struct vmw_private *dev_priv)
{
	struct drm_device *dev = dev_priv->dev;
	struct vmw_display_unit *du;
	struct drm_crtc *crtc;

	drm_modeset_lock_all(dev);
	drm_for_each_crtc(crtc, dev) {
		du = vmw_crtc_to_du(crtc);

		du->hotspot_x = 0;
		du->hotspot_y = 0;
	}
	drm_modeset_unlock_all(dev);
}

void vmw_kms_cursor_post_execbuf(struct vmw_private *dev_priv)
{
	struct drm_device *dev = dev_priv->dev;
	struct vmw_display_unit *du;
	struct drm_crtc *crtc;

	mutex_lock(&dev->mode_config.mutex);

	list_for_each_entry(crtc, &dev->mode_config.crtc_list, head) {
		du = vmw_crtc_to_du(crtc);
		if (!du->cursor_surface ||
		    du->cursor_age == du->cursor_surface->snooper.age)
			continue;

		du->cursor_age = du->cursor_surface->snooper.age;
		vmw_cursor_update_image(dev_priv,
					du->cursor_surface->snooper.image,
					64, 64,
					du->hotspot_x + du->core_hotspot_x,
					du->hotspot_y + du->core_hotspot_y);
	}

	mutex_unlock(&dev->mode_config.mutex);
}


void vmw_du_cursor_plane_destroy(struct drm_plane *plane)
{
	vmw_cursor_update_position(plane->dev->dev_private, false, 0, 0);

	drm_plane_cleanup(plane);
}


void vmw_du_primary_plane_destroy(struct drm_plane *plane)
{
	drm_plane_cleanup(plane);

	/* Planes are static in our case so we don't free it */
}


/**
 * vmw_du_vps_unpin_surf - unpins resource associated with a framebuffer surface
 *
 * @vps: plane state associated with the display surface
 * @unreference: true if we also want to unreference the display.
 */
void vmw_du_plane_unpin_surf(struct vmw_plane_state *vps,
			     bool unreference)
{
	if (vps->surf) {
		if (vps->pinned) {
			vmw_resource_unpin(&vps->surf->res);
			vps->pinned--;
		}

		if (unreference) {
			if (vps->pinned)
				DRM_ERROR("Surface still pinned\n");
			vmw_surface_unreference(&vps->surf);
		}
	}
}


/**
 * vmw_du_plane_cleanup_fb - Unpins the cursor
 *
 * @plane:  display plane
 * @old_state: Contains the FB to clean up
 *
 * Unpins the framebuffer surface
 *
 * Returns 0 on success
 */
void
vmw_du_plane_cleanup_fb(struct drm_plane *plane,
			struct drm_plane_state *old_state)
{
	struct vmw_plane_state *vps = vmw_plane_state_to_vps(old_state);

	vmw_du_plane_unpin_surf(vps, false);
}


/**
 * vmw_du_cursor_plane_prepare_fb - Readies the cursor by referencing it
 *
 * @plane:  display plane
 * @new_state: info on the new plane state, including the FB
 *
 * Returns 0 on success
 */
int
vmw_du_cursor_plane_prepare_fb(struct drm_plane *plane,
			       struct drm_plane_state *new_state)
{
	struct drm_framebuffer *fb = new_state->fb;
	struct vmw_plane_state *vps = vmw_plane_state_to_vps(new_state);


	if (vps->surf)
		vmw_surface_unreference(&vps->surf);

	if (vps->bo)
		vmw_bo_unreference(&vps->bo);

	if (fb) {
		if (vmw_framebuffer_to_vfb(fb)->bo) {
			vps->bo = vmw_framebuffer_to_vfbd(fb)->buffer;
			vmw_bo_reference(vps->bo);
		} else {
			vps->surf = vmw_framebuffer_to_vfbs(fb)->surface;
			vmw_surface_reference(vps->surf);
		}
	}

	return 0;
}


void
vmw_du_cursor_plane_atomic_update(struct drm_plane *plane,
				  struct drm_plane_state *old_state)
{
	struct drm_crtc *crtc = plane->state->crtc ?: old_state->crtc;
	struct vmw_private *dev_priv = vmw_priv(crtc->dev);
	struct vmw_display_unit *du = vmw_crtc_to_du(crtc);
	struct vmw_plane_state *vps = vmw_plane_state_to_vps(plane->state);
	s32 hotspot_x, hotspot_y;
	int ret = 0;


	hotspot_x = du->hotspot_x;
	hotspot_y = du->hotspot_y;

	if (plane->state->fb) {
		hotspot_x += plane->state->fb->hot_x;
		hotspot_y += plane->state->fb->hot_y;
	}

	du->cursor_surface = vps->surf;
	du->cursor_bo = vps->bo;

	if (vps->surf) {
		du->cursor_age = du->cursor_surface->snooper.age;

		ret = vmw_cursor_update_image(dev_priv,
					      vps->surf->snooper.image,
					      64, 64, hotspot_x,
					      hotspot_y);
	} else if (vps->bo) {
		ret = vmw_cursor_update_bo(dev_priv, vps->bo,
					   plane->state->crtc_w,
					   plane->state->crtc_h,
					   hotspot_x, hotspot_y);
	} else {
		vmw_cursor_update_position(dev_priv, false, 0, 0);
		return;
	}

	if (!ret) {
		du->cursor_x = plane->state->crtc_x + du->set_gui_x;
		du->cursor_y = plane->state->crtc_y + du->set_gui_y;

		vmw_cursor_update_position(dev_priv, true,
					   du->cursor_x + hotspot_x,
					   du->cursor_y + hotspot_y);

		du->core_hotspot_x = hotspot_x - du->hotspot_x;
		du->core_hotspot_y = hotspot_y - du->hotspot_y;
	} else {
		DRM_ERROR("Failed to update cursor image\n");
	}
}


/**
 * vmw_du_primary_plane_atomic_check - check if the new state is okay
 *
 * @plane: display plane
 * @state: info on the new plane state, including the FB
 *
 * Check if the new state is settable given the current state.  Other
 * than what the atomic helper checks, we care about crtc fitting
 * the FB and maintaining one active framebuffer.
 *
 * Returns 0 on success
 */
int vmw_du_primary_plane_atomic_check(struct drm_plane *plane,
				      struct drm_plane_state *state)
{
	struct drm_crtc_state *crtc_state = NULL;
	struct drm_framebuffer *new_fb = state->fb;
	int ret;

	if (state->crtc)
		crtc_state = drm_atomic_get_new_crtc_state(state->state, state->crtc);

	ret = drm_atomic_helper_check_plane_state(state, crtc_state,
						  DRM_PLANE_HELPER_NO_SCALING,
						  DRM_PLANE_HELPER_NO_SCALING,
						  false, true);

	if (!ret && new_fb) {
		struct drm_crtc *crtc = state->crtc;
		struct vmw_connector_state *vcs;
		struct vmw_display_unit *du = vmw_crtc_to_du(crtc);
		struct vmw_private *dev_priv = vmw_priv(crtc->dev);
		struct vmw_framebuffer *vfb = vmw_framebuffer_to_vfb(new_fb);

		vcs = vmw_connector_state_to_vcs(du->connector.state);

		/* Only one active implicit framebuffer at a time. */
		mutex_lock(&dev_priv->global_kms_state_mutex);
		if (vcs->is_implicit && dev_priv->implicit_fb &&
		    !(dev_priv->num_implicit == 1 && du->active_implicit)
		    && dev_priv->implicit_fb != vfb) {
			DRM_ERROR("Multiple implicit framebuffers "
				  "not supported.\n");
			ret = -EINVAL;
		}
		mutex_unlock(&dev_priv->global_kms_state_mutex);
	}


	return ret;
}


/**
 * vmw_du_cursor_plane_atomic_check - check if the new state is okay
 *
 * @plane: cursor plane
 * @state: info on the new plane state
 *
 * This is a chance to fail if the new cursor state does not fit
 * our requirements.
 *
 * Returns 0 on success
 */
int vmw_du_cursor_plane_atomic_check(struct drm_plane *plane,
				     struct drm_plane_state *new_state)
{
	int ret = 0;
	struct vmw_surface *surface = NULL;
	struct drm_framebuffer *fb = new_state->fb;

	struct drm_rect src = drm_plane_state_src(new_state);
	struct drm_rect dest = drm_plane_state_dest(new_state);

	/* Turning off */
	if (!fb)
		return ret;

	ret = drm_plane_helper_check_update(plane, new_state->crtc, fb,
					    &src, &dest,
					    DRM_MODE_ROTATE_0,
					    DRM_PLANE_HELPER_NO_SCALING,
					    DRM_PLANE_HELPER_NO_SCALING,
					    true, true, &new_state->visible);
	if (!ret)
		return ret;

	/* A lot of the code assumes this */
	if (new_state->crtc_w != 64 || new_state->crtc_h != 64) {
		DRM_ERROR("Invalid cursor dimensions (%d, %d)\n",
			  new_state->crtc_w, new_state->crtc_h);
		ret = -EINVAL;
	}

	if (!vmw_framebuffer_to_vfb(fb)->bo)
		surface = vmw_framebuffer_to_vfbs(fb)->surface;

	if (surface && !surface->snooper.image) {
		DRM_ERROR("surface not suitable for cursor\n");
		ret = -EINVAL;
	}

	return ret;
}


int vmw_du_crtc_atomic_check(struct drm_crtc *crtc,
			     struct drm_crtc_state *new_state)
{
	struct vmw_display_unit *du = vmw_crtc_to_du(new_state->crtc);
	int connector_mask = drm_connector_mask(&du->connector);
	bool has_primary = new_state->plane_mask &
			   drm_plane_mask(crtc->primary);

	/* We always want to have an active plane with an active CRTC */
	if (has_primary != new_state->enable)
		return -EINVAL;


	if (new_state->connector_mask != connector_mask &&
	    new_state->connector_mask != 0) {
		DRM_ERROR("Invalid connectors configuration\n");
		return -EINVAL;
	}

	/*
	 * Our virtual device does not have a dot clock, so use the logical
	 * clock value as the dot clock.
	 */
	if (new_state->mode.crtc_clock == 0)
		new_state->adjusted_mode.crtc_clock = new_state->mode.clock;

	return 0;
}


void vmw_du_crtc_atomic_begin(struct drm_crtc *crtc,
			      struct drm_crtc_state *old_crtc_state)
{
}


void vmw_du_crtc_atomic_flush(struct drm_crtc *crtc,
			      struct drm_crtc_state *old_crtc_state)
{
	struct drm_pending_vblank_event *event = crtc->state->event;

	if (event) {
		crtc->state->event = NULL;

		spin_lock_irq(&crtc->dev->event_lock);
		drm_crtc_send_vblank_event(crtc, event);
		spin_unlock_irq(&crtc->dev->event_lock);
	}
}


/**
 * vmw_du_crtc_duplicate_state - duplicate crtc state
 * @crtc: DRM crtc
 *
 * Allocates and returns a copy of the crtc state (both common and
 * vmw-specific) for the specified crtc.
 *
 * Returns: The newly allocated crtc state, or NULL on failure.
 */
struct drm_crtc_state *
vmw_du_crtc_duplicate_state(struct drm_crtc *crtc)
{
	struct drm_crtc_state *state;
	struct vmw_crtc_state *vcs;

	if (WARN_ON(!crtc->state))
		return NULL;

	vcs = kmemdup(crtc->state, sizeof(*vcs), GFP_KERNEL);

	if (!vcs)
		return NULL;

	state = &vcs->base;

	__drm_atomic_helper_crtc_duplicate_state(crtc, state);

	return state;
}


/**
 * vmw_du_crtc_reset - creates a blank vmw crtc state
 * @crtc: DRM crtc
 *
 * Resets the atomic state for @crtc by freeing the state pointer (which
 * might be NULL, e.g. at driver load time) and allocating a new empty state
 * object.
 */
void vmw_du_crtc_reset(struct drm_crtc *crtc)
{
	struct vmw_crtc_state *vcs;


	if (crtc->state) {
		__drm_atomic_helper_crtc_destroy_state(crtc->state);

		kfree(vmw_crtc_state_to_vcs(crtc->state));
	}

	vcs = kzalloc(sizeof(*vcs), GFP_KERNEL);

	if (!vcs) {
		DRM_ERROR("Cannot allocate vmw_crtc_state\n");
		return;
	}

	crtc->state = &vcs->base;
	crtc->state->crtc = crtc;
}


/**
 * vmw_du_crtc_destroy_state - destroy crtc state
 * @crtc: DRM crtc
 * @state: state object to destroy
 *
 * Destroys the crtc state (both common and vmw-specific) for the
 * specified plane.
 */
void
vmw_du_crtc_destroy_state(struct drm_crtc *crtc,
			  struct drm_crtc_state *state)
{
	drm_atomic_helper_crtc_destroy_state(crtc, state);
}


/**
 * vmw_du_plane_duplicate_state - duplicate plane state
 * @plane: drm plane
 *
 * Allocates and returns a copy of the plane state (both common and
 * vmw-specific) for the specified plane.
 *
 * Returns: The newly allocated plane state, or NULL on failure.
 */
struct drm_plane_state *
vmw_du_plane_duplicate_state(struct drm_plane *plane)
{
	struct drm_plane_state *state;
	struct vmw_plane_state *vps;

	vps = kmemdup(plane->state, sizeof(*vps), GFP_KERNEL);

	if (!vps)
		return NULL;

	vps->pinned = 0;
	vps->cpp = 0;

	/* Each ref counted resource needs to be acquired again */
	if (vps->surf)
		(void) vmw_surface_reference(vps->surf);

	if (vps->bo)
		(void) vmw_bo_reference(vps->bo);

	state = &vps->base;

	__drm_atomic_helper_plane_duplicate_state(plane, state);

	return state;
}


/**
 * vmw_du_plane_reset - creates a blank vmw plane state
 * @plane: drm plane
 *
 * Resets the atomic state for @plane by freeing the state pointer (which might
 * be NULL, e.g. at driver load time) and allocating a new empty state object.
 */
void vmw_du_plane_reset(struct drm_plane *plane)
{
	struct vmw_plane_state *vps;


	if (plane->state)
		vmw_du_plane_destroy_state(plane, plane->state);

	vps = kzalloc(sizeof(*vps), GFP_KERNEL);

	if (!vps) {
		DRM_ERROR("Cannot allocate vmw_plane_state\n");
		return;
	}

	plane->state = &vps->base;
	plane->state->plane = plane;
	plane->state->rotation = DRM_MODE_ROTATE_0;
}


/**
 * vmw_du_plane_destroy_state - destroy plane state
 * @plane: DRM plane
 * @state: state object to destroy
 *
 * Destroys the plane state (both common and vmw-specific) for the
 * specified plane.
 */
void
vmw_du_plane_destroy_state(struct drm_plane *plane,
			   struct drm_plane_state *state)
{
	struct vmw_plane_state *vps = vmw_plane_state_to_vps(state);


	/* Should have been freed by cleanup_fb */
	if (vps->surf)
		vmw_surface_unreference(&vps->surf);

	if (vps->bo)
		vmw_bo_unreference(&vps->bo);

	drm_atomic_helper_plane_destroy_state(plane, state);
}


/**
 * vmw_du_connector_duplicate_state - duplicate connector state
 * @connector: DRM connector
 *
 * Allocates and returns a copy of the connector state (both common and
 * vmw-specific) for the specified connector.
 *
 * Returns: The newly allocated connector state, or NULL on failure.
 */
struct drm_connector_state *
vmw_du_connector_duplicate_state(struct drm_connector *connector)
{
	struct drm_connector_state *state;
	struct vmw_connector_state *vcs;

	if (WARN_ON(!connector->state))
		return NULL;

	vcs = kmemdup(connector->state, sizeof(*vcs), GFP_KERNEL);

	if (!vcs)
		return NULL;

	state = &vcs->base;

	__drm_atomic_helper_connector_duplicate_state(connector, state);

	return state;
}


/**
 * vmw_du_connector_reset - creates a blank vmw connector state
 * @connector: DRM connector
 *
 * Resets the atomic state for @connector by freeing the state pointer (which
 * might be NULL, e.g. at driver load time) and allocating a new empty state
 * object.
 */
void vmw_du_connector_reset(struct drm_connector *connector)
{
	struct vmw_connector_state *vcs;


	if (connector->state) {
		__drm_atomic_helper_connector_destroy_state(connector->state);

		kfree(vmw_connector_state_to_vcs(connector->state));
	}

	vcs = kzalloc(sizeof(*vcs), GFP_KERNEL);

	if (!vcs) {
		DRM_ERROR("Cannot allocate vmw_connector_state\n");
		return;
	}

	__drm_atomic_helper_connector_reset(connector, &vcs->base);
}


/**
 * vmw_du_connector_destroy_state - destroy connector state
 * @connector: DRM connector
 * @state: state object to destroy
 *
 * Destroys the connector state (both common and vmw-specific) for the
 * specified plane.
 */
void
vmw_du_connector_destroy_state(struct drm_connector *connector,
			  struct drm_connector_state *state)
{
	drm_atomic_helper_connector_destroy_state(connector, state);
}
/*
 * Generic framebuffer code
 */

/*
 * Surface framebuffer code
 */

static void vmw_framebuffer_surface_destroy(struct drm_framebuffer *framebuffer)
{
	struct vmw_framebuffer_surface *vfbs =
		vmw_framebuffer_to_vfbs(framebuffer);

	drm_framebuffer_cleanup(framebuffer);
	vmw_surface_unreference(&vfbs->surface);
	if (vfbs->base.user_obj)
		ttm_base_object_unref(&vfbs->base.user_obj);

	kfree(vfbs);
}

static int vmw_framebuffer_surface_dirty(struct drm_framebuffer *framebuffer,
				  struct drm_file *file_priv,
				  unsigned flags, unsigned color,
				  struct drm_clip_rect *clips,
				  unsigned num_clips)
{
	struct vmw_private *dev_priv = vmw_priv(framebuffer->dev);
	struct vmw_framebuffer_surface *vfbs =
		vmw_framebuffer_to_vfbs(framebuffer);
	struct drm_clip_rect norect;
	int ret, inc = 1;

	/* Legacy Display Unit does not support 3D */
	if (dev_priv->active_display_unit == vmw_du_legacy)
		return -EINVAL;

	drm_modeset_lock_all(dev_priv->dev);

	ret = ttm_read_lock(&dev_priv->reservation_sem, true);
	if (unlikely(ret != 0)) {
		drm_modeset_unlock_all(dev_priv->dev);
		return ret;
	}

	if (!num_clips) {
		num_clips = 1;
		clips = &norect;
		norect.x1 = norect.y1 = 0;
		norect.x2 = framebuffer->width;
		norect.y2 = framebuffer->height;
	} else if (flags & DRM_MODE_FB_DIRTY_ANNOTATE_COPY) {
		num_clips /= 2;
		inc = 2; /* skip source rects */
	}

	if (dev_priv->active_display_unit == vmw_du_screen_object)
		ret = vmw_kms_sou_do_surface_dirty(dev_priv, &vfbs->base,
						   clips, NULL, NULL, 0, 0,
						   num_clips, inc, NULL, NULL);
	else
		ret = vmw_kms_stdu_surface_dirty(dev_priv, &vfbs->base,
						 clips, NULL, NULL, 0, 0,
						 num_clips, inc, NULL, NULL);

	vmw_fifo_flush(dev_priv, false);
	ttm_read_unlock(&dev_priv->reservation_sem);

	drm_modeset_unlock_all(dev_priv->dev);

	return 0;
}

/**
 * vmw_kms_readback - Perform a readback from the screen system to
 * a buffer-object backed framebuffer.
 *
 * @dev_priv: Pointer to the device private structure.
 * @file_priv: Pointer to a struct drm_file identifying the caller.
 * Must be set to NULL if @user_fence_rep is NULL.
 * @vfb: Pointer to the buffer-object backed framebuffer.
 * @user_fence_rep: User-space provided structure for fence information.
 * Must be set to non-NULL if @file_priv is non-NULL.
 * @vclips: Array of clip rects.
 * @num_clips: Number of clip rects in @vclips.
 *
 * Returns 0 on success, negative error code on failure. -ERESTARTSYS if
 * interrupted.
 */
int vmw_kms_readback(struct vmw_private *dev_priv,
		     struct drm_file *file_priv,
		     struct vmw_framebuffer *vfb,
		     struct drm_vmw_fence_rep __user *user_fence_rep,
		     struct drm_vmw_rect *vclips,
		     uint32_t num_clips)
{
	switch (dev_priv->active_display_unit) {
	case vmw_du_screen_object:
		return vmw_kms_sou_readback(dev_priv, file_priv, vfb,
					    user_fence_rep, vclips, num_clips,
					    NULL);
	case vmw_du_screen_target:
		return vmw_kms_stdu_dma(dev_priv, file_priv, vfb,
					user_fence_rep, NULL, vclips, num_clips,
					1, false, true, NULL);
	default:
		WARN_ONCE(true,
			  "Readback called with invalid display system.\n");
}

	return -ENOSYS;
}


static const struct drm_framebuffer_funcs vmw_framebuffer_surface_funcs = {
	.destroy = vmw_framebuffer_surface_destroy,
	.dirty = vmw_framebuffer_surface_dirty,
};

static int vmw_kms_new_framebuffer_surface(struct vmw_private *dev_priv,
					   struct vmw_surface *surface,
					   struct vmw_framebuffer **out,
					   const struct drm_mode_fb_cmd2
					   *mode_cmd,
					   bool is_bo_proxy)

{
	struct drm_device *dev = dev_priv->dev;
	struct vmw_framebuffer_surface *vfbs;
	enum SVGA3dSurfaceFormat format;
	int ret;
	struct drm_format_name_buf format_name;

	/* 3D is only supported on HWv8 and newer hosts */
	if (dev_priv->active_display_unit == vmw_du_legacy)
		return -ENOSYS;

	/*
	 * Sanity checks.
	 */

	/* Surface must be marked as a scanout. */
	if (unlikely(!surface->scanout))
		return -EINVAL;

	if (unlikely(surface->mip_levels[0] != 1 ||
		     surface->num_sizes != 1 ||
		     surface->base_size.width < mode_cmd->width ||
		     surface->base_size.height < mode_cmd->height ||
		     surface->base_size.depth != 1)) {
		DRM_ERROR("Incompatible surface dimensions "
			  "for requested mode.\n");
		return -EINVAL;
	}

	switch (mode_cmd->pixel_format) {
	case DRM_FORMAT_ARGB8888:
		format = SVGA3D_A8R8G8B8;
		break;
	case DRM_FORMAT_XRGB8888:
		format = SVGA3D_X8R8G8B8;
		break;
	case DRM_FORMAT_RGB565:
		format = SVGA3D_R5G6B5;
		break;
	case DRM_FORMAT_XRGB1555:
		format = SVGA3D_A1R5G5B5;
		break;
	default:
		DRM_ERROR("Invalid pixel format: %s\n",
			  drm_get_format_name(mode_cmd->pixel_format, &format_name));
		return -EINVAL;
	}

	/*
	 * For DX, surface format validation is done when surface->scanout
	 * is set.
	 */
	if (!dev_priv->has_dx && format != surface->format) {
		DRM_ERROR("Invalid surface format for requested mode.\n");
		return -EINVAL;
	}

	vfbs = kzalloc(sizeof(*vfbs), GFP_KERNEL);
	if (!vfbs) {
		ret = -ENOMEM;
		goto out_err1;
	}

	drm_helper_mode_fill_fb_struct(dev, &vfbs->base.base, mode_cmd);
	vfbs->surface = vmw_surface_reference(surface);
	vfbs->base.user_handle = mode_cmd->handles[0];
	vfbs->is_bo_proxy = is_bo_proxy;

	*out = &vfbs->base;

	ret = drm_framebuffer_init(dev, &vfbs->base.base,
				   &vmw_framebuffer_surface_funcs);
	if (ret)
		goto out_err2;

	return 0;

out_err2:
	vmw_surface_unreference(&surface);
	kfree(vfbs);
out_err1:
	return ret;
}

/*
 * Buffer-object framebuffer code
 */

static void vmw_framebuffer_bo_destroy(struct drm_framebuffer *framebuffer)
{
	struct vmw_framebuffer_bo *vfbd =
		vmw_framebuffer_to_vfbd(framebuffer);

	drm_framebuffer_cleanup(framebuffer);
	vmw_bo_unreference(&vfbd->buffer);
	if (vfbd->base.user_obj)
		ttm_base_object_unref(&vfbd->base.user_obj);

	kfree(vfbd);
}

static int vmw_framebuffer_bo_dirty(struct drm_framebuffer *framebuffer,
				    struct drm_file *file_priv,
				    unsigned int flags, unsigned int color,
				    struct drm_clip_rect *clips,
				    unsigned int num_clips)
{
	struct vmw_private *dev_priv = vmw_priv(framebuffer->dev);
	struct vmw_framebuffer_bo *vfbd =
		vmw_framebuffer_to_vfbd(framebuffer);
	struct drm_clip_rect norect;
	int ret, increment = 1;

	drm_modeset_lock_all(dev_priv->dev);

	ret = ttm_read_lock(&dev_priv->reservation_sem, true);
	if (unlikely(ret != 0)) {
		drm_modeset_unlock_all(dev_priv->dev);
		return ret;
	}

	if (!num_clips) {
		num_clips = 1;
		clips = &norect;
		norect.x1 = norect.y1 = 0;
		norect.x2 = framebuffer->width;
		norect.y2 = framebuffer->height;
	} else if (flags & DRM_MODE_FB_DIRTY_ANNOTATE_COPY) {
		num_clips /= 2;
		increment = 2;
	}

	switch (dev_priv->active_display_unit) {
	case vmw_du_screen_target:
		ret = vmw_kms_stdu_dma(dev_priv, NULL, &vfbd->base, NULL,
				       clips, NULL, num_clips, increment,
				       true, true, NULL);
		break;
	case vmw_du_screen_object:
		ret = vmw_kms_sou_do_bo_dirty(dev_priv, &vfbd->base,
					      clips, NULL, num_clips,
					      increment, true, NULL, NULL);
		break;
	case vmw_du_legacy:
		ret = vmw_kms_ldu_do_bo_dirty(dev_priv, &vfbd->base, 0, 0,
					      clips, num_clips, increment);
		break;
	default:
		ret = -EINVAL;
		WARN_ONCE(true, "Dirty called with invalid display system.\n");
		break;
	}

	vmw_fifo_flush(dev_priv, false);
	ttm_read_unlock(&dev_priv->reservation_sem);

	drm_modeset_unlock_all(dev_priv->dev);

	return ret;
}

static const struct drm_framebuffer_funcs vmw_framebuffer_bo_funcs = {
	.destroy = vmw_framebuffer_bo_destroy,
	.dirty = vmw_framebuffer_bo_dirty,
};

/**
 * Pin the bofer in a location suitable for access by the
 * display system.
 */
static int vmw_framebuffer_pin(struct vmw_framebuffer *vfb)
{
	struct vmw_private *dev_priv = vmw_priv(vfb->base.dev);
	struct vmw_buffer_object *buf;
	struct ttm_placement *placement;
	int ret;

	buf = vfb->bo ?  vmw_framebuffer_to_vfbd(&vfb->base)->buffer :
		vmw_framebuffer_to_vfbs(&vfb->base)->surface->res.backup;

	if (!buf)
		return 0;

	switch (dev_priv->active_display_unit) {
	case vmw_du_legacy:
		vmw_overlay_pause_all(dev_priv);
		ret = vmw_bo_pin_in_start_of_vram(dev_priv, buf, false);
		vmw_overlay_resume_all(dev_priv);
		break;
	case vmw_du_screen_object:
	case vmw_du_screen_target:
		if (vfb->bo) {
			if (dev_priv->capabilities & SVGA_CAP_3D) {
				/*
				 * Use surface DMA to get content to
				 * sreen target surface.
				 */
				placement = &vmw_vram_gmr_placement;
			} else {
				/* Use CPU blit. */
				placement = &vmw_sys_placement;
			}
		} else {
			/* Use surface / image update */
			placement = &vmw_mob_placement;
		}

		return vmw_bo_pin_in_placement(dev_priv, buf, placement, false);
	default:
		return -EINVAL;
	}

	return ret;
}

static int vmw_framebuffer_unpin(struct vmw_framebuffer *vfb)
{
	struct vmw_private *dev_priv = vmw_priv(vfb->base.dev);
	struct vmw_buffer_object *buf;

	buf = vfb->bo ?  vmw_framebuffer_to_vfbd(&vfb->base)->buffer :
		vmw_framebuffer_to_vfbs(&vfb->base)->surface->res.backup;

	if (WARN_ON(!buf))
		return 0;

	return vmw_bo_unpin(dev_priv, buf, false);
}

/**
 * vmw_create_bo_proxy - create a proxy surface for the buffer object
 *
 * @dev: DRM device
 * @mode_cmd: parameters for the new surface
 * @bo_mob: MOB backing the buffer object
 * @srf_out: newly created surface
 *
 * When the content FB is a buffer object, we create a surface as a proxy to the
 * same buffer.  This way we can do a surface copy rather than a surface DMA.
 * This is a more efficient approach
 *
 * RETURNS:
 * 0 on success, error code otherwise
 */
static int vmw_create_bo_proxy(struct drm_device *dev,
			       const struct drm_mode_fb_cmd2 *mode_cmd,
			       struct vmw_buffer_object *bo_mob,
			       struct vmw_surface **srf_out)
{
	uint32_t format;
	struct drm_vmw_size content_base_size = {0};
	struct vmw_resource *res;
	unsigned int bytes_pp;
	struct drm_format_name_buf format_name;
	int ret;

	switch (mode_cmd->pixel_format) {
	case DRM_FORMAT_ARGB8888:
	case DRM_FORMAT_XRGB8888:
		format = SVGA3D_X8R8G8B8;
		bytes_pp = 4;
		break;

	case DRM_FORMAT_RGB565:
	case DRM_FORMAT_XRGB1555:
		format = SVGA3D_R5G6B5;
		bytes_pp = 2;
		break;

	case 8:
		format = SVGA3D_P8;
		bytes_pp = 1;
		break;

	default:
		DRM_ERROR("Invalid framebuffer format %s\n",
			  drm_get_format_name(mode_cmd->pixel_format, &format_name));
		return -EINVAL;
	}

	content_base_size.width  = mode_cmd->pitches[0] / bytes_pp;
	content_base_size.height = mode_cmd->height;
	content_base_size.depth  = 1;

	ret = vmw_surface_gb_priv_define(dev,
					 0, /* kernel visible only */
					 0, /* flags */
					 format,
					 true, /* can be a scanout buffer */
					 1, /* num of mip levels */
					 0,
					 0,
					 content_base_size,
					 SVGA3D_MS_PATTERN_NONE,
					 SVGA3D_MS_QUALITY_NONE,
					 srf_out);
	if (ret) {
		DRM_ERROR("Failed to allocate proxy content buffer\n");
		return ret;
	}

	res = &(*srf_out)->res;

	/* Reserve and switch the backing mob. */
	mutex_lock(&res->dev_priv->cmdbuf_mutex);
	(void) vmw_resource_reserve(res, false, true);
	vmw_bo_unreference(&res->backup);
	res->backup = vmw_bo_reference(bo_mob);
	res->backup_offset = 0;
	vmw_resource_unreserve(res, false, NULL, 0);
	mutex_unlock(&res->dev_priv->cmdbuf_mutex);

	return 0;
}



static int vmw_kms_new_framebuffer_bo(struct vmw_private *dev_priv,
				      struct vmw_buffer_object *bo,
				      struct vmw_framebuffer **out,
				      const struct drm_mode_fb_cmd2
				      *mode_cmd)

{
	struct drm_device *dev = dev_priv->dev;
	struct vmw_framebuffer_bo *vfbd;
	unsigned int requested_size;
	struct drm_format_name_buf format_name;
	int ret;

	requested_size = mode_cmd->height * mode_cmd->pitches[0];
	if (unlikely(requested_size > bo->base.num_pages * PAGE_SIZE)) {
		DRM_ERROR("Screen buffer object size is too small "
			  "for requested mode.\n");
		return -EINVAL;
	}

	/* Limited framebuffer color depth support for screen objects */
	if (dev_priv->active_display_unit == vmw_du_screen_object) {
		switch (mode_cmd->pixel_format) {
		case DRM_FORMAT_XRGB8888:
		case DRM_FORMAT_ARGB8888:
			break;
		case DRM_FORMAT_XRGB1555:
		case DRM_FORMAT_RGB565:
			break;
		default:
			DRM_ERROR("Invalid pixel format: %s\n",
				  drm_get_format_name(mode_cmd->pixel_format, &format_name));
			return -EINVAL;
		}
	}

	vfbd = kzalloc(sizeof(*vfbd), GFP_KERNEL);
	if (!vfbd) {
		ret = -ENOMEM;
		goto out_err1;
	}

	drm_helper_mode_fill_fb_struct(dev, &vfbd->base.base, mode_cmd);
	vfbd->base.bo = true;
	vfbd->buffer = vmw_bo_reference(bo);
	vfbd->base.user_handle = mode_cmd->handles[0];
	*out = &vfbd->base;

	ret = drm_framebuffer_init(dev, &vfbd->base.base,
				   &vmw_framebuffer_bo_funcs);
	if (ret)
		goto out_err2;

	return 0;

out_err2:
	vmw_bo_unreference(&bo);
	kfree(vfbd);
out_err1:
	return ret;
}


/**
 * vmw_kms_srf_ok - check if a surface can be created
 *
 * @width: requested width
 * @height: requested height
 *
 * Surfaces need to be less than texture size
 */
static bool
vmw_kms_srf_ok(struct vmw_private *dev_priv, uint32_t width, uint32_t height)
{
	if (width  > dev_priv->texture_max_width ||
	    height > dev_priv->texture_max_height)
		return false;

	return true;
}

/**
 * vmw_kms_new_framebuffer - Create a new framebuffer.
 *
 * @dev_priv: Pointer to device private struct.
 * @bo: Pointer to buffer object to wrap the kms framebuffer around.
 * Either @bo or @surface must be NULL.
 * @surface: Pointer to a surface to wrap the kms framebuffer around.
 * Either @bo or @surface must be NULL.
 * @only_2d: No presents will occur to this buffer object based framebuffer.
 * This helps the code to do some important optimizations.
 * @mode_cmd: Frame-buffer metadata.
 */
struct vmw_framebuffer *
vmw_kms_new_framebuffer(struct vmw_private *dev_priv,
			struct vmw_buffer_object *bo,
			struct vmw_surface *surface,
			bool only_2d,
			const struct drm_mode_fb_cmd2 *mode_cmd)
{
	struct vmw_framebuffer *vfb = NULL;
	bool is_bo_proxy = false;
	int ret;

	/*
	 * We cannot use the SurfaceDMA command in an non-accelerated VM,
	 * therefore, wrap the buffer object in a surface so we can use the
	 * SurfaceCopy command.
	 */
	if (vmw_kms_srf_ok(dev_priv, mode_cmd->width, mode_cmd->height)  &&
	    bo && only_2d &&
	    mode_cmd->width > 64 &&  /* Don't create a proxy for cursor */
	    dev_priv->active_display_unit == vmw_du_screen_target) {
		ret = vmw_create_bo_proxy(dev_priv->dev, mode_cmd,
					  bo, &surface);
		if (ret)
			return ERR_PTR(ret);

		is_bo_proxy = true;
	}

	/* Create the new framebuffer depending one what we have */
	if (surface) {
		ret = vmw_kms_new_framebuffer_surface(dev_priv, surface, &vfb,
						      mode_cmd,
						      is_bo_proxy);

		/*
		 * vmw_create_bo_proxy() adds a reference that is no longer
		 * needed
		 */
		if (is_bo_proxy)
			vmw_surface_unreference(&surface);
	} else if (bo) {
		ret = vmw_kms_new_framebuffer_bo(dev_priv, bo, &vfb,
						 mode_cmd);
	} else {
		BUG();
	}

	if (ret)
		return ERR_PTR(ret);

	vfb->pin = vmw_framebuffer_pin;
	vfb->unpin = vmw_framebuffer_unpin;

	return vfb;
}

/*
 * Generic Kernel modesetting functions
 */

static struct drm_framebuffer *vmw_kms_fb_create(struct drm_device *dev,
						 struct drm_file *file_priv,
						 const struct drm_mode_fb_cmd2 *mode_cmd)
{
	struct vmw_private *dev_priv = vmw_priv(dev);
	struct ttm_object_file *tfile = vmw_fpriv(file_priv)->tfile;
	struct vmw_framebuffer *vfb = NULL;
	struct vmw_surface *surface = NULL;
	struct vmw_buffer_object *bo = NULL;
	struct ttm_base_object *user_obj;
	int ret;

	/*
	 * Take a reference on the user object of the resource
	 * backing the kms fb. This ensures that user-space handle
	 * lookups on that resource will always work as long as
	 * it's registered with a kms framebuffer. This is important,
	 * since vmw_execbuf_process identifies resources in the
	 * command stream using user-space handles.
	 */

	user_obj = ttm_base_object_lookup(tfile, mode_cmd->handles[0]);
	if (unlikely(user_obj == NULL)) {
		DRM_ERROR("Could not locate requested kms frame buffer.\n");
		return ERR_PTR(-ENOENT);
	}

	/**
	 * End conditioned code.
	 */

	/* returns either a bo or surface */
	ret = vmw_user_lookup_handle(dev_priv, tfile,
				     mode_cmd->handles[0],
				     &surface, &bo);
	if (ret)
		goto err_out;


	if (!bo &&
	    !vmw_kms_srf_ok(dev_priv, mode_cmd->width, mode_cmd->height)) {
		DRM_ERROR("Surface size cannot exceed %dx%d",
			dev_priv->texture_max_width,
			dev_priv->texture_max_height);
		goto err_out;
	}


	vfb = vmw_kms_new_framebuffer(dev_priv, bo, surface,
				      !(dev_priv->capabilities & SVGA_CAP_3D),
				      mode_cmd);
	if (IS_ERR(vfb)) {
		ret = PTR_ERR(vfb);
		goto err_out;
 	}

err_out:
	/* vmw_user_lookup_handle takes one ref so does new_fb */
	if (bo)
		vmw_bo_unreference(&bo);
	if (surface)
		vmw_surface_unreference(&surface);

	if (ret) {
		DRM_ERROR("failed to create vmw_framebuffer: %i\n", ret);
		ttm_base_object_unref(&user_obj);
		return ERR_PTR(ret);
	} else
		vfb->user_obj = user_obj;

	return &vfb->base;
}

/**
 * vmw_kms_check_display_memory - Validates display memory required for a
 * topology
 * @dev: DRM device
 * @num_rects: number of drm_rect in rects
 * @rects: array of drm_rect representing the topology to validate indexed by
 * crtc index.
 *
 * Returns:
 * 0 on success otherwise negative error code
 */
static int vmw_kms_check_display_memory(struct drm_device *dev,
					uint32_t num_rects,
					struct drm_rect *rects)
{
	struct vmw_private *dev_priv = vmw_priv(dev);
	struct drm_rect bounding_box = {0};
	u64 total_pixels = 0, pixel_mem, bb_mem;
	int i;

	for (i = 0; i < num_rects; i++) {
		/*
		 * For STDU only individual screen (screen target) is limited by
		 * SCREENTARGET_MAX_WIDTH/HEIGHT registers.
		 */
		if (dev_priv->active_display_unit == vmw_du_screen_target &&
		    (drm_rect_width(&rects[i]) > dev_priv->stdu_max_width ||
		     drm_rect_height(&rects[i]) > dev_priv->stdu_max_height)) {
			DRM_ERROR("Screen size not supported.\n");
			return -EINVAL;
		}

		/* Bounding box upper left is at (0,0). */
		if (rects[i].x2 > bounding_box.x2)
			bounding_box.x2 = rects[i].x2;

		if (rects[i].y2 > bounding_box.y2)
			bounding_box.y2 = rects[i].y2;

		total_pixels += (u64) drm_rect_width(&rects[i]) *
			(u64) drm_rect_height(&rects[i]);
	}

	/* Virtual svga device primary limits are always in 32-bpp. */
	pixel_mem = total_pixels * 4;

	/*
	 * For HV10 and below prim_bb_mem is vram size. When
	 * SVGA_REG_MAX_PRIMARY_BOUNDING_BOX_MEM is not present vram size is
	 * limit on primary bounding box
	 */
	if (pixel_mem > dev_priv->prim_bb_mem) {
		DRM_ERROR("Combined output size too large.\n");
		return -EINVAL;
	}

	/* SVGA_CAP_NO_BB_RESTRICTION is available for STDU only. */
	if (dev_priv->active_display_unit != vmw_du_screen_target ||
	    !(dev_priv->capabilities & SVGA_CAP_NO_BB_RESTRICTION)) {
		bb_mem = (u64) bounding_box.x2 * bounding_box.y2 * 4;

		if (bb_mem > dev_priv->prim_bb_mem) {
			DRM_ERROR("Topology is beyond supported limits.\n");
			return -EINVAL;
		}
	}

	return 0;
}

/**
 * vmw_kms_check_topology - Validates topology in drm_atomic_state
 * @dev: DRM device
 * @state: the driver state object
 *
 * Returns:
 * 0 on success otherwise negative error code
 */
static int vmw_kms_check_topology(struct drm_device *dev,
				  struct drm_atomic_state *state)
{
	struct vmw_private *dev_priv = vmw_priv(dev);
	struct drm_crtc_state *old_crtc_state, *new_crtc_state;
	struct drm_rect *rects;
	struct drm_crtc *crtc;
	uint32_t i;
	int ret = 0;

	rects = kcalloc(dev->mode_config.num_crtc, sizeof(struct drm_rect),
			GFP_KERNEL);
	if (!rects)
		return -ENOMEM;

	mutex_lock(&dev_priv->requested_layout_mutex);

	drm_for_each_crtc(crtc, dev) {
		struct vmw_display_unit *du = vmw_crtc_to_du(crtc);
		struct drm_crtc_state *crtc_state = crtc->state;

		i = drm_crtc_index(crtc);

		if (crtc_state && crtc_state->enable) {
			rects[i].x1 = du->gui_x;
			rects[i].y1 = du->gui_y;
			rects[i].x2 = du->gui_x + crtc_state->mode.hdisplay;
			rects[i].y2 = du->gui_y + crtc_state->mode.vdisplay;
		}
	}

	/* Determine change to topology due to new atomic state */
	for_each_oldnew_crtc_in_state(state, crtc, old_crtc_state,
				      new_crtc_state, i) {
		struct vmw_display_unit *du = vmw_crtc_to_du(crtc);
		struct drm_connector *connector;
		struct drm_connector_state *conn_state;
		struct vmw_connector_state *vmw_conn_state;

		if (!new_crtc_state->enable) {
			rects[i].x1 = 0;
			rects[i].y1 = 0;
			rects[i].x2 = 0;
			rects[i].y2 = 0;
			continue;
		}

		if (!du->pref_active) {
			ret = -EINVAL;
			goto clean;
		}

		/*
		 * For vmwgfx each crtc has only one connector attached and it
		 * is not changed so don't really need to check the
		 * crtc->connector_mask and iterate over it.
		 */
		connector = &du->connector;
		conn_state = drm_atomic_get_connector_state(state, connector);
		if (IS_ERR(conn_state)) {
			ret = PTR_ERR(conn_state);
			goto clean;
		}

		vmw_conn_state = vmw_connector_state_to_vcs(conn_state);
		vmw_conn_state->gui_x = du->gui_x;
		vmw_conn_state->gui_y = du->gui_y;

		rects[i].x1 = du->gui_x;
		rects[i].y1 = du->gui_y;
		rects[i].x2 = du->gui_x + new_crtc_state->mode.hdisplay;
		rects[i].y2 = du->gui_y + new_crtc_state->mode.vdisplay;
	}

	ret = vmw_kms_check_display_memory(dev, dev->mode_config.num_crtc,
					   rects);

clean:
	mutex_unlock(&dev_priv->requested_layout_mutex);
	kfree(rects);
	return ret;
}

/**
 * vmw_kms_atomic_check_modeset- validate state object for modeset changes
 *
 * @dev: DRM device
 * @state: the driver state object
 *
 * This is a simple wrapper around drm_atomic_helper_check_modeset() for
 * us to assign a value to mode->crtc_clock so that
 * drm_calc_timestamping_constants() won't throw an error message
 *
 * Returns:
 * Zero for success or -errno
 */
static int
vmw_kms_atomic_check_modeset(struct drm_device *dev,
			     struct drm_atomic_state *state)
{
	struct drm_crtc *crtc;
	struct drm_crtc_state *crtc_state;
	bool need_modeset = false;
	int i, ret;

	ret = drm_atomic_helper_check(dev, state);
	if (ret)
		return ret;

	if (!state->allow_modeset)
		return ret;

	/*
	 * Legacy path do not set allow_modeset properly like
	 * @drm_atomic_helper_update_plane, This will result in unnecessary call
	 * to vmw_kms_check_topology. So extra set of check.
	 */
	for_each_new_crtc_in_state(state, crtc, crtc_state, i) {
		if (drm_atomic_crtc_needs_modeset(crtc_state))
			need_modeset = true;
	}

	if (need_modeset)
		return vmw_kms_check_topology(dev, state);

	return ret;
}

static const struct drm_mode_config_funcs vmw_kms_funcs = {
	.fb_create = vmw_kms_fb_create,
	.atomic_check = vmw_kms_atomic_check_modeset,
	.atomic_commit = drm_atomic_helper_commit,
};

static int vmw_kms_generic_present(struct vmw_private *dev_priv,
				   struct drm_file *file_priv,
				   struct vmw_framebuffer *vfb,
				   struct vmw_surface *surface,
				   uint32_t sid,
				   int32_t destX, int32_t destY,
				   struct drm_vmw_rect *clips,
				   uint32_t num_clips)
{
	return vmw_kms_sou_do_surface_dirty(dev_priv, vfb, NULL, clips,
					    &surface->res, destX, destY,
					    num_clips, 1, NULL, NULL);
}


int vmw_kms_present(struct vmw_private *dev_priv,
		    struct drm_file *file_priv,
		    struct vmw_framebuffer *vfb,
		    struct vmw_surface *surface,
		    uint32_t sid,
		    int32_t destX, int32_t destY,
		    struct drm_vmw_rect *clips,
		    uint32_t num_clips)
{
	int ret;

	switch (dev_priv->active_display_unit) {
	case vmw_du_screen_target:
		ret = vmw_kms_stdu_surface_dirty(dev_priv, vfb, NULL, clips,
						 &surface->res, destX, destY,
						 num_clips, 1, NULL, NULL);
		break;
	case vmw_du_screen_object:
		ret = vmw_kms_generic_present(dev_priv, file_priv, vfb, surface,
					      sid, destX, destY, clips,
					      num_clips);
		break;
	default:
		WARN_ONCE(true,
			  "Present called with invalid display system.\n");
		ret = -ENOSYS;
		break;
	}
	if (ret)
		return ret;

	vmw_fifo_flush(dev_priv, false);

	return 0;
}

static void
vmw_kms_create_hotplug_mode_update_property(struct vmw_private *dev_priv)
{
	if (dev_priv->hotplug_mode_update_property)
		return;

	dev_priv->hotplug_mode_update_property =
		drm_property_create_range(dev_priv->dev,
					  DRM_MODE_PROP_IMMUTABLE,
					  "hotplug_mode_update", 0, 1);

	if (!dev_priv->hotplug_mode_update_property)
		return;

}

int vmw_kms_init(struct vmw_private *dev_priv)
{
	struct drm_device *dev = dev_priv->dev;
	int ret;

	drm_mode_config_init(dev);
	dev->mode_config.funcs = &vmw_kms_funcs;
	dev->mode_config.min_width = 1;
	dev->mode_config.min_height = 1;
	dev->mode_config.max_width = dev_priv->texture_max_width;
	dev->mode_config.max_height = dev_priv->texture_max_height;

	drm_mode_create_suggested_offset_properties(dev);
	vmw_kms_create_hotplug_mode_update_property(dev_priv);

	ret = vmw_kms_stdu_init_display(dev_priv);
	if (ret) {
		ret = vmw_kms_sou_init_display(dev_priv);
		if (ret) /* Fallback */
			ret = vmw_kms_ldu_init_display(dev_priv);
	}

	return ret;
}

int vmw_kms_close(struct vmw_private *dev_priv)
{
	int ret = 0;

	/*
	 * Docs says we should take the lock before calling this function
	 * but since it destroys encoders and our destructor calls
	 * drm_encoder_cleanup which takes the lock we deadlock.
	 */
	drm_mode_config_cleanup(dev_priv->dev);
	if (dev_priv->active_display_unit == vmw_du_legacy)
		ret = vmw_kms_ldu_close_display(dev_priv);

	return ret;
}

int vmw_kms_cursor_bypass_ioctl(struct drm_device *dev, void *data,
				struct drm_file *file_priv)
{
	struct drm_vmw_cursor_bypass_arg *arg = data;
	struct vmw_display_unit *du;
	struct drm_crtc *crtc;
	int ret = 0;


	mutex_lock(&dev->mode_config.mutex);
	if (arg->flags & DRM_VMW_CURSOR_BYPASS_ALL) {

		list_for_each_entry(crtc, &dev->mode_config.crtc_list, head) {
			du = vmw_crtc_to_du(crtc);
			du->hotspot_x = arg->xhot;
			du->hotspot_y = arg->yhot;
		}

		mutex_unlock(&dev->mode_config.mutex);
		return 0;
	}

	crtc = drm_crtc_find(dev, file_priv, arg->crtc_id);
	if (!crtc) {
		ret = -ENOENT;
		goto out;
	}

	du = vmw_crtc_to_du(crtc);

	du->hotspot_x = arg->xhot;
	du->hotspot_y = arg->yhot;

out:
	mutex_unlock(&dev->mode_config.mutex);

	return ret;
}

int vmw_kms_write_svga(struct vmw_private *vmw_priv,
			unsigned width, unsigned height, unsigned pitch,
			unsigned bpp, unsigned depth)
{
	if (vmw_priv->capabilities & SVGA_CAP_PITCHLOCK)
		vmw_write(vmw_priv, SVGA_REG_PITCHLOCK, pitch);
	else if (vmw_fifo_have_pitchlock(vmw_priv))
		vmw_mmio_write(pitch, vmw_priv->mmio_virt +
			       SVGA_FIFO_PITCHLOCK);
	vmw_write(vmw_priv, SVGA_REG_WIDTH, width);
	vmw_write(vmw_priv, SVGA_REG_HEIGHT, height);
	vmw_write(vmw_priv, SVGA_REG_BITS_PER_PIXEL, bpp);

	if (vmw_read(vmw_priv, SVGA_REG_DEPTH) != depth) {
		DRM_ERROR("Invalid depth %u for %u bpp, host expects %u\n",
			  depth, bpp, vmw_read(vmw_priv, SVGA_REG_DEPTH));
		return -EINVAL;
	}

	return 0;
}

int vmw_kms_save_vga(struct vmw_private *vmw_priv)
{
	struct vmw_vga_topology_state *save;
	uint32_t i;

	vmw_priv->vga_width = vmw_read(vmw_priv, SVGA_REG_WIDTH);
	vmw_priv->vga_height = vmw_read(vmw_priv, SVGA_REG_HEIGHT);
	vmw_priv->vga_bpp = vmw_read(vmw_priv, SVGA_REG_BITS_PER_PIXEL);
	if (vmw_priv->capabilities & SVGA_CAP_PITCHLOCK)
		vmw_priv->vga_pitchlock =
		  vmw_read(vmw_priv, SVGA_REG_PITCHLOCK);
	else if (vmw_fifo_have_pitchlock(vmw_priv))
		vmw_priv->vga_pitchlock = vmw_mmio_read(vmw_priv->mmio_virt +
							SVGA_FIFO_PITCHLOCK);

	if (!(vmw_priv->capabilities & SVGA_CAP_DISPLAY_TOPOLOGY))
		return 0;

	vmw_priv->num_displays = vmw_read(vmw_priv,
					  SVGA_REG_NUM_GUEST_DISPLAYS);

	if (vmw_priv->num_displays == 0)
		vmw_priv->num_displays = 1;

	for (i = 0; i < vmw_priv->num_displays; ++i) {
		save = &vmw_priv->vga_save[i];
		vmw_write(vmw_priv, SVGA_REG_DISPLAY_ID, i);
		save->primary = vmw_read(vmw_priv, SVGA_REG_DISPLAY_IS_PRIMARY);
		save->pos_x = vmw_read(vmw_priv, SVGA_REG_DISPLAY_POSITION_X);
		save->pos_y = vmw_read(vmw_priv, SVGA_REG_DISPLAY_POSITION_Y);
		save->width = vmw_read(vmw_priv, SVGA_REG_DISPLAY_WIDTH);
		save->height = vmw_read(vmw_priv, SVGA_REG_DISPLAY_HEIGHT);
		vmw_write(vmw_priv, SVGA_REG_DISPLAY_ID, SVGA_ID_INVALID);
		if (i == 0 && vmw_priv->num_displays == 1 &&
		    save->width == 0 && save->height == 0) {

			/*
			 * It should be fairly safe to assume that these
			 * values are uninitialized.
			 */

			save->width = vmw_priv->vga_width - save->pos_x;
			save->height = vmw_priv->vga_height - save->pos_y;
		}
	}

	return 0;
}

int vmw_kms_restore_vga(struct vmw_private *vmw_priv)
{
	struct vmw_vga_topology_state *save;
	uint32_t i;

	vmw_write(vmw_priv, SVGA_REG_WIDTH, vmw_priv->vga_width);
	vmw_write(vmw_priv, SVGA_REG_HEIGHT, vmw_priv->vga_height);
	vmw_write(vmw_priv, SVGA_REG_BITS_PER_PIXEL, vmw_priv->vga_bpp);
	if (vmw_priv->capabilities & SVGA_CAP_PITCHLOCK)
		vmw_write(vmw_priv, SVGA_REG_PITCHLOCK,
			  vmw_priv->vga_pitchlock);
	else if (vmw_fifo_have_pitchlock(vmw_priv))
		vmw_mmio_write(vmw_priv->vga_pitchlock,
			       vmw_priv->mmio_virt + SVGA_FIFO_PITCHLOCK);

	if (!(vmw_priv->capabilities & SVGA_CAP_DISPLAY_TOPOLOGY))
		return 0;

	for (i = 0; i < vmw_priv->num_displays; ++i) {
		save = &vmw_priv->vga_save[i];
		vmw_write(vmw_priv, SVGA_REG_DISPLAY_ID, i);
		vmw_write(vmw_priv, SVGA_REG_DISPLAY_IS_PRIMARY, save->primary);
		vmw_write(vmw_priv, SVGA_REG_DISPLAY_POSITION_X, save->pos_x);
		vmw_write(vmw_priv, SVGA_REG_DISPLAY_POSITION_Y, save->pos_y);
		vmw_write(vmw_priv, SVGA_REG_DISPLAY_WIDTH, save->width);
		vmw_write(vmw_priv, SVGA_REG_DISPLAY_HEIGHT, save->height);
		vmw_write(vmw_priv, SVGA_REG_DISPLAY_ID, SVGA_ID_INVALID);
	}

	return 0;
}

bool vmw_kms_validate_mode_vram(struct vmw_private *dev_priv,
				uint32_t pitch,
				uint32_t height)
{
	return ((u64) pitch * (u64) height) < (u64)
		((dev_priv->active_display_unit == vmw_du_screen_target) ?
		 dev_priv->prim_bb_mem : dev_priv->vram_size);
}


/**
 * Function called by DRM code called with vbl_lock held.
 */
u32 vmw_get_vblank_counter(struct drm_device *dev, unsigned int pipe)
{
	return 0;
}

/**
 * Function called by DRM code called with vbl_lock held.
 */
int vmw_enable_vblank(struct drm_device *dev, unsigned int pipe)
{
	return -EINVAL;
}

/**
 * Function called by DRM code called with vbl_lock held.
 */
void vmw_disable_vblank(struct drm_device *dev, unsigned int pipe)
{
}

/**
 * vmw_du_update_layout - Update the display unit with topology from resolution
 * plugin and generate DRM uevent
 * @dev_priv: device private
 * @num_rects: number of drm_rect in rects
 * @rects: toplogy to update
 */
static int vmw_du_update_layout(struct vmw_private *dev_priv,
				unsigned int num_rects, struct drm_rect *rects)
{
	struct drm_device *dev = dev_priv->dev;
	struct vmw_display_unit *du;
	struct drm_connector *con;
	struct drm_connector_list_iter conn_iter;

	/*
	 * Currently only gui_x/y is protected with requested_layout_mutex.
	 */
	mutex_lock(&dev_priv->requested_layout_mutex);
	drm_connector_list_iter_begin(dev, &conn_iter);
	drm_for_each_connector_iter(con, &conn_iter) {
		du = vmw_connector_to_du(con);
		if (num_rects > du->unit) {
			du->pref_width = drm_rect_width(&rects[du->unit]);
			du->pref_height = drm_rect_height(&rects[du->unit]);
			du->pref_active = true;
			du->gui_x = rects[du->unit].x1;
			du->gui_y = rects[du->unit].y1;
		} else {
			du->pref_width = 800;
			du->pref_height = 600;
			du->pref_active = false;
			du->gui_x = 0;
			du->gui_y = 0;
		}
	}
	drm_connector_list_iter_end(&conn_iter);
	mutex_unlock(&dev_priv->requested_layout_mutex);

	mutex_lock(&dev->mode_config.mutex);
	list_for_each_entry(con, &dev->mode_config.connector_list, head) {
		du = vmw_connector_to_du(con);
		if (num_rects > du->unit) {
			drm_object_property_set_value
			  (&con->base, dev->mode_config.suggested_x_property,
			   du->gui_x);
			drm_object_property_set_value
			  (&con->base, dev->mode_config.suggested_y_property,
			   du->gui_y);
		} else {
			drm_object_property_set_value
			  (&con->base, dev->mode_config.suggested_x_property,
			   0);
			drm_object_property_set_value
			  (&con->base, dev->mode_config.suggested_y_property,
			   0);
		}
		con->status = vmw_du_connector_detect(con, true);
	}
	mutex_unlock(&dev->mode_config.mutex);

	drm_sysfs_hotplug_event(dev);

	return 0;
}

int vmw_du_crtc_gamma_set(struct drm_crtc *crtc,
			  u16 *r, u16 *g, u16 *b,
			  uint32_t size,
			  struct drm_modeset_acquire_ctx *ctx)
{
	struct vmw_private *dev_priv = vmw_priv(crtc->dev);
	int i;

	for (i = 0; i < size; i++) {
		DRM_DEBUG("%d r/g/b = 0x%04x / 0x%04x / 0x%04x\n", i,
			  r[i], g[i], b[i]);
		vmw_write(dev_priv, SVGA_PALETTE_BASE + i * 3 + 0, r[i] >> 8);
		vmw_write(dev_priv, SVGA_PALETTE_BASE + i * 3 + 1, g[i] >> 8);
		vmw_write(dev_priv, SVGA_PALETTE_BASE + i * 3 + 2, b[i] >> 8);
	}

	return 0;
}

int vmw_du_connector_dpms(struct drm_connector *connector, int mode)
{
	return 0;
}

enum drm_connector_status
vmw_du_connector_detect(struct drm_connector *connector, bool force)
{
	uint32_t num_displays;
	struct drm_device *dev = connector->dev;
	struct vmw_private *dev_priv = vmw_priv(dev);
	struct vmw_display_unit *du = vmw_connector_to_du(connector);

	num_displays = vmw_read(dev_priv, SVGA_REG_NUM_DISPLAYS);

	return ((vmw_connector_to_du(connector)->unit < num_displays &&
		 du->pref_active) ?
		connector_status_connected : connector_status_disconnected);
}

static struct drm_display_mode vmw_kms_connector_builtin[] = {
	/* 640x480@60Hz */
	{ DRM_MODE("640x480", DRM_MODE_TYPE_DRIVER, 25175, 640, 656,
		   752, 800, 0, 480, 489, 492, 525, 0,
		   DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC) },
	/* 800x600@60Hz */
	{ DRM_MODE("800x600", DRM_MODE_TYPE_DRIVER, 40000, 800, 840,
		   968, 1056, 0, 600, 601, 605, 628, 0,
		   DRM_MODE_FLAG_PHSYNC | DRM_MODE_FLAG_PVSYNC) },
	/* 1024x768@60Hz */
	{ DRM_MODE("1024x768", DRM_MODE_TYPE_DRIVER, 65000, 1024, 1048,
		   1184, 1344, 0, 768, 771, 777, 806, 0,
		   DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC) },
	/* 1152x864@75Hz */
	{ DRM_MODE("1152x864", DRM_MODE_TYPE_DRIVER, 108000, 1152, 1216,
		   1344, 1600, 0, 864, 865, 868, 900, 0,
		   DRM_MODE_FLAG_PHSYNC | DRM_MODE_FLAG_PVSYNC) },
	/* 1280x768@60Hz */
	{ DRM_MODE("1280x768", DRM_MODE_TYPE_DRIVER, 79500, 1280, 1344,
		   1472, 1664, 0, 768, 771, 778, 798, 0,
		   DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_PVSYNC) },
	/* 1280x800@60Hz */
	{ DRM_MODE("1280x800", DRM_MODE_TYPE_DRIVER, 83500, 1280, 1352,
		   1480, 1680, 0, 800, 803, 809, 831, 0,
		   DRM_MODE_FLAG_PHSYNC | DRM_MODE_FLAG_NVSYNC) },
	/* 1280x960@60Hz */
	{ DRM_MODE("1280x960", DRM_MODE_TYPE_DRIVER, 108000, 1280, 1376,
		   1488, 1800, 0, 960, 961, 964, 1000, 0,
		   DRM_MODE_FLAG_PHSYNC | DRM_MODE_FLAG_PVSYNC) },
	/* 1280x1024@60Hz */
	{ DRM_MODE("1280x1024", DRM_MODE_TYPE_DRIVER, 108000, 1280, 1328,
		   1440, 1688, 0, 1024, 1025, 1028, 1066, 0,
		   DRM_MODE_FLAG_PHSYNC | DRM_MODE_FLAG_PVSYNC) },
	/* 1360x768@60Hz */
	{ DRM_MODE("1360x768", DRM_MODE_TYPE_DRIVER, 85500, 1360, 1424,
		   1536, 1792, 0, 768, 771, 777, 795, 0,
		   DRM_MODE_FLAG_PHSYNC | DRM_MODE_FLAG_PVSYNC) },
	/* 1440x1050@60Hz */
	{ DRM_MODE("1400x1050", DRM_MODE_TYPE_DRIVER, 121750, 1400, 1488,
		   1632, 1864, 0, 1050, 1053, 1057, 1089, 0,
		   DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_PVSYNC) },
	/* 1440x900@60Hz */
	{ DRM_MODE("1440x900", DRM_MODE_TYPE_DRIVER, 106500, 1440, 1520,
		   1672, 1904, 0, 900, 903, 909, 934, 0,
		   DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_PVSYNC) },
	/* 1600x1200@60Hz */
	{ DRM_MODE("1600x1200", DRM_MODE_TYPE_DRIVER, 162000, 1600, 1664,
		   1856, 2160, 0, 1200, 1201, 1204, 1250, 0,
		   DRM_MODE_FLAG_PHSYNC | DRM_MODE_FLAG_PVSYNC) },
	/* 1680x1050@60Hz */
	{ DRM_MODE("1680x1050", DRM_MODE_TYPE_DRIVER, 146250, 1680, 1784,
		   1960, 2240, 0, 1050, 1053, 1059, 1089, 0,
		   DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_PVSYNC) },
	/* 1792x1344@60Hz */
	{ DRM_MODE("1792x1344", DRM_MODE_TYPE_DRIVER, 204750, 1792, 1920,
		   2120, 2448, 0, 1344, 1345, 1348, 1394, 0,
		   DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_PVSYNC) },
	/* 1853x1392@60Hz */
	{ DRM_MODE("1856x1392", DRM_MODE_TYPE_DRIVER, 218250, 1856, 1952,
		   2176, 2528, 0, 1392, 1393, 1396, 1439, 0,
		   DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_PVSYNC) },
	/* 1920x1200@60Hz */
	{ DRM_MODE("1920x1200", DRM_MODE_TYPE_DRIVER, 193250, 1920, 2056,
		   2256, 2592, 0, 1200, 1203, 1209, 1245, 0,
		   DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_PVSYNC) },
	/* 1920x1440@60Hz */
	{ DRM_MODE("1920x1440", DRM_MODE_TYPE_DRIVER, 234000, 1920, 2048,
		   2256, 2600, 0, 1440, 1441, 1444, 1500, 0,
		   DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_PVSYNC) },
	/* 2560x1600@60Hz */
	{ DRM_MODE("2560x1600", DRM_MODE_TYPE_DRIVER, 348500, 2560, 2752,
		   3032, 3504, 0, 1600, 1603, 1609, 1658, 0,
		   DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_PVSYNC) },
	/* Terminate */
	{ DRM_MODE("", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) },
};

/**
 * vmw_guess_mode_timing - Provide fake timings for a
 * 60Hz vrefresh mode.
 *
 * @mode - Pointer to a struct drm_display_mode with hdisplay and vdisplay
 * members filled in.
 */
void vmw_guess_mode_timing(struct drm_display_mode *mode)
{
	mode->hsync_start = mode->hdisplay + 50;
	mode->hsync_end = mode->hsync_start + 50;
	mode->htotal = mode->hsync_end + 50;

	mode->vsync_start = mode->vdisplay + 50;
	mode->vsync_end = mode->vsync_start + 50;
	mode->vtotal = mode->vsync_end + 50;

	mode->clock = (u32)mode->htotal * (u32)mode->vtotal / 100 * 6;
	mode->vrefresh = drm_mode_vrefresh(mode);
}


int vmw_du_connector_fill_modes(struct drm_connector *connector,
				uint32_t max_width, uint32_t max_height)
{
	struct vmw_display_unit *du = vmw_connector_to_du(connector);
	struct drm_device *dev = connector->dev;
	struct vmw_private *dev_priv = vmw_priv(dev);
	struct drm_display_mode *mode = NULL;
	struct drm_display_mode *bmode;
	struct drm_display_mode prefmode = { DRM_MODE("preferred",
		DRM_MODE_TYPE_DRIVER | DRM_MODE_TYPE_PREFERRED,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_PVSYNC)
	};
	int i;
	u32 assumed_bpp = 4;

	if (dev_priv->assume_16bpp)
		assumed_bpp = 2;

	max_width  = min(max_width,  dev_priv->texture_max_width);
	max_height = min(max_height, dev_priv->texture_max_height);

	/*
	 * For STDU extra limit for a mode on SVGA_REG_SCREENTARGET_MAX_WIDTH/
	 * HEIGHT registers.
	 */
	if (dev_priv->active_display_unit == vmw_du_screen_target) {
		max_width  = min(max_width,  dev_priv->stdu_max_width);
		max_height = min(max_height, dev_priv->stdu_max_height);
	}

	/* Add preferred mode */
	mode = drm_mode_duplicate(dev, &prefmode);
	if (!mode)
		return 0;
	mode->hdisplay = du->pref_width;
	mode->vdisplay = du->pref_height;
	vmw_guess_mode_timing(mode);

	if (vmw_kms_validate_mode_vram(dev_priv,
					mode->hdisplay * assumed_bpp,
					mode->vdisplay)) {
		drm_mode_probed_add(connector, mode);
	} else {
		drm_mode_destroy(dev, mode);
		mode = NULL;
	}

	if (du->pref_mode) {
		list_del_init(&du->pref_mode->head);
		drm_mode_destroy(dev, du->pref_mode);
	}

	/* mode might be null here, this is intended */
	du->pref_mode = mode;

	for (i = 0; vmw_kms_connector_builtin[i].type != 0; i++) {
		bmode = &vmw_kms_connector_builtin[i];
		if (bmode->hdisplay > max_width ||
		    bmode->vdisplay > max_height)
			continue;

		if (!vmw_kms_validate_mode_vram(dev_priv,
						bmode->hdisplay * assumed_bpp,
						bmode->vdisplay))
			continue;

		mode = drm_mode_duplicate(dev, bmode);
		if (!mode)
			return 0;
		mode->vrefresh = drm_mode_vrefresh(mode);

		drm_mode_probed_add(connector, mode);
	}

	drm_connector_list_update(connector);
	/* Move the prefered mode first, help apps pick the right mode. */
	drm_mode_sort(&connector->modes);

	return 1;
}

int vmw_du_connector_set_property(struct drm_connector *connector,
				  struct drm_property *property,
				  uint64_t val)
{
	struct vmw_display_unit *du = vmw_connector_to_du(connector);
	struct vmw_private *dev_priv = vmw_priv(connector->dev);

	if (property == dev_priv->implicit_placement_property)
		du->is_implicit = val;

	return 0;
}



/**
 * vmw_du_connector_atomic_set_property - Atomic version of get property
 *
 * @crtc - crtc the property is associated with
 *
 * Returns:
 * Zero on success, negative errno on failure.
 */
int
vmw_du_connector_atomic_set_property(struct drm_connector *connector,
				     struct drm_connector_state *state,
				     struct drm_property *property,
				     uint64_t val)
{
	struct vmw_private *dev_priv = vmw_priv(connector->dev);
	struct vmw_connector_state *vcs = vmw_connector_state_to_vcs(state);
	struct vmw_display_unit *du = vmw_connector_to_du(connector);


	if (property == dev_priv->implicit_placement_property) {
		vcs->is_implicit = val;

		/*
		 * We should really be doing a drm_atomic_commit() to
		 * commit the new state, but since this doesn't cause
		 * an immedate state change, this is probably ok
		 */
		du->is_implicit = vcs->is_implicit;
	} else {
		return -EINVAL;
	}

	return 0;
}


/**
 * vmw_du_connector_atomic_get_property - Atomic version of get property
 *
 * @connector - connector the property is associated with
 *
 * Returns:
 * Zero on success, negative errno on failure.
 */
int
vmw_du_connector_atomic_get_property(struct drm_connector *connector,
				     const struct drm_connector_state *state,
				     struct drm_property *property,
				     uint64_t *val)
{
	struct vmw_private *dev_priv = vmw_priv(connector->dev);
	struct vmw_connector_state *vcs = vmw_connector_state_to_vcs(state);

	if (property == dev_priv->implicit_placement_property)
		*val = vcs->is_implicit;
	else {
		DRM_ERROR("Invalid Property %s\n", property->name);
		return -EINVAL;
	}

	return 0;
}

/**
 * vmw_kms_update_layout_ioctl - Handler for DRM_VMW_UPDATE_LAYOUT ioctl
 * @dev: drm device for the ioctl
 * @data: data pointer for the ioctl
 * @file_priv: drm file for the ioctl call
 *
 * Update preferred topology of display unit as per ioctl request. The topology
 * is expressed as array of drm_vmw_rect.
 * e.g.
 * [0 0 640 480] [640 0 800 600] [0 480 640 480]
 *
 * NOTE:
 * The x and y offset (upper left) in drm_vmw_rect cannot be less than 0. Beside
 * device limit on topology, x + w and y + h (lower right) cannot be greater
 * than INT_MAX. So topology beyond these limits will return with error.
 *
 * Returns:
 * Zero on success, negative errno on failure.
 */
int vmw_kms_update_layout_ioctl(struct drm_device *dev, void *data,
				struct drm_file *file_priv)
{
	struct vmw_private *dev_priv = vmw_priv(dev);
	struct drm_mode_config *mode_config = &dev->mode_config;
	struct drm_vmw_update_layout_arg *arg =
		(struct drm_vmw_update_layout_arg *)data;
	void __user *user_rects;
	struct drm_vmw_rect *rects;
	struct drm_rect *drm_rects;
	unsigned rects_size;
	int ret, i;

	if (!arg->num_outputs) {
		struct drm_rect def_rect = {0, 0, 800, 600};
		vmw_du_update_layout(dev_priv, 1, &def_rect);
		return 0;
	}

	rects_size = arg->num_outputs * sizeof(struct drm_vmw_rect);
	rects = kcalloc(arg->num_outputs, sizeof(struct drm_vmw_rect),
			GFP_KERNEL);
	if (unlikely(!rects))
		return -ENOMEM;

	user_rects = (void __user *)(unsigned long)arg->rects;
	ret = copy_from_user(rects, user_rects, rects_size);
	if (unlikely(ret != 0)) {
		DRM_ERROR("Failed to get rects.\n");
		ret = -EFAULT;
		goto out_free;
	}

	drm_rects = (struct drm_rect *)rects;

	for (i = 0; i < arg->num_outputs; i++) {
		struct drm_vmw_rect curr_rect;

		/* Verify user-space for overflow as kernel use drm_rect */
		if ((rects[i].x + rects[i].w > INT_MAX) ||
		    (rects[i].y + rects[i].h > INT_MAX)) {
			ret = -ERANGE;
			goto out_free;
		}

		curr_rect = rects[i];
		drm_rects[i].x1 = curr_rect.x;
		drm_rects[i].y1 = curr_rect.y;
		drm_rects[i].x2 = curr_rect.x + curr_rect.w;
		drm_rects[i].y2 = curr_rect.y + curr_rect.h;

		/*
		 * Currently this check is limiting the topology within
		 * mode_config->max (which actually is max texture size
		 * supported by virtual device). This limit is here to address
		 * window managers that create a big framebuffer for whole
		 * topology.
		 */
		if (drm_rects[i].x1 < 0 ||  drm_rects[i].y1 < 0 ||
		    drm_rects[i].x2 > mode_config->max_width ||
		    drm_rects[i].y2 > mode_config->max_height) {
			DRM_ERROR("Invalid GUI layout.\n");
			ret = -EINVAL;
			goto out_free;
		}
	}

	ret = vmw_kms_check_display_memory(dev, arg->num_outputs, drm_rects);

	if (ret == 0)
		vmw_du_update_layout(dev_priv, arg->num_outputs, drm_rects);

out_free:
	kfree(rects);
	return ret;
}

/**
 * vmw_kms_helper_dirty - Helper to build commands and perform actions based
 * on a set of cliprects and a set of display units.
 *
 * @dev_priv: Pointer to a device private structure.
 * @framebuffer: Pointer to the framebuffer on which to perform the actions.
 * @clips: A set of struct drm_clip_rect. Either this os @vclips must be NULL.
 * Cliprects are given in framebuffer coordinates.
 * @vclips: A set of struct drm_vmw_rect cliprects. Either this or @clips must
 * be NULL. Cliprects are given in source coordinates.
 * @dest_x: X coordinate offset for the crtc / destination clip rects.
 * @dest_y: Y coordinate offset for the crtc / destination clip rects.
 * @num_clips: Number of cliprects in the @clips or @vclips array.
 * @increment: Integer with which to increment the clip counter when looping.
 * Used to skip a predetermined number of clip rects.
 * @dirty: Closure structure. See the description of struct vmw_kms_dirty.
 */
int vmw_kms_helper_dirty(struct vmw_private *dev_priv,
			 struct vmw_framebuffer *framebuffer,
			 const struct drm_clip_rect *clips,
			 const struct drm_vmw_rect *vclips,
			 s32 dest_x, s32 dest_y,
			 int num_clips,
			 int increment,
			 struct vmw_kms_dirty *dirty)
{
	struct vmw_display_unit *units[VMWGFX_NUM_DISPLAY_UNITS];
	struct drm_crtc *crtc;
	u32 num_units = 0;
	u32 i, k;

	dirty->dev_priv = dev_priv;

	/* If crtc is passed, no need to iterate over other display units */
	if (dirty->crtc) {
		units[num_units++] = vmw_crtc_to_du(dirty->crtc);
	} else {
		list_for_each_entry(crtc, &dev_priv->dev->mode_config.crtc_list,
				    head) {
			struct drm_plane *plane = crtc->primary;

			if (plane->state->fb == &framebuffer->base)
				units[num_units++] = vmw_crtc_to_du(crtc);
		}
	}

	for (k = 0; k < num_units; k++) {
		struct vmw_display_unit *unit = units[k];
		s32 crtc_x = unit->crtc.x;
		s32 crtc_y = unit->crtc.y;
		s32 crtc_width = unit->crtc.mode.hdisplay;
		s32 crtc_height = unit->crtc.mode.vdisplay;
		const struct drm_clip_rect *clips_ptr = clips;
		const struct drm_vmw_rect *vclips_ptr = vclips;

		dirty->unit = unit;
		if (dirty->fifo_reserve_size > 0) {
			dirty->cmd = vmw_fifo_reserve(dev_priv,
						      dirty->fifo_reserve_size);
			if (!dirty->cmd) {
				DRM_ERROR("Couldn't reserve fifo space "
					  "for dirty blits.\n");
				return -ENOMEM;
			}
			memset(dirty->cmd, 0, dirty->fifo_reserve_size);
		}
		dirty->num_hits = 0;
		for (i = 0; i < num_clips; i++, clips_ptr += increment,
		       vclips_ptr += increment) {
			s32 clip_left;
			s32 clip_top;

			/*
			 * Select clip array type. Note that integer type
			 * in @clips is unsigned short, whereas in @vclips
			 * it's 32-bit.
			 */
			if (clips) {
				dirty->fb_x = (s32) clips_ptr->x1;
				dirty->fb_y = (s32) clips_ptr->y1;
				dirty->unit_x2 = (s32) clips_ptr->x2 + dest_x -
					crtc_x;
				dirty->unit_y2 = (s32) clips_ptr->y2 + dest_y -
					crtc_y;
			} else {
				dirty->fb_x = vclips_ptr->x;
				dirty->fb_y = vclips_ptr->y;
				dirty->unit_x2 = dirty->fb_x + vclips_ptr->w +
					dest_x - crtc_x;
				dirty->unit_y2 = dirty->fb_y + vclips_ptr->h +
					dest_y - crtc_y;
			}

			dirty->unit_x1 = dirty->fb_x + dest_x - crtc_x;
			dirty->unit_y1 = dirty->fb_y + dest_y - crtc_y;

			/* Skip this clip if it's outside the crtc region */
			if (dirty->unit_x1 >= crtc_width ||
			    dirty->unit_y1 >= crtc_height ||
			    dirty->unit_x2 <= 0 || dirty->unit_y2 <= 0)
				continue;

			/* Clip right and bottom to crtc limits */
			dirty->unit_x2 = min_t(s32, dirty->unit_x2,
					       crtc_width);
			dirty->unit_y2 = min_t(s32, dirty->unit_y2,
					       crtc_height);

			/* Clip left and top to crtc limits */
			clip_left = min_t(s32, dirty->unit_x1, 0);
			clip_top = min_t(s32, dirty->unit_y1, 0);
			dirty->unit_x1 -= clip_left;
			dirty->unit_y1 -= clip_top;
			dirty->fb_x -= clip_left;
			dirty->fb_y -= clip_top;

			dirty->clip(dirty);
		}

		dirty->fifo_commit(dirty);
	}

	return 0;
}

/**
 * vmw_kms_helper_buffer_prepare - Reserve and validate a buffer object before
 * command submission.
 *
 * @dev_priv. Pointer to a device private structure.
 * @buf: The buffer object
 * @interruptible: Whether to perform waits as interruptible.
 * @validate_as_mob: Whether the buffer should be validated as a MOB. If false,
 * The buffer will be validated as a GMR. Already pinned buffers will not be
 * validated.
 *
 * Returns 0 on success, negative error code on failure, -ERESTARTSYS if
 * interrupted by a signal.
 */
int vmw_kms_helper_buffer_prepare(struct vmw_private *dev_priv,
				  struct vmw_buffer_object *buf,
				  bool interruptible,
				  bool validate_as_mob,
				  bool for_cpu_blit)
{
	struct ttm_operation_ctx ctx = {
		.interruptible = interruptible,
		.no_wait_gpu = false};
	struct ttm_buffer_object *bo = &buf->base;
	int ret;

	ttm_bo_reserve(bo, false, false, NULL);
	if (for_cpu_blit)
		ret = ttm_bo_validate(bo, &vmw_nonfixed_placement, &ctx);
	else
		ret = vmw_validate_single_buffer(dev_priv, bo, interruptible,
						 validate_as_mob);
	if (ret)
		ttm_bo_unreserve(bo);

	return ret;
}

/**
 * vmw_kms_helper_buffer_revert - Undo the actions of
 * vmw_kms_helper_buffer_prepare.
 *
 * @res: Pointer to the buffer object.
 *
 * Helper to be used if an error forces the caller to undo the actions of
 * vmw_kms_helper_buffer_prepare.
 */
void vmw_kms_helper_buffer_revert(struct vmw_buffer_object *buf)
{
	if (buf)
		ttm_bo_unreserve(&buf->base);
}

/**
 * vmw_kms_helper_buffer_finish - Unreserve and fence a buffer object after
 * kms command submission.
 *
 * @dev_priv: Pointer to a device private structure.
 * @file_priv: Pointer to a struct drm_file representing the caller's
 * connection. Must be set to NULL if @user_fence_rep is NULL, and conversely
 * if non-NULL, @user_fence_rep must be non-NULL.
 * @buf: The buffer object.
 * @out_fence:  Optional pointer to a fence pointer. If non-NULL, a
 * ref-counted fence pointer is returned here.
 * @user_fence_rep: Optional pointer to a user-space provided struct
 * drm_vmw_fence_rep. If provided, @file_priv must also be provided and the
 * function copies fence data to user-space in a fail-safe manner.
 */
void vmw_kms_helper_buffer_finish(struct vmw_private *dev_priv,
				  struct drm_file *file_priv,
				  struct vmw_buffer_object *buf,
				  struct vmw_fence_obj **out_fence,
				  struct drm_vmw_fence_rep __user *
				  user_fence_rep)
{
	struct vmw_fence_obj *fence;
	uint32_t handle;
	int ret;

	ret = vmw_execbuf_fence_commands(file_priv, dev_priv, &fence,
					 file_priv ? &handle : NULL);
	if (buf)
		vmw_bo_fence_single(&buf->base, fence);
	if (file_priv)
		vmw_execbuf_copy_fence_user(dev_priv, vmw_fpriv(file_priv),
					    ret, user_fence_rep, fence,
					    handle, -1);
	if (out_fence)
		*out_fence = fence;
	else
		vmw_fence_obj_unreference(&fence);

	vmw_kms_helper_buffer_revert(buf);
}


/**
 * vmw_kms_helper_resource_revert - Undo the actions of
 * vmw_kms_helper_resource_prepare.
 *
 * @res: Pointer to the resource. Typically a surface.
 *
 * Helper to be used if an error forces the caller to undo the actions of
 * vmw_kms_helper_resource_prepare.
 */
void vmw_kms_helper_resource_revert(struct vmw_validation_ctx *ctx)
{
	struct vmw_resource *res = ctx->res;

	vmw_kms_helper_buffer_revert(ctx->buf);
	vmw_bo_unreference(&ctx->buf);
	vmw_resource_unreserve(res, false, NULL, 0);
	mutex_unlock(&res->dev_priv->cmdbuf_mutex);
}

/**
 * vmw_kms_helper_resource_prepare - Reserve and validate a resource before
 * command submission.
 *
 * @res: Pointer to the resource. Typically a surface.
 * @interruptible: Whether to perform waits as interruptible.
 *
 * Reserves and validates also the backup buffer if a guest-backed resource.
 * Returns 0 on success, negative error code on failure. -ERESTARTSYS if
 * interrupted by a signal.
 */
int vmw_kms_helper_resource_prepare(struct vmw_resource *res,
				    bool interruptible,
				    struct vmw_validation_ctx *ctx)
{
	int ret = 0;

	ctx->buf = NULL;
	ctx->res = res;

	if (interruptible)
		ret = mutex_lock_interruptible(&res->dev_priv->cmdbuf_mutex);
	else
		mutex_lock(&res->dev_priv->cmdbuf_mutex);

	if (unlikely(ret != 0))
		return -ERESTARTSYS;

	ret = vmw_resource_reserve(res, interruptible, false);
	if (ret)
		goto out_unlock;

	if (res->backup) {
		ret = vmw_kms_helper_buffer_prepare(res->dev_priv, res->backup,
						    interruptible,
						    res->dev_priv->has_mob,
						    false);
		if (ret)
			goto out_unreserve;

		ctx->buf = vmw_bo_reference(res->backup);
	}
	ret = vmw_resource_validate(res);
	if (ret)
		goto out_revert;
	return 0;

out_revert:
	vmw_kms_helper_buffer_revert(ctx->buf);
out_unreserve:
	vmw_resource_unreserve(res, false, NULL, 0);
out_unlock:
	mutex_unlock(&res->dev_priv->cmdbuf_mutex);
	return ret;
}

/**
 * vmw_kms_helper_resource_finish - Unreserve and fence a resource after
 * kms command submission.
 *
 * @res: Pointer to the resource. Typically a surface.
 * @out_fence: Optional pointer to a fence pointer. If non-NULL, a
 * ref-counted fence pointer is returned here.
 */
void vmw_kms_helper_resource_finish(struct vmw_validation_ctx *ctx,
				    struct vmw_fence_obj **out_fence)
{
	struct vmw_resource *res = ctx->res;

	if (ctx->buf || out_fence)
		vmw_kms_helper_buffer_finish(res->dev_priv, NULL, ctx->buf,
					     out_fence, NULL);

	vmw_bo_unreference(&ctx->buf);
	vmw_resource_unreserve(res, false, NULL, 0);
	mutex_unlock(&res->dev_priv->cmdbuf_mutex);
}

/**
 * vmw_kms_update_proxy - Helper function to update a proxy surface from
 * its backing MOB.
 *
 * @res: Pointer to the surface resource
 * @clips: Clip rects in framebuffer (surface) space.
 * @num_clips: Number of clips in @clips.
 * @increment: Integer with which to increment the clip counter when looping.
 * Used to skip a predetermined number of clip rects.
 *
 * This function makes sure the proxy surface is updated from its backing MOB
 * using the region given by @clips. The surface resource @res and its backing
 * MOB needs to be reserved and validated on call.
 */
int vmw_kms_update_proxy(struct vmw_resource *res,
			 const struct drm_clip_rect *clips,
			 unsigned num_clips,
			 int increment)
{
	struct vmw_private *dev_priv = res->dev_priv;
	struct drm_vmw_size *size = &vmw_res_to_srf(res)->base_size;
	struct {
		SVGA3dCmdHeader header;
		SVGA3dCmdUpdateGBImage body;
	} *cmd;
	SVGA3dBox *box;
	size_t copy_size = 0;
	int i;

	if (!clips)
		return 0;

	cmd = vmw_fifo_reserve(dev_priv, sizeof(*cmd) * num_clips);
	if (!cmd) {
		DRM_ERROR("Couldn't reserve fifo space for proxy surface "
			  "update.\n");
		return -ENOMEM;
	}

	for (i = 0; i < num_clips; ++i, clips += increment, ++cmd) {
		box = &cmd->body.box;

		cmd->header.id = SVGA_3D_CMD_UPDATE_GB_IMAGE;
		cmd->header.size = sizeof(cmd->body);
		cmd->body.image.sid = res->id;
		cmd->body.image.face = 0;
		cmd->body.image.mipmap = 0;

		if (clips->x1 > size->width || clips->x2 > size->width ||
		    clips->y1 > size->height || clips->y2 > size->height) {
			DRM_ERROR("Invalid clips outsize of framebuffer.\n");
			return -EINVAL;
		}

		box->x = clips->x1;
		box->y = clips->y1;
		box->z = 0;
		box->w = clips->x2 - clips->x1;
		box->h = clips->y2 - clips->y1;
		box->d = 1;

		copy_size += sizeof(*cmd);
	}

	vmw_fifo_commit(dev_priv, copy_size);

	return 0;
}

int vmw_kms_fbdev_init_data(struct vmw_private *dev_priv,
			    unsigned unit,
			    u32 max_width,
			    u32 max_height,
			    struct drm_connector **p_con,
			    struct drm_crtc **p_crtc,
			    struct drm_display_mode **p_mode)
{
	struct drm_connector *con;
	struct vmw_display_unit *du;
	struct drm_display_mode *mode;
	int i = 0;
	int ret = 0;

	mutex_lock(&dev_priv->dev->mode_config.mutex);
	list_for_each_entry(con, &dev_priv->dev->mode_config.connector_list,
			    head) {
		if (i == unit)
			break;

		++i;
	}

	if (&con->head == &dev_priv->dev->mode_config.connector_list) {
		DRM_ERROR("Could not find initial display unit.\n");
		ret = -EINVAL;
		goto out_unlock;
	}

	if (list_empty(&con->modes))
		(void) vmw_du_connector_fill_modes(con, max_width, max_height);

	if (list_empty(&con->modes)) {
		DRM_ERROR("Could not find initial display mode.\n");
		ret = -EINVAL;
		goto out_unlock;
	}

	du = vmw_connector_to_du(con);
	*p_con = con;
	*p_crtc = &du->crtc;

	list_for_each_entry(mode, &con->modes, head) {
		if (mode->type & DRM_MODE_TYPE_PREFERRED)
			break;
	}

	if (&mode->head == &con->modes) {
		WARN_ONCE(true, "Could not find initial preferred mode.\n");
		*p_mode = list_first_entry(&con->modes,
					   struct drm_display_mode,
					   head);
	} else {
		*p_mode = mode;
	}

 out_unlock:
	mutex_unlock(&dev_priv->dev->mode_config.mutex);

	return ret;
}

/**
 * vmw_kms_del_active - unregister a crtc binding to the implicit framebuffer
 *
 * @dev_priv: Pointer to a device private struct.
 * @du: The display unit of the crtc.
 */
void vmw_kms_del_active(struct vmw_private *dev_priv,
			struct vmw_display_unit *du)
{
	mutex_lock(&dev_priv->global_kms_state_mutex);
	if (du->active_implicit) {
		if (--(dev_priv->num_implicit) == 0)
			dev_priv->implicit_fb = NULL;
		du->active_implicit = false;
	}
	mutex_unlock(&dev_priv->global_kms_state_mutex);
}

/**
 * vmw_kms_add_active - register a crtc binding to an implicit framebuffer
 *
 * @vmw_priv: Pointer to a device private struct.
 * @du: The display unit of the crtc.
 * @vfb: The implicit framebuffer
 *
 * Registers a binding to an implicit framebuffer.
 */
void vmw_kms_add_active(struct vmw_private *dev_priv,
			struct vmw_display_unit *du,
			struct vmw_framebuffer *vfb)
{
	mutex_lock(&dev_priv->global_kms_state_mutex);
	WARN_ON_ONCE(!dev_priv->num_implicit && dev_priv->implicit_fb);

	if (!du->active_implicit && du->is_implicit) {
		dev_priv->implicit_fb = vfb;
		du->active_implicit = true;
		dev_priv->num_implicit++;
	}
	mutex_unlock(&dev_priv->global_kms_state_mutex);
}

/**
 * vmw_kms_screen_object_flippable - Check whether we can page-flip a crtc.
 *
 * @dev_priv: Pointer to device-private struct.
 * @crtc: The crtc we want to flip.
 *
 * Returns true or false depending whether it's OK to flip this crtc
 * based on the criterion that we must not have more than one implicit
 * frame-buffer at any one time.
 */
bool vmw_kms_crtc_flippable(struct vmw_private *dev_priv,
			    struct drm_crtc *crtc)
{
	struct vmw_display_unit *du = vmw_crtc_to_du(crtc);
	bool ret;

	mutex_lock(&dev_priv->global_kms_state_mutex);
	ret = !du->is_implicit || dev_priv->num_implicit == 1;
	mutex_unlock(&dev_priv->global_kms_state_mutex);

	return ret;
}

/**
 * vmw_kms_update_implicit_fb - Update the implicit fb.
 *
 * @dev_priv: Pointer to device-private struct.
 * @crtc: The crtc the new implicit frame-buffer is bound to.
 */
void vmw_kms_update_implicit_fb(struct vmw_private *dev_priv,
				struct drm_crtc *crtc)
{
	struct vmw_display_unit *du = vmw_crtc_to_du(crtc);
	struct drm_plane *plane = crtc->primary;
	struct vmw_framebuffer *vfb;

	mutex_lock(&dev_priv->global_kms_state_mutex);

	if (!du->is_implicit)
		goto out_unlock;

	vfb = vmw_framebuffer_to_vfb(plane->state->fb);
	WARN_ON_ONCE(dev_priv->num_implicit != 1 &&
		     dev_priv->implicit_fb != vfb);

	dev_priv->implicit_fb = vfb;
out_unlock:
	mutex_unlock(&dev_priv->global_kms_state_mutex);
}

/**
 * vmw_kms_create_implicit_placement_proparty - Set up the implicit placement
 * property.
 *
 * @dev_priv: Pointer to a device private struct.
 * @immutable: Whether the property is immutable.
 *
 * Sets up the implicit placement property unless it's already set up.
 */
void
vmw_kms_create_implicit_placement_property(struct vmw_private *dev_priv,
					   bool immutable)
{
	if (dev_priv->implicit_placement_property)
		return;

	dev_priv->implicit_placement_property =
		drm_property_create_range(dev_priv->dev,
					  immutable ?
					  DRM_MODE_PROP_IMMUTABLE : 0,
					  "implicit_placement", 0, 1);

}


/**
 * vmw_kms_set_config - Wrapper around drm_atomic_helper_set_config
 *
 * @set: The configuration to set.
 *
 * The vmwgfx Xorg driver doesn't assign the mode::type member, which
 * when drm_mode_set_crtcinfo is called as part of the configuration setting
 * causes it to return incorrect crtc dimensions causing severe problems in
 * the vmwgfx modesetting. So explicitly clear that member before calling
 * into drm_atomic_helper_set_config.
 */
int vmw_kms_set_config(struct drm_mode_set *set,
		       struct drm_modeset_acquire_ctx *ctx)
{
	if (set && set->mode)
		set->mode->type = 0;

	return drm_atomic_helper_set_config(set, ctx);
}


/**
 * vmw_kms_suspend - Save modesetting state and turn modesetting off.
 *
 * @dev: Pointer to the drm device
 * Return: 0 on success. Negative error code on failure.
 */
int vmw_kms_suspend(struct drm_device *dev)
{
	struct vmw_private *dev_priv = vmw_priv(dev);

	dev_priv->suspend_state = drm_atomic_helper_suspend(dev);
	if (IS_ERR(dev_priv->suspend_state)) {
		int ret = PTR_ERR(dev_priv->suspend_state);

		DRM_ERROR("Failed kms suspend: %d\n", ret);
		dev_priv->suspend_state = NULL;

		return ret;
	}

	return 0;
}


/**
 * vmw_kms_resume - Re-enable modesetting and restore state
 *
 * @dev: Pointer to the drm device
 * Return: 0 on success. Negative error code on failure.
 *
 * State is resumed from a previous vmw_kms_suspend(). It's illegal
 * to call this function without a previous vmw_kms_suspend().
 */
int vmw_kms_resume(struct drm_device *dev)
{
	struct vmw_private *dev_priv = vmw_priv(dev);
	int ret;

	if (WARN_ON(!dev_priv->suspend_state))
		return 0;

	ret = drm_atomic_helper_resume(dev, dev_priv->suspend_state);
	dev_priv->suspend_state = NULL;

	return ret;
}

/**
 * vmw_kms_lost_device - Notify kms that modesetting capabilities will be lost
 *
 * @dev: Pointer to the drm device
 */
void vmw_kms_lost_device(struct drm_device *dev)
{
	drm_atomic_helper_shutdown(dev);
}
