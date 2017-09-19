/*
 * Copyright 2015 Freescale Semiconductor, Inc.
 *
 * Freescale DCU drm device driver
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/backlight.h>
#include <linux/of_graph.h>

#include <drm/drmP.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_of.h>
#include <drm/drm_panel.h>

#include "fsl_dcu_drm_drv.h"
#include "fsl_tcon.h"

static void fsl_dcu_drm_encoder_destroy(struct drm_encoder *encoder)
{
	drm_encoder_cleanup(encoder);
}

static const struct drm_encoder_funcs encoder_funcs = {
	.destroy = fsl_dcu_drm_encoder_destroy,
};

int fsl_dcu_drm_encoder_create(struct fsl_dcu_drm_device *fsl_dev,
			       struct drm_crtc *crtc)
{
	struct drm_encoder *encoder = &fsl_dev->encoder;
	int ret;

	encoder->possible_crtcs = 1;

	/* Use bypass mode for parallel RGB/LVDS encoder */
	if (fsl_dev->tcon)
		fsl_tcon_bypass_enable(fsl_dev->tcon);

	ret = drm_encoder_init(fsl_dev->drm, encoder, &encoder_funcs,
			       DRM_MODE_ENCODER_LVDS, NULL);
	if (ret < 0)
		return ret;

	return 0;
}

static void fsl_dcu_drm_connector_destroy(struct drm_connector *connector)
{
	struct fsl_dcu_drm_connector *fsl_con = to_fsl_dcu_connector(connector);

	drm_connector_unregister(connector);
	drm_panel_detach(fsl_con->panel);
	drm_connector_cleanup(connector);
}

static const struct drm_connector_funcs fsl_dcu_drm_connector_funcs = {
	.atomic_duplicate_state = drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_connector_destroy_state,
	.destroy = fsl_dcu_drm_connector_destroy,
	.dpms = drm_atomic_helper_connector_dpms,
	.fill_modes = drm_helper_probe_single_connector_modes,
	.reset = drm_atomic_helper_connector_reset,
};

static int fsl_dcu_drm_connector_get_modes(struct drm_connector *connector)
{
	struct fsl_dcu_drm_connector *fsl_connector;
	int (*get_modes)(struct drm_panel *panel);
	int num_modes = 0;

	fsl_connector = to_fsl_dcu_connector(connector);
	if (fsl_connector->panel && fsl_connector->panel->funcs &&
	    fsl_connector->panel->funcs->get_modes) {
		get_modes = fsl_connector->panel->funcs->get_modes;
		num_modes = get_modes(fsl_connector->panel);
	}

	return num_modes;
}

static int fsl_dcu_drm_connector_mode_valid(struct drm_connector *connector,
					    struct drm_display_mode *mode)
{
	if (mode->hdisplay & 0xf)
		return MODE_ERROR;

	return MODE_OK;
}

static const struct drm_connector_helper_funcs connector_helper_funcs = {
	.get_modes = fsl_dcu_drm_connector_get_modes,
	.mode_valid = fsl_dcu_drm_connector_mode_valid,
};

static int fsl_dcu_attach_panel(struct fsl_dcu_drm_device *fsl_dev,
				 struct drm_panel *panel)
{
	struct drm_encoder *encoder = &fsl_dev->encoder;
	struct drm_connector *connector = &fsl_dev->connector.base;
	struct drm_mode_config *mode_config = &fsl_dev->drm->mode_config;
	int ret;

	fsl_dev->connector.encoder = encoder;

	ret = drm_connector_init(fsl_dev->drm, connector,
				 &fsl_dcu_drm_connector_funcs,
				 DRM_MODE_CONNECTOR_LVDS);
	if (ret < 0)
		return ret;

	drm_connector_helper_add(connector, &connector_helper_funcs);
	ret = drm_connector_register(connector);
	if (ret < 0)
		goto err_cleanup;

	ret = drm_mode_connector_attach_encoder(connector, encoder);
	if (ret < 0)
		goto err_sysfs;

	drm_object_property_set_value(&connector->base,
				      mode_config->dpms_property,
				      DRM_MODE_DPMS_OFF);

	ret = drm_panel_attach(panel, connector);
	if (ret) {
		dev_err(fsl_dev->dev, "failed to attach panel\n");
		goto err_sysfs;
	}

	return 0;

err_sysfs:
	drm_connector_unregister(connector);
err_cleanup:
	drm_connector_cleanup(connector);
	return ret;
}

int fsl_dcu_create_outputs(struct fsl_dcu_drm_device *fsl_dev)
{
	struct device_node *panel_node;
	struct drm_panel *panel;
	struct drm_bridge *bridge;
	int ret;

	/* This is for backward compatibility */
	panel_node = of_parse_phandle(fsl_dev->np, "fsl,panel", 0);
	if (panel_node) {
		fsl_dev->connector.panel = of_drm_find_panel(panel_node);
		of_node_put(panel_node);
		if (!fsl_dev->connector.panel)
			return -EPROBE_DEFER;
		return fsl_dcu_attach_panel(fsl_dev, fsl_dev->connector.panel);
	}

	ret = drm_of_find_panel_or_bridge(fsl_dev->np, 0, 0, &panel, &bridge);
	if (ret)
		return ret;

	if (panel) {
		fsl_dev->connector.panel = panel;
		return fsl_dcu_attach_panel(fsl_dev, panel);
	}

	return drm_bridge_attach(&fsl_dev->encoder, bridge, NULL);
}
