// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019, Huaqin Telecom Technology Co., Ltd
 *
 * Author: Jerry Han <jerry.han.hq@gmail.com>
 *
 */

#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>

#include <linux/gpio/consumer.h>
#include <linux/regulator/consumer.h>

#include <drm/drm_device.h>
#include <drm/drm_mipi_dsi.h>
#include <drm/drm_modes.h>
#include <drm/drm_panel.h>

#include <video/mipi_display.h>

struct panel_cmd {
	char cmd;
	char data;
};

struct panel_desc {
	const struct drm_display_mode *display_mode;
	unsigned int bpc;
	unsigned int width_mm;
	unsigned int height_mm;

	unsigned long mode_flags;
	enum mipi_dsi_pixel_format format;
	unsigned int lanes;
	const struct panel_cmd *on_cmds;
	unsigned int on_cmds_num;
};

struct panel_info {
	struct drm_panel base;
	struct mipi_dsi_device *link;
	const struct panel_desc *desc;

	struct gpio_desc *enable_gpio;
	struct gpio_desc *pp33_gpio;
	struct gpio_desc *pp18_gpio;

	bool prepared;
	bool enabled;
};

static inline struct panel_info *to_panel_info(struct drm_panel *panel)
{
	return container_of(panel, struct panel_info, base);
}

static void disable_gpios(struct panel_info *pinfo)
{
	gpiod_set_value(pinfo->enable_gpio, 0);
	gpiod_set_value(pinfo->pp33_gpio, 0);
	gpiod_set_value(pinfo->pp18_gpio, 0);
}

static int send_mipi_cmds(struct drm_panel *panel, const struct panel_cmd *cmds)
{
	struct panel_info *pinfo = to_panel_info(panel);
	unsigned int i = 0;
	int err;

	for (i = 0; i < pinfo->desc->on_cmds_num; i++) {
		err = mipi_dsi_dcs_write_buffer(pinfo->link, &cmds[i],
						sizeof(struct panel_cmd));

		if (err < 0)
			return err;
	}

	return 0;
}

static int boe_panel_disable(struct drm_panel *panel)
{
	struct panel_info *pinfo = to_panel_info(panel);
	int err;

	if (!pinfo->enabled)
		return 0;

	err = mipi_dsi_dcs_set_display_off(pinfo->link);
	if (err < 0) {
		dev_err(panel->dev, "failed to set display off: %d\n", err);
		return err;
	}

	pinfo->enabled = false;

	return 0;
}

static int boe_panel_unprepare(struct drm_panel *panel)
{
	struct panel_info *pinfo = to_panel_info(panel);
	int err;

	if (!pinfo->prepared)
		return 0;

	err = mipi_dsi_dcs_set_display_off(pinfo->link);
	if (err < 0)
		dev_err(panel->dev, "failed to set display off: %d\n", err);

	err = mipi_dsi_dcs_enter_sleep_mode(pinfo->link);
	if (err < 0)
		dev_err(panel->dev, "failed to enter sleep mode: %d\n", err);

	/* sleep_mode_delay: 1ms - 2ms */
	usleep_range(1000, 2000);

	disable_gpios(pinfo);

	pinfo->prepared = false;

	return 0;
}

static int boe_panel_prepare(struct drm_panel *panel)
{
	struct panel_info *pinfo = to_panel_info(panel);
	int err;

	if (pinfo->prepared)
		return 0;

	gpiod_set_value(pinfo->pp18_gpio, 1);
	/* T1: 5ms - 6ms */
	usleep_range(5000, 6000);
	gpiod_set_value(pinfo->pp33_gpio, 1);

	/* reset sequence */
	/* T2: 14ms - 15ms */
	usleep_range(14000, 15000);
	gpiod_set_value(pinfo->enable_gpio, 1);

	/* T3: 1ms - 2ms */
	usleep_range(1000, 2000);
	gpiod_set_value(pinfo->enable_gpio, 0);

	/* T4: 1ms - 2ms */
	usleep_range(1000, 2000);
	gpiod_set_value(pinfo->enable_gpio, 1);

	/* T5: 5ms - 6ms */
	usleep_range(5000, 6000);

	/* send init code */
	err = send_mipi_cmds(panel, pinfo->desc->on_cmds);
	if (err < 0) {
		dev_err(panel->dev, "failed to send DCS Init Code: %d\n", err);
		goto poweroff;
	}

	err = mipi_dsi_dcs_exit_sleep_mode(pinfo->link);
	if (err < 0) {
		dev_err(panel->dev, "failed to exit sleep mode: %d\n", err);
		goto poweroff;
	}

	/* T6: 120ms - 121ms */
	usleep_range(120000, 121000);

	err = mipi_dsi_dcs_set_display_on(pinfo->link);
	if (err < 0) {
		dev_err(panel->dev, "failed to set display on: %d\n", err);
		goto poweroff;
	}

	/* T7: 20ms - 21ms */
	usleep_range(20000, 21000);

	pinfo->prepared = true;

	return 0;

poweroff:
	disable_gpios(pinfo);
	return err;
}

static int boe_panel_enable(struct drm_panel *panel)
{
	struct panel_info *pinfo = to_panel_info(panel);
	int ret;

	if (pinfo->enabled)
		return 0;

	usleep_range(120000, 121000);

	ret = mipi_dsi_dcs_set_display_on(pinfo->link);
	if (ret < 0) {
		dev_err(panel->dev, "failed to set display on: %d\n", ret);
		return ret;
	}

	pinfo->enabled = true;

	return 0;
}

static int boe_panel_get_modes(struct drm_panel *panel,
			       struct drm_connector *connector)
{
	struct panel_info *pinfo = to_panel_info(panel);
	const struct drm_display_mode *m = pinfo->desc->display_mode;
	struct drm_display_mode *mode;

	mode = drm_mode_duplicate(connector->dev, m);
	if (!mode) {
		dev_err(pinfo->base.dev, "failed to add mode %ux%u@%u\n",
			m->hdisplay, m->vdisplay, drm_mode_vrefresh(m));
		return -ENOMEM;
	}

	drm_mode_set_name(mode);

	drm_mode_probed_add(connector, mode);

	connector->display_info.width_mm = pinfo->desc->width_mm;
	connector->display_info.height_mm = pinfo->desc->height_mm;
	connector->display_info.bpc = pinfo->desc->bpc;

	return 1;
}

static const struct drm_panel_funcs panel_funcs = {
	.disable = boe_panel_disable,
	.unprepare = boe_panel_unprepare,
	.prepare = boe_panel_prepare,
	.enable = boe_panel_enable,
	.get_modes = boe_panel_get_modes,
};

static const struct drm_display_mode default_display_mode = {
	.clock = 159420,
	.hdisplay = 1200,
	.hsync_start = 1200 + 80,
	.hsync_end = 1200 + 80 + 60,
	.htotal = 1200 + 80 + 60 + 24,
	.vdisplay = 1920,
	.vsync_start = 1920 + 10,
	.vsync_end = 1920 + 10 + 14,
	.vtotal = 1920 + 10 + 14 + 4,
};

/* 8 inch */
static const struct panel_cmd boe_himax8279d8p_on_cmds[] = {
	{ 0xB0, 0x05 },
	{ 0xB1, 0xE5 },
	{ 0xB3, 0x52 },
	{ 0xC0, 0x00 },
	{ 0xC2, 0x57 },
	{ 0xD9, 0x85 },
	{ 0xB0, 0x01 },
	{ 0xC8, 0x00 },
	{ 0xC9, 0x00 },
	{ 0xCC, 0x26 },
	{ 0xCD, 0x26 },
	{ 0xDC, 0x00 },
	{ 0xDD, 0x00 },
	{ 0xE0, 0x26 },
	{ 0xE1, 0x26 },
	{ 0xB0, 0x03 },
	{ 0xC3, 0x2A },
	{ 0xE7, 0x2A },
	{ 0xC5, 0x2A },
	{ 0xDE, 0x2A },
	{ 0xBC, 0x02 },
	{ 0xCB, 0x02 },
	{ 0xB0, 0x00 },
	{ 0xB6, 0x03 },
	{ 0xBA, 0x8B },
	{ 0xBF, 0x15 },
	{ 0xC0, 0x18 },
	{ 0xC2, 0x14 },
	{ 0xC3, 0x02 },
	{ 0xC4, 0x14 },
	{ 0xC5, 0x02 },
	{ 0xCC, 0x0A },
	{ 0xB0, 0x06 },
	{ 0xC0, 0xA5 },
	{ 0xD5, 0x20 },
	{ 0xC0, 0x00 },
	{ 0xB0, 0x02 },
	{ 0xC0, 0x00 },
	{ 0xC1, 0x02 },
	{ 0xC2, 0x06 },
	{ 0xC3, 0x16 },
	{ 0xC4, 0x0E },
	{ 0xC5, 0x18 },
	{ 0xC6, 0x26 },
	{ 0xC7, 0x32 },
	{ 0xC8, 0x3F },
	{ 0xC9, 0x3F },
	{ 0xCA, 0x3F },
	{ 0xCB, 0x3F },
	{ 0xCC, 0x3D },
	{ 0xCD, 0x2F },
	{ 0xCE, 0x2F },
	{ 0xCF, 0x2F },
	{ 0xD0, 0x07 },
	{ 0xD2, 0x00 },
	{ 0xD3, 0x02 },
	{ 0xD4, 0x06 },
	{ 0xD5, 0x12 },
	{ 0xD6, 0x0A },
	{ 0xD7, 0x14 },
	{ 0xD8, 0x22 },
	{ 0xD9, 0x2E },
	{ 0xDA, 0x3D },
	{ 0xDB, 0x3F },
	{ 0xDC, 0x3F },
	{ 0xDD, 0x3F },
	{ 0xDE, 0x3D },
	{ 0xDF, 0x2F },
	{ 0xE0, 0x2F },
	{ 0xE1, 0x2F },
	{ 0xE2, 0x07 },
	{ 0xB0, 0x07 },
	{ 0xB1, 0x18 },
	{ 0xB2, 0x19 },
	{ 0xB3, 0x2E },
	{ 0xB4, 0x52 },
	{ 0xB5, 0x72 },
	{ 0xB6, 0x8C },
	{ 0xB7, 0xBD },
	{ 0xB8, 0xEB },
	{ 0xB9, 0x47 },
	{ 0xBA, 0x96 },
	{ 0xBB, 0x1E },
	{ 0xBC, 0x90 },
	{ 0xBD, 0x93 },
	{ 0xBE, 0xFA },
	{ 0xBF, 0x56 },
	{ 0xC0, 0x8C },
	{ 0xC1, 0xB7 },
	{ 0xC2, 0xCC },
	{ 0xC3, 0xDF },
	{ 0xC4, 0xE8 },
	{ 0xC5, 0xF0 },
	{ 0xC6, 0xF8 },
	{ 0xC7, 0xFA },
	{ 0xC8, 0xFC },
	{ 0xC9, 0x00 },
	{ 0xCA, 0x00 },
	{ 0xCB, 0x5A },
	{ 0xCC, 0xAF },
	{ 0xCD, 0xFF },
	{ 0xCE, 0xFF },
	{ 0xB0, 0x08 },
	{ 0xB1, 0x04 },
	{ 0xB2, 0x15 },
	{ 0xB3, 0x2D },
	{ 0xB4, 0x51 },
	{ 0xB5, 0x72 },
	{ 0xB6, 0x8D },
	{ 0xB7, 0xBE },
	{ 0xB8, 0xED },
	{ 0xB9, 0x4A },
	{ 0xBA, 0x9A },
	{ 0xBB, 0x23 },
	{ 0xBC, 0x95 },
	{ 0xBD, 0x98 },
	{ 0xBE, 0xFF },
	{ 0xBF, 0x59 },
	{ 0xC0, 0x8E },
	{ 0xC1, 0xB9 },
	{ 0xC2, 0xCD },
	{ 0xC3, 0xDF },
	{ 0xC4, 0xE8 },
	{ 0xC5, 0xF0 },
	{ 0xC6, 0xF8 },
	{ 0xC7, 0xFA },
	{ 0xC8, 0xFC },
	{ 0xC9, 0x00 },
	{ 0xCA, 0x00 },
	{ 0xCB, 0x5A },
	{ 0xCC, 0xAF },
	{ 0xCD, 0xFF },
	{ 0xCE, 0xFF },
	{ 0xB0, 0x09 },
	{ 0xB1, 0x04 },
	{ 0xB2, 0x2C },
	{ 0xB3, 0x36 },
	{ 0xB4, 0x53 },
	{ 0xB5, 0x73 },
	{ 0xB6, 0x8E },
	{ 0xB7, 0xC0 },
	{ 0xB8, 0xEF },
	{ 0xB9, 0x4C },
	{ 0xBA, 0x9D },
	{ 0xBB, 0x25 },
	{ 0xBC, 0x96 },
	{ 0xBD, 0x9A },
	{ 0xBE, 0x01 },
	{ 0xBF, 0x59 },
	{ 0xC0, 0x8E },
	{ 0xC1, 0xB9 },
	{ 0xC2, 0xCD },
	{ 0xC3, 0xDF },
	{ 0xC4, 0xE8 },
	{ 0xC5, 0xF0 },
	{ 0xC6, 0xF8 },
	{ 0xC7, 0xFA },
	{ 0xC8, 0xFC },
	{ 0xC9, 0x00 },
	{ 0xCA, 0x00 },
	{ 0xCB, 0x5A },
	{ 0xCC, 0xBF },
	{ 0xCD, 0xFF },
	{ 0xCE, 0xFF },
	{ 0xB0, 0x0A },
	{ 0xB1, 0x18 },
	{ 0xB2, 0x19 },
	{ 0xB3, 0x2E },
	{ 0xB4, 0x52 },
	{ 0xB5, 0x72 },
	{ 0xB6, 0x8C },
	{ 0xB7, 0xBD },
	{ 0xB8, 0xEB },
	{ 0xB9, 0x47 },
	{ 0xBA, 0x96 },
	{ 0xBB, 0x1E },
	{ 0xBC, 0x90 },
	{ 0xBD, 0x93 },
	{ 0xBE, 0xFA },
	{ 0xBF, 0x56 },
	{ 0xC0, 0x8C },
	{ 0xC1, 0xB7 },
	{ 0xC2, 0xCC },
	{ 0xC3, 0xDF },
	{ 0xC4, 0xE8 },
	{ 0xC5, 0xF0 },
	{ 0xC6, 0xF8 },
	{ 0xC7, 0xFA },
	{ 0xC8, 0xFC },
	{ 0xC9, 0x00 },
	{ 0xCA, 0x00 },
	{ 0xCB, 0x5A },
	{ 0xCC, 0xAF },
	{ 0xCD, 0xFF },
	{ 0xCE, 0xFF },
	{ 0xB0, 0x0B },
	{ 0xB1, 0x04 },
	{ 0xB2, 0x15 },
	{ 0xB3, 0x2D },
	{ 0xB4, 0x51 },
	{ 0xB5, 0x72 },
	{ 0xB6, 0x8D },
	{ 0xB7, 0xBE },
	{ 0xB8, 0xED },
	{ 0xB9, 0x4A },
	{ 0xBA, 0x9A },
	{ 0xBB, 0x23 },
	{ 0xBC, 0x95 },
	{ 0xBD, 0x98 },
	{ 0xBE, 0xFF },
	{ 0xBF, 0x59 },
	{ 0xC0, 0x8E },
	{ 0xC1, 0xB9 },
	{ 0xC2, 0xCD },
	{ 0xC3, 0xDF },
	{ 0xC4, 0xE8 },
	{ 0xC5, 0xF0 },
	{ 0xC6, 0xF8 },
	{ 0xC7, 0xFA },
	{ 0xC8, 0xFC },
	{ 0xC9, 0x00 },
	{ 0xCA, 0x00 },
	{ 0xCB, 0x5A },
	{ 0xCC, 0xAF },
	{ 0xCD, 0xFF },
	{ 0xCE, 0xFF },
	{ 0xB0, 0x0C },
	{ 0xB1, 0x04 },
	{ 0xB2, 0x2C },
	{ 0xB3, 0x36 },
	{ 0xB4, 0x53 },
	{ 0xB5, 0x73 },
	{ 0xB6, 0x8E },
	{ 0xB7, 0xC0 },
	{ 0xB8, 0xEF },
	{ 0xB9, 0x4C },
	{ 0xBA, 0x9D },
	{ 0xBB, 0x25 },
	{ 0xBC, 0x96 },
	{ 0xBD, 0x9A },
	{ 0xBE, 0x01 },
	{ 0xBF, 0x59 },
	{ 0xC0, 0x8E },
	{ 0xC1, 0xB9 },
	{ 0xC2, 0xCD },
	{ 0xC3, 0xDF },
	{ 0xC4, 0xE8 },
	{ 0xC5, 0xF0 },
	{ 0xC6, 0xF8 },
	{ 0xC7, 0xFA },
	{ 0xC8, 0xFC },
	{ 0xC9, 0x00 },
	{ 0xCA, 0x00 },
	{ 0xCB, 0x5A },
	{ 0xCC, 0xBF },
	{ 0xCD, 0xFF },
	{ 0xCE, 0xFF },
	{ 0xB0, 0x04 },
	{ 0xB5, 0x02 },
	{ 0xB6, 0x01 },
};

static const struct panel_desc boe_himax8279d8p_panel_desc = {
	.display_mode = &default_display_mode,
	.bpc = 8,
	.width_mm = 107,
	.height_mm = 172,
	.mode_flags = MIPI_DSI_MODE_VIDEO | MIPI_DSI_MODE_VIDEO_SYNC_PULSE |
			MIPI_DSI_CLOCK_NON_CONTINUOUS | MIPI_DSI_MODE_LPM,
	.format = MIPI_DSI_FMT_RGB888,
	.lanes = 4,
	.on_cmds = boe_himax8279d8p_on_cmds,
	.on_cmds_num = 260,
};

/* 10 inch */
static const struct panel_cmd boe_himax8279d10p_on_cmds[] = {
	{ 0xB0, 0x05 },
	{ 0xB1, 0xE5 },
	{ 0xB3, 0x52 },
	{ 0xB0, 0x00 },
	{ 0xB6, 0x03 },
	{ 0xBA, 0x8B },
	{ 0xBF, 0x1A },
	{ 0xC0, 0x0F },
	{ 0xC2, 0x0C },
	{ 0xC3, 0x02 },
	{ 0xC4, 0x0C },
	{ 0xC5, 0x02 },
	{ 0xB0, 0x01 },
	{ 0xE0, 0x26 },
	{ 0xE1, 0x26 },
	{ 0xDC, 0x00 },
	{ 0xDD, 0x00 },
	{ 0xCC, 0x26 },
	{ 0xCD, 0x26 },
	{ 0xC8, 0x00 },
	{ 0xC9, 0x00 },
	{ 0xD2, 0x03 },
	{ 0xD3, 0x03 },
	{ 0xE6, 0x04 },
	{ 0xE7, 0x04 },
	{ 0xC4, 0x09 },
	{ 0xC5, 0x09 },
	{ 0xD8, 0x0A },
	{ 0xD9, 0x0A },
	{ 0xC2, 0x0B },
	{ 0xC3, 0x0B },
	{ 0xD6, 0x0C },
	{ 0xD7, 0x0C },
	{ 0xC0, 0x05 },
	{ 0xC1, 0x05 },
	{ 0xD4, 0x06 },
	{ 0xD5, 0x06 },
	{ 0xCA, 0x07 },
	{ 0xCB, 0x07 },
	{ 0xDE, 0x08 },
	{ 0xDF, 0x08 },
	{ 0xB0, 0x02 },
	{ 0xC0, 0x00 },
	{ 0xC1, 0x0D },
	{ 0xC2, 0x17 },
	{ 0xC3, 0x26 },
	{ 0xC4, 0x31 },
	{ 0xC5, 0x1C },
	{ 0xC6, 0x2C },
	{ 0xC7, 0x33 },
	{ 0xC8, 0x31 },
	{ 0xC9, 0x37 },
	{ 0xCA, 0x37 },
	{ 0xCB, 0x37 },
	{ 0xCC, 0x39 },
	{ 0xCD, 0x2E },
	{ 0xCE, 0x2F },
	{ 0xCF, 0x2F },
	{ 0xD0, 0x07 },
	{ 0xD2, 0x00 },
	{ 0xD3, 0x0D },
	{ 0xD4, 0x17 },
	{ 0xD5, 0x26 },
	{ 0xD6, 0x31 },
	{ 0xD7, 0x3F },
	{ 0xD8, 0x3F },
	{ 0xD9, 0x3F },
	{ 0xDA, 0x3F },
	{ 0xDB, 0x37 },
	{ 0xDC, 0x37 },
	{ 0xDD, 0x37 },
	{ 0xDE, 0x39 },
	{ 0xDF, 0x2E },
	{ 0xE0, 0x2F },
	{ 0xE1, 0x2F },
	{ 0xE2, 0x07 },
	{ 0xB0, 0x03 },
	{ 0xC8, 0x0B },
	{ 0xC9, 0x07 },
	{ 0xC3, 0x00 },
	{ 0xE7, 0x00 },
	{ 0xC5, 0x2A },
	{ 0xDE, 0x2A },
	{ 0xCA, 0x43 },
	{ 0xC9, 0x07 },
	{ 0xE4, 0xC0 },
	{ 0xE5, 0x0D },
	{ 0xCB, 0x01 },
	{ 0xBC, 0x01 },
	{ 0xB0, 0x06 },
	{ 0xB8, 0xA5 },
	{ 0xC0, 0xA5 },
	{ 0xC7, 0x0F },
	{ 0xD5, 0x32 },
	{ 0xB8, 0x00 },
	{ 0xC0, 0x00 },
	{ 0xBC, 0x00 },
	{ 0xB0, 0x07 },
	{ 0xB1, 0x00 },
	{ 0xB2, 0x05 },
	{ 0xB3, 0x10 },
	{ 0xB4, 0x22 },
	{ 0xB5, 0x36 },
	{ 0xB6, 0x4A },
	{ 0xB7, 0x6C },
	{ 0xB8, 0x9A },
	{ 0xB9, 0xD7 },
	{ 0xBA, 0x17 },
	{ 0xBB, 0x92 },
	{ 0xBC, 0x15 },
	{ 0xBD, 0x18 },
	{ 0xBE, 0x8C },
	{ 0xBF, 0x00 },
	{ 0xC0, 0x3A },
	{ 0xC1, 0x72 },
	{ 0xC2, 0x8C },
	{ 0xC3, 0xA5 },
	{ 0xC4, 0xB1 },
	{ 0xC5, 0xBE },
	{ 0xC6, 0xCA },
	{ 0xC7, 0xD1 },
	{ 0xC8, 0xD4 },
	{ 0xC9, 0x00 },
	{ 0xCA, 0x00 },
	{ 0xCB, 0x16 },
	{ 0xCC, 0xAF },
	{ 0xCD, 0xFF },
	{ 0xCE, 0xFF },
	{ 0xB0, 0x08 },
	{ 0xB1, 0x04 },
	{ 0xB2, 0x05 },
	{ 0xB3, 0x11 },
	{ 0xB4, 0x24 },
	{ 0xB5, 0x39 },
	{ 0xB6, 0x4E },
	{ 0xB7, 0x72 },
	{ 0xB8, 0xA3 },
	{ 0xB9, 0xE1 },
	{ 0xBA, 0x25 },
	{ 0xBB, 0xA8 },
	{ 0xBC, 0x2E },
	{ 0xBD, 0x32 },
	{ 0xBE, 0xAD },
	{ 0xBF, 0x28 },
	{ 0xC0, 0x63 },
	{ 0xC1, 0x9B },
	{ 0xC2, 0xB5 },
	{ 0xC3, 0xCF },
	{ 0xC4, 0xDB },
	{ 0xC5, 0xE8 },
	{ 0xC6, 0xF5 },
	{ 0xC7, 0xFA },
	{ 0xC8, 0xFC },
	{ 0xC9, 0x00 },
	{ 0xCA, 0x00 },
	{ 0xCB, 0x16 },
	{ 0xCC, 0xAF },
	{ 0xCD, 0xFF },
	{ 0xCE, 0xFF },
	{ 0xB0, 0x09 },
	{ 0xB1, 0x04 },
	{ 0xB2, 0x04 },
	{ 0xB3, 0x0F },
	{ 0xB4, 0x22 },
	{ 0xB5, 0x37 },
	{ 0xB6, 0x4D },
	{ 0xB7, 0x71 },
	{ 0xB8, 0xA2 },
	{ 0xB9, 0xE1 },
	{ 0xBA, 0x26 },
	{ 0xBB, 0xA9 },
	{ 0xBC, 0x2F },
	{ 0xBD, 0x33 },
	{ 0xBE, 0xAC },
	{ 0xBF, 0x24 },
	{ 0xC0, 0x5D },
	{ 0xC1, 0x94 },
	{ 0xC2, 0xAC },
	{ 0xC3, 0xC5 },
	{ 0xC4, 0xD1 },
	{ 0xC5, 0xDC },
	{ 0xC6, 0xE8 },
	{ 0xC7, 0xED },
	{ 0xC8, 0xF0 },
	{ 0xC9, 0x00 },
	{ 0xCA, 0x00 },
	{ 0xCB, 0x16 },
	{ 0xCC, 0xAF },
	{ 0xCD, 0xFF },
	{ 0xCE, 0xFF },
	{ 0xB0, 0x0A },
	{ 0xB1, 0x00 },
	{ 0xB2, 0x05 },
	{ 0xB3, 0x10 },
	{ 0xB4, 0x22 },
	{ 0xB5, 0x36 },
	{ 0xB6, 0x4A },
	{ 0xB7, 0x6C },
	{ 0xB8, 0x9A },
	{ 0xB9, 0xD7 },
	{ 0xBA, 0x17 },
	{ 0xBB, 0x92 },
	{ 0xBC, 0x15 },
	{ 0xBD, 0x18 },
	{ 0xBE, 0x8C },
	{ 0xBF, 0x00 },
	{ 0xC0, 0x3A },
	{ 0xC1, 0x72 },
	{ 0xC2, 0x8C },
	{ 0xC3, 0xA5 },
	{ 0xC4, 0xB1 },
	{ 0xC5, 0xBE },
	{ 0xC6, 0xCA },
	{ 0xC7, 0xD1 },
	{ 0xC8, 0xD4 },
	{ 0xC9, 0x00 },
	{ 0xCA, 0x00 },
	{ 0xCB, 0x16 },
	{ 0xCC, 0xAF },
	{ 0xCD, 0xFF },
	{ 0xCE, 0xFF },
	{ 0xB0, 0x0B },
	{ 0xB1, 0x04 },
	{ 0xB2, 0x05 },
	{ 0xB3, 0x11 },
	{ 0xB4, 0x24 },
	{ 0xB5, 0x39 },
	{ 0xB6, 0x4E },
	{ 0xB7, 0x72 },
	{ 0xB8, 0xA3 },
	{ 0xB9, 0xE1 },
	{ 0xBA, 0x25 },
	{ 0xBB, 0xA8 },
	{ 0xBC, 0x2E },
	{ 0xBD, 0x32 },
	{ 0xBE, 0xAD },
	{ 0xBF, 0x28 },
	{ 0xC0, 0x63 },
	{ 0xC1, 0x9B },
	{ 0xC2, 0xB5 },
	{ 0xC3, 0xCF },
	{ 0xC4, 0xDB },
	{ 0xC5, 0xE8 },
	{ 0xC6, 0xF5 },
	{ 0xC7, 0xFA },
	{ 0xC8, 0xFC },
	{ 0xC9, 0x00 },
	{ 0xCA, 0x00 },
	{ 0xCB, 0x16 },
	{ 0xCC, 0xAF },
	{ 0xCD, 0xFF },
	{ 0xCE, 0xFF },
	{ 0xB0, 0x0C },
	{ 0xB1, 0x04 },
	{ 0xB2, 0x04 },
	{ 0xB3, 0x0F },
	{ 0xB4, 0x22 },
	{ 0xB5, 0x37 },
	{ 0xB6, 0x4D },
	{ 0xB7, 0x71 },
	{ 0xB8, 0xA2 },
	{ 0xB9, 0xE1 },
	{ 0xBA, 0x26 },
	{ 0xBB, 0xA9 },
	{ 0xBC, 0x2F },
	{ 0xBD, 0x33 },
	{ 0xBE, 0xAC },
	{ 0xBF, 0x24 },
	{ 0xC0, 0x5D },
	{ 0xC1, 0x94 },
	{ 0xC2, 0xAC },
	{ 0xC3, 0xC5 },
	{ 0xC4, 0xD1 },
	{ 0xC5, 0xDC },
	{ 0xC6, 0xE8 },
	{ 0xC7, 0xED },
	{ 0xC8, 0xF0 },
	{ 0xC9, 0x00 },
	{ 0xCA, 0x00 },
	{ 0xCB, 0x16 },
	{ 0xCC, 0xAF },
	{ 0xCD, 0xFF },
	{ 0xCE, 0xFF },
};

static const struct panel_desc boe_himax8279d10p_panel_desc = {
	.display_mode = &default_display_mode,
	.bpc = 8,
	.width_mm = 135,
	.height_mm = 216,
	.mode_flags = MIPI_DSI_MODE_VIDEO | MIPI_DSI_MODE_VIDEO_SYNC_PULSE |
			MIPI_DSI_CLOCK_NON_CONTINUOUS | MIPI_DSI_MODE_LPM,
	.format = MIPI_DSI_FMT_RGB888,
	.lanes = 4,
	.on_cmds = boe_himax8279d10p_on_cmds,
	.on_cmds_num = 283,
};

static const struct of_device_id panel_of_match[] = {
	{
		.compatible = "boe,himax8279d8p",
		.data = &boe_himax8279d8p_panel_desc,
	},
	{
		.compatible = "boe,himax8279d10p",
		.data = &boe_himax8279d10p_panel_desc,
	},
	{
		/* sentinel */
	}
};
MODULE_DEVICE_TABLE(of, panel_of_match);

static int panel_add(struct panel_info *pinfo)
{
	struct device *dev = &pinfo->link->dev;
	int ret;

	pinfo->pp18_gpio = devm_gpiod_get(dev, "pp18", GPIOD_OUT_HIGH);
	if (IS_ERR(pinfo->pp18_gpio)) {
		ret = PTR_ERR(pinfo->pp18_gpio);
		if (ret != -EPROBE_DEFER)
			dev_err(dev, "failed to get pp18 gpio: %d\n", ret);
		return ret;
	}

	pinfo->pp33_gpio = devm_gpiod_get(dev, "pp33", GPIOD_OUT_HIGH);
	if (IS_ERR(pinfo->pp33_gpio)) {
		ret = PTR_ERR(pinfo->pp33_gpio);
		if (ret != -EPROBE_DEFER)
			dev_err(dev, "failed to get pp33 gpio: %d\n", ret);
		return ret;
	}

	pinfo->enable_gpio = devm_gpiod_get(dev, "enable", GPIOD_OUT_HIGH);
	if (IS_ERR(pinfo->enable_gpio)) {
		ret = PTR_ERR(pinfo->enable_gpio);
		if (ret != -EPROBE_DEFER)
			dev_err(dev, "failed to get enable gpio: %d\n", ret);
		return ret;
	}

	drm_panel_init(&pinfo->base, dev, &panel_funcs,
		       DRM_MODE_CONNECTOR_DSI);

	ret = drm_panel_of_backlight(&pinfo->base);
	if (ret)
		return ret;

	drm_panel_add(&pinfo->base);

	return 0;
}

static int panel_probe(struct mipi_dsi_device *dsi)
{
	struct panel_info *pinfo;
	const struct panel_desc *desc;
	int err;

	pinfo = devm_kzalloc(&dsi->dev, sizeof(*pinfo), GFP_KERNEL);
	if (!pinfo)
		return -ENOMEM;

	desc = of_device_get_match_data(&dsi->dev);
	dsi->mode_flags = desc->mode_flags;
	dsi->format = desc->format;
	dsi->lanes = desc->lanes;
	pinfo->desc = desc;

	pinfo->link = dsi;
	mipi_dsi_set_drvdata(dsi, pinfo);

	err = panel_add(pinfo);
	if (err < 0)
		return err;

	err = mipi_dsi_attach(dsi);
	if (err < 0)
		drm_panel_remove(&pinfo->base);

	return err;
}

static int panel_remove(struct mipi_dsi_device *dsi)
{
	struct panel_info *pinfo = mipi_dsi_get_drvdata(dsi);
	int err;

	err = boe_panel_disable(&pinfo->base);
	if (err < 0)
		dev_err(&dsi->dev, "failed to disable panel: %d\n", err);

	err = boe_panel_unprepare(&pinfo->base);
	if (err < 0)
		dev_err(&dsi->dev, "failed to unprepare panel: %d\n", err);

	err = mipi_dsi_detach(dsi);
	if (err < 0)
		dev_err(&dsi->dev, "failed to detach from DSI host: %d\n", err);

	drm_panel_remove(&pinfo->base);

	return 0;
}

static void panel_shutdown(struct mipi_dsi_device *dsi)
{
	struct panel_info *pinfo = mipi_dsi_get_drvdata(dsi);

	boe_panel_disable(&pinfo->base);
	boe_panel_unprepare(&pinfo->base);
}

static struct mipi_dsi_driver panel_driver = {
	.driver = {
		.name = "panel-boe-himax8279d",
		.of_match_table = panel_of_match,
	},
	.probe = panel_probe,
	.remove = panel_remove,
	.shutdown = panel_shutdown,
};
module_mipi_dsi_driver(panel_driver);

MODULE_AUTHOR("Jerry Han <jerry.han.hq@gmail.com>");
MODULE_DESCRIPTION("Boe Himax8279d driver");
MODULE_LICENSE("GPL v2");
