// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 BayLibre, SAS
 * Author: Neil Armstrong <narmstrong@baylibre.com>
 */

#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/regulator/consumer.h>

#include <video/mipi_display.h>

#include <drm/drm_crtc.h>
#include <drm/drm_device.h>
#include <drm/drm_mipi_dsi.h>
#include <drm/drm_modes.h>
#include <drm/drm_panel.h>

struct khadas_ts050_panel {
	struct drm_panel base;
	struct mipi_dsi_device *link;

	struct regulator *supply;
	struct gpio_desc *reset_gpio;
	struct gpio_desc *enable_gpio;

	bool prepared;
	bool enabled;
};

struct khadas_ts050_panel_cmd {
	u8 cmd;
	u8 data;
};

/* Only the CMD1 User Command set is documented */
static const struct khadas_ts050_panel_cmd init_code[] = {
	/* Select Unknown CMD Page (Undocumented) */
	{0xff, 0xee},
	/* Reload CMD1: Don't reload default value to register */
	{0xfb, 0x01},
	{0x1f, 0x45},
	{0x24, 0x4f},
	{0x38, 0xc8},
	{0x39, 0x27},
	{0x1e, 0x77},
	{0x1d, 0x0f},
	{0x7e, 0x71},
	{0x7c, 0x03},
	{0xff, 0x00},
	{0xfb, 0x01},
	{0x35, 0x01},
	/* Select CMD2 Page0 (Undocumented) */
	{0xff, 0x01},
	/* Reload CMD1: Don't reload default value to register */
	{0xfb, 0x01},
	{0x00, 0x01},
	{0x01, 0x55},
	{0x02, 0x40},
	{0x05, 0x40},
	{0x06, 0x4a},
	{0x07, 0x24},
	{0x08, 0x0c},
	{0x0b, 0x7d},
	{0x0c, 0x7d},
	{0x0e, 0xb0},
	{0x0f, 0xae},
	{0x11, 0x10},
	{0x12, 0x10},
	{0x13, 0x03},
	{0x14, 0x4a},
	{0x15, 0x12},
	{0x16, 0x12},
	{0x18, 0x00},
	{0x19, 0x77},
	{0x1a, 0x55},
	{0x1b, 0x13},
	{0x1c, 0x00},
	{0x1d, 0x00},
	{0x1e, 0x13},
	{0x1f, 0x00},
	{0x23, 0x00},
	{0x24, 0x00},
	{0x25, 0x00},
	{0x26, 0x00},
	{0x27, 0x00},
	{0x28, 0x00},
	{0x35, 0x00},
	{0x66, 0x00},
	{0x58, 0x82},
	{0x59, 0x02},
	{0x5a, 0x02},
	{0x5b, 0x02},
	{0x5c, 0x82},
	{0x5d, 0x82},
	{0x5e, 0x02},
	{0x5f, 0x02},
	{0x72, 0x31},
	/* Select CMD2 Page4 (Undocumented) */
	{0xff, 0x05},
	/* Reload CMD1: Don't reload default value to register */
	{0xfb, 0x01},
	{0x00, 0x01},
	{0x01, 0x0b},
	{0x02, 0x0c},
	{0x03, 0x09},
	{0x04, 0x0a},
	{0x05, 0x00},
	{0x06, 0x0f},
	{0x07, 0x10},
	{0x08, 0x00},
	{0x09, 0x00},
	{0x0a, 0x00},
	{0x0b, 0x00},
	{0x0c, 0x00},
	{0x0d, 0x13},
	{0x0e, 0x15},
	{0x0f, 0x17},
	{0x10, 0x01},
	{0x11, 0x0b},
	{0x12, 0x0c},
	{0x13, 0x09},
	{0x14, 0x0a},
	{0x15, 0x00},
	{0x16, 0x0f},
	{0x17, 0x10},
	{0x18, 0x00},
	{0x19, 0x00},
	{0x1a, 0x00},
	{0x1b, 0x00},
	{0x1c, 0x00},
	{0x1d, 0x13},
	{0x1e, 0x15},
	{0x1f, 0x17},
	{0x20, 0x00},
	{0x21, 0x03},
	{0x22, 0x01},
	{0x23, 0x40},
	{0x24, 0x40},
	{0x25, 0xed},
	{0x29, 0x58},
	{0x2a, 0x12},
	{0x2b, 0x01},
	{0x4b, 0x06},
	{0x4c, 0x11},
	{0x4d, 0x20},
	{0x4e, 0x02},
	{0x4f, 0x02},
	{0x50, 0x20},
	{0x51, 0x61},
	{0x52, 0x01},
	{0x53, 0x63},
	{0x54, 0x77},
	{0x55, 0xed},
	{0x5b, 0x00},
	{0x5c, 0x00},
	{0x5d, 0x00},
	{0x5e, 0x00},
	{0x5f, 0x15},
	{0x60, 0x75},
	{0x61, 0x00},
	{0x62, 0x00},
	{0x63, 0x00},
	{0x64, 0x00},
	{0x65, 0x00},
	{0x66, 0x00},
	{0x67, 0x00},
	{0x68, 0x04},
	{0x69, 0x00},
	{0x6a, 0x00},
	{0x6c, 0x40},
	{0x75, 0x01},
	{0x76, 0x01},
	{0x7a, 0x80},
	{0x7b, 0xa3},
	{0x7c, 0xd8},
	{0x7d, 0x60},
	{0x7f, 0x15},
	{0x80, 0x81},
	{0x83, 0x05},
	{0x93, 0x08},
	{0x94, 0x10},
	{0x8a, 0x00},
	{0x9b, 0x0f},
	{0xea, 0xff},
	{0xec, 0x00},
	/* Select CMD2 Page0 (Undocumented) */
	{0xff, 0x01},
	/* Reload CMD1: Don't reload default value to register */
	{0xfb, 0x01},
	{0x75, 0x00},
	{0x76, 0xdf},
	{0x77, 0x00},
	{0x78, 0xe4},
	{0x79, 0x00},
	{0x7a, 0xed},
	{0x7b, 0x00},
	{0x7c, 0xf6},
	{0x7d, 0x00},
	{0x7e, 0xff},
	{0x7f, 0x01},
	{0x80, 0x07},
	{0x81, 0x01},
	{0x82, 0x10},
	{0x83, 0x01},
	{0x84, 0x18},
	{0x85, 0x01},
	{0x86, 0x20},
	{0x87, 0x01},
	{0x88, 0x3d},
	{0x89, 0x01},
	{0x8a, 0x56},
	{0x8b, 0x01},
	{0x8c, 0x84},
	{0x8d, 0x01},
	{0x8e, 0xab},
	{0x8f, 0x01},
	{0x90, 0xec},
	{0x91, 0x02},
	{0x92, 0x22},
	{0x93, 0x02},
	{0x94, 0x23},
	{0x95, 0x02},
	{0x96, 0x55},
	{0x97, 0x02},
	{0x98, 0x8b},
	{0x99, 0x02},
	{0x9a, 0xaf},
	{0x9b, 0x02},
	{0x9c, 0xdf},
	{0x9d, 0x03},
	{0x9e, 0x01},
	{0x9f, 0x03},
	{0xa0, 0x2c},
	{0xa2, 0x03},
	{0xa3, 0x39},
	{0xa4, 0x03},
	{0xa5, 0x47},
	{0xa6, 0x03},
	{0xa7, 0x56},
	{0xa9, 0x03},
	{0xaa, 0x66},
	{0xab, 0x03},
	{0xac, 0x76},
	{0xad, 0x03},
	{0xae, 0x85},
	{0xaf, 0x03},
	{0xb0, 0x90},
	{0xb1, 0x03},
	{0xb2, 0xcb},
	{0xb3, 0x00},
	{0xb4, 0xdf},
	{0xb5, 0x00},
	{0xb6, 0xe4},
	{0xb7, 0x00},
	{0xb8, 0xed},
	{0xb9, 0x00},
	{0xba, 0xf6},
	{0xbb, 0x00},
	{0xbc, 0xff},
	{0xbd, 0x01},
	{0xbe, 0x07},
	{0xbf, 0x01},
	{0xc0, 0x10},
	{0xc1, 0x01},
	{0xc2, 0x18},
	{0xc3, 0x01},
	{0xc4, 0x20},
	{0xc5, 0x01},
	{0xc6, 0x3d},
	{0xc7, 0x01},
	{0xc8, 0x56},
	{0xc9, 0x01},
	{0xca, 0x84},
	{0xcb, 0x01},
	{0xcc, 0xab},
	{0xcd, 0x01},
	{0xce, 0xec},
	{0xcf, 0x02},
	{0xd0, 0x22},
	{0xd1, 0x02},
	{0xd2, 0x23},
	{0xd3, 0x02},
	{0xd4, 0x55},
	{0xd5, 0x02},
	{0xd6, 0x8b},
	{0xd7, 0x02},
	{0xd8, 0xaf},
	{0xd9, 0x02},
	{0xda, 0xdf},
	{0xdb, 0x03},
	{0xdc, 0x01},
	{0xdd, 0x03},
	{0xde, 0x2c},
	{0xdf, 0x03},
	{0xe0, 0x39},
	{0xe1, 0x03},
	{0xe2, 0x47},
	{0xe3, 0x03},
	{0xe4, 0x56},
	{0xe5, 0x03},
	{0xe6, 0x66},
	{0xe7, 0x03},
	{0xe8, 0x76},
	{0xe9, 0x03},
	{0xea, 0x85},
	{0xeb, 0x03},
	{0xec, 0x90},
	{0xed, 0x03},
	{0xee, 0xcb},
	{0xef, 0x00},
	{0xf0, 0xbb},
	{0xf1, 0x00},
	{0xf2, 0xc0},
	{0xf3, 0x00},
	{0xf4, 0xcc},
	{0xf5, 0x00},
	{0xf6, 0xd6},
	{0xf7, 0x00},
	{0xf8, 0xe1},
	{0xf9, 0x00},
	{0xfa, 0xea},
	/* Select CMD2 Page2 (Undocumented) */
	{0xff, 0x02},
	/* Reload CMD1: Don't reload default value to register */
	{0xfb, 0x01},
	{0x00, 0x00},
	{0x01, 0xf4},
	{0x02, 0x00},
	{0x03, 0xef},
	{0x04, 0x01},
	{0x05, 0x07},
	{0x06, 0x01},
	{0x07, 0x28},
	{0x08, 0x01},
	{0x09, 0x44},
	{0x0a, 0x01},
	{0x0b, 0x76},
	{0x0c, 0x01},
	{0x0d, 0xa0},
	{0x0e, 0x01},
	{0x0f, 0xe7},
	{0x10, 0x02},
	{0x11, 0x1f},
	{0x12, 0x02},
	{0x13, 0x22},
	{0x14, 0x02},
	{0x15, 0x54},
	{0x16, 0x02},
	{0x17, 0x8b},
	{0x18, 0x02},
	{0x19, 0xaf},
	{0x1a, 0x02},
	{0x1b, 0xe0},
	{0x1c, 0x03},
	{0x1d, 0x01},
	{0x1e, 0x03},
	{0x1f, 0x2d},
	{0x20, 0x03},
	{0x21, 0x39},
	{0x22, 0x03},
	{0x23, 0x47},
	{0x24, 0x03},
	{0x25, 0x57},
	{0x26, 0x03},
	{0x27, 0x65},
	{0x28, 0x03},
	{0x29, 0x77},
	{0x2a, 0x03},
	{0x2b, 0x85},
	{0x2d, 0x03},
	{0x2f, 0x8f},
	{0x30, 0x03},
	{0x31, 0xcb},
	{0x32, 0x00},
	{0x33, 0xbb},
	{0x34, 0x00},
	{0x35, 0xc0},
	{0x36, 0x00},
	{0x37, 0xcc},
	{0x38, 0x00},
	{0x39, 0xd6},
	{0x3a, 0x00},
	{0x3b, 0xe1},
	{0x3d, 0x00},
	{0x3f, 0xea},
	{0x40, 0x00},
	{0x41, 0xf4},
	{0x42, 0x00},
	{0x43, 0xfe},
	{0x44, 0x01},
	{0x45, 0x07},
	{0x46, 0x01},
	{0x47, 0x28},
	{0x48, 0x01},
	{0x49, 0x44},
	{0x4a, 0x01},
	{0x4b, 0x76},
	{0x4c, 0x01},
	{0x4d, 0xa0},
	{0x4e, 0x01},
	{0x4f, 0xe7},
	{0x50, 0x02},
	{0x51, 0x1f},
	{0x52, 0x02},
	{0x53, 0x22},
	{0x54, 0x02},
	{0x55, 0x54},
	{0x56, 0x02},
	{0x58, 0x8b},
	{0x59, 0x02},
	{0x5a, 0xaf},
	{0x5b, 0x02},
	{0x5c, 0xe0},
	{0x5d, 0x03},
	{0x5e, 0x01},
	{0x5f, 0x03},
	{0x60, 0x2d},
	{0x61, 0x03},
	{0x62, 0x39},
	{0x63, 0x03},
	{0x64, 0x47},
	{0x65, 0x03},
	{0x66, 0x57},
	{0x67, 0x03},
	{0x68, 0x65},
	{0x69, 0x03},
	{0x6a, 0x77},
	{0x6b, 0x03},
	{0x6c, 0x85},
	{0x6d, 0x03},
	{0x6e, 0x8f},
	{0x6f, 0x03},
	{0x70, 0xcb},
	{0x71, 0x00},
	{0x72, 0x00},
	{0x73, 0x00},
	{0x74, 0x21},
	{0x75, 0x00},
	{0x76, 0x4c},
	{0x77, 0x00},
	{0x78, 0x6b},
	{0x79, 0x00},
	{0x7a, 0x85},
	{0x7b, 0x00},
	{0x7c, 0x9a},
	{0x7d, 0x00},
	{0x7e, 0xad},
	{0x7f, 0x00},
	{0x80, 0xbe},
	{0x81, 0x00},
	{0x82, 0xcd},
	{0x83, 0x01},
	{0x84, 0x01},
	{0x85, 0x01},
	{0x86, 0x29},
	{0x87, 0x01},
	{0x88, 0x68},
	{0x89, 0x01},
	{0x8a, 0x98},
	{0x8b, 0x01},
	{0x8c, 0xe5},
	{0x8d, 0x02},
	{0x8e, 0x1e},
	{0x8f, 0x02},
	{0x90, 0x30},
	{0x91, 0x02},
	{0x92, 0x52},
	{0x93, 0x02},
	{0x94, 0x88},
	{0x95, 0x02},
	{0x96, 0xaa},
	{0x97, 0x02},
	{0x98, 0xd7},
	{0x99, 0x02},
	{0x9a, 0xf7},
	{0x9b, 0x03},
	{0x9c, 0x21},
	{0x9d, 0x03},
	{0x9e, 0x2e},
	{0x9f, 0x03},
	{0xa0, 0x3d},
	{0xa2, 0x03},
	{0xa3, 0x4c},
	{0xa4, 0x03},
	{0xa5, 0x5e},
	{0xa6, 0x03},
	{0xa7, 0x71},
	{0xa9, 0x03},
	{0xaa, 0x86},
	{0xab, 0x03},
	{0xac, 0x94},
	{0xad, 0x03},
	{0xae, 0xfa},
	{0xaf, 0x00},
	{0xb0, 0x00},
	{0xb1, 0x00},
	{0xb2, 0x21},
	{0xb3, 0x00},
	{0xb4, 0x4c},
	{0xb5, 0x00},
	{0xb6, 0x6b},
	{0xb7, 0x00},
	{0xb8, 0x85},
	{0xb9, 0x00},
	{0xba, 0x9a},
	{0xbb, 0x00},
	{0xbc, 0xad},
	{0xbd, 0x00},
	{0xbe, 0xbe},
	{0xbf, 0x00},
	{0xc0, 0xcd},
	{0xc1, 0x01},
	{0xc2, 0x01},
	{0xc3, 0x01},
	{0xc4, 0x29},
	{0xc5, 0x01},
	{0xc6, 0x68},
	{0xc7, 0x01},
	{0xc8, 0x98},
	{0xc9, 0x01},
	{0xca, 0xe5},
	{0xcb, 0x02},
	{0xcc, 0x1e},
	{0xcd, 0x02},
	{0xce, 0x20},
	{0xcf, 0x02},
	{0xd0, 0x52},
	{0xd1, 0x02},
	{0xd2, 0x88},
	{0xd3, 0x02},
	{0xd4, 0xaa},
	{0xd5, 0x02},
	{0xd6, 0xd7},
	{0xd7, 0x02},
	{0xd8, 0xf7},
	{0xd9, 0x03},
	{0xda, 0x21},
	{0xdb, 0x03},
	{0xdc, 0x2e},
	{0xdd, 0x03},
	{0xde, 0x3d},
	{0xdf, 0x03},
	{0xe0, 0x4c},
	{0xe1, 0x03},
	{0xe2, 0x5e},
	{0xe3, 0x03},
	{0xe4, 0x71},
	{0xe5, 0x03},
	{0xe6, 0x86},
	{0xe7, 0x03},
	{0xe8, 0x94},
	{0xe9, 0x03},
	{0xea, 0xfa},
	/* Select CMD2 Page0 (Undocumented) */
	{0xff, 0x01},
	/* Reload CMD1: Don't reload default value to register */
	{0xfb, 0x01},
	/* Select CMD2 Page1 (Undocumented) */
	{0xff, 0x02},
	/* Reload CMD1: Don't reload default value to register */
	{0xfb, 0x01},
	/* Select CMD2 Page3 (Undocumented) */
	{0xff, 0x04},
	/* Reload CMD1: Don't reload default value to register */
	{0xfb, 0x01},
	/* Select CMD1 */
	{0xff, 0x00},
	{0xd3, 0x05}, /* RGBMIPICTRL: VSYNC back porch = 5 */
	{0xd4, 0x04}, /* RGBMIPICTRL: VSYNC front porch = 4 */
};

static inline
struct khadas_ts050_panel *to_khadas_ts050_panel(struct drm_panel *panel)
{
	return container_of(panel, struct khadas_ts050_panel, base);
}

static int khadas_ts050_panel_prepare(struct drm_panel *panel)
{
	struct khadas_ts050_panel *khadas_ts050 = to_khadas_ts050_panel(panel);
	unsigned int i;
	int err;

	if (khadas_ts050->prepared)
		return 0;

	gpiod_set_value_cansleep(khadas_ts050->enable_gpio, 0);

	err = regulator_enable(khadas_ts050->supply);
	if (err < 0)
		return err;

	gpiod_set_value_cansleep(khadas_ts050->enable_gpio, 1);

	msleep(60);

	gpiod_set_value_cansleep(khadas_ts050->reset_gpio, 1);

	usleep_range(10000, 11000);

	gpiod_set_value_cansleep(khadas_ts050->reset_gpio, 0);

	/* Select CMD2 page 4 (Undocumented) */
	mipi_dsi_dcs_write(khadas_ts050->link, 0xff, (u8[]){ 0x05 }, 1);

	/* Reload CMD1: Don't reload default value to register */
	mipi_dsi_dcs_write(khadas_ts050->link, 0xfb, (u8[]){ 0x01 }, 1);

	mipi_dsi_dcs_write(khadas_ts050->link, 0xc5, (u8[]){ 0x01 }, 1);

	msleep(100);

	for (i = 0; i < ARRAY_SIZE(init_code); i++) {
		err = mipi_dsi_dcs_write(khadas_ts050->link,
					 init_code[i].cmd,
					 &init_code[i].data, 1);
		if (err < 0) {
			dev_err(panel->dev, "failed write cmds: %d\n", err);
			goto poweroff;
		}
	}

	err = mipi_dsi_dcs_exit_sleep_mode(khadas_ts050->link);
	if (err < 0) {
		dev_err(panel->dev, "failed to exit sleep mode: %d\n", err);
		goto poweroff;
	}

	msleep(120);

	/* Select CMD1 */
	mipi_dsi_dcs_write(khadas_ts050->link, 0xff, (u8[]){ 0x00 }, 1);

	err = mipi_dsi_dcs_set_tear_on(khadas_ts050->link,
				       MIPI_DSI_DCS_TEAR_MODE_VBLANK);
	if (err < 0) {
		dev_err(panel->dev, "failed to set tear on: %d\n", err);
		goto poweroff;
	}

	err = mipi_dsi_dcs_set_display_on(khadas_ts050->link);
	if (err < 0) {
		dev_err(panel->dev, "failed to set display on: %d\n", err);
		goto poweroff;
	}

	usleep_range(10000, 11000);

	khadas_ts050->prepared = true;

	return 0;

poweroff:
	gpiod_set_value_cansleep(khadas_ts050->enable_gpio, 0);
	gpiod_set_value_cansleep(khadas_ts050->reset_gpio, 1);

	regulator_disable(khadas_ts050->supply);

	return err;
}

static int khadas_ts050_panel_unprepare(struct drm_panel *panel)
{
	struct khadas_ts050_panel *khadas_ts050 = to_khadas_ts050_panel(panel);
	int err;

	if (!khadas_ts050->prepared)
		return 0;

	khadas_ts050->prepared = false;

	err = mipi_dsi_dcs_enter_sleep_mode(khadas_ts050->link);
	if (err < 0)
		dev_err(panel->dev, "failed to enter sleep mode: %d\n", err);

	msleep(150);

	gpiod_set_value_cansleep(khadas_ts050->enable_gpio, 0);
	gpiod_set_value_cansleep(khadas_ts050->reset_gpio, 1);

	err = regulator_disable(khadas_ts050->supply);
	if (err < 0)
		return err;

	return 0;
}

static int khadas_ts050_panel_enable(struct drm_panel *panel)
{
	struct khadas_ts050_panel *khadas_ts050 = to_khadas_ts050_panel(panel);

	khadas_ts050->enabled = true;

	return 0;
}

static int khadas_ts050_panel_disable(struct drm_panel *panel)
{
	struct khadas_ts050_panel *khadas_ts050 = to_khadas_ts050_panel(panel);
	int err;

	if (!khadas_ts050->enabled)
		return 0;

	err = mipi_dsi_dcs_set_display_off(khadas_ts050->link);
	if (err < 0)
		dev_err(panel->dev, "failed to set display off: %d\n", err);

	usleep_range(10000, 11000);

	khadas_ts050->enabled = false;

	return 0;
}

static const struct drm_display_mode default_mode = {
	.clock = 120000,
	.hdisplay = 1088,
	.hsync_start = 1088 + 104,
	.hsync_end = 1088 + 104 + 4,
	.htotal = 1088 + 104 + 4 + 127,
	.vdisplay = 1920,
	.vsync_start = 1920 + 4,
	.vsync_end = 1920 + 4 + 2,
	.vtotal = 1920 + 4 + 2 + 3,
	.flags = DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC,
};

static int khadas_ts050_panel_get_modes(struct drm_panel *panel,
					struct drm_connector *connector)
{
	struct drm_display_mode *mode;

	mode = drm_mode_duplicate(connector->dev, &default_mode);
	if (!mode) {
		dev_err(panel->dev, "failed to add mode %ux%u@%u\n",
			default_mode.hdisplay, default_mode.vdisplay,
			drm_mode_vrefresh(&default_mode));
		return -ENOMEM;
	}

	drm_mode_set_name(mode);

	drm_mode_probed_add(connector, mode);

	connector->display_info.width_mm = 64;
	connector->display_info.height_mm = 118;
	connector->display_info.bpc = 8;

	return 1;
}

static const struct drm_panel_funcs khadas_ts050_panel_funcs = {
	.prepare = khadas_ts050_panel_prepare,
	.unprepare = khadas_ts050_panel_unprepare,
	.enable = khadas_ts050_panel_enable,
	.disable = khadas_ts050_panel_disable,
	.get_modes = khadas_ts050_panel_get_modes,
};

static const struct of_device_id khadas_ts050_of_match[] = {
	{ .compatible = "khadas,ts050", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, khadas_ts050_of_match);

static int khadas_ts050_panel_add(struct khadas_ts050_panel *khadas_ts050)
{
	struct device *dev = &khadas_ts050->link->dev;
	int err;

	khadas_ts050->supply = devm_regulator_get(dev, "power");
	if (IS_ERR(khadas_ts050->supply))
		return dev_err_probe(dev, PTR_ERR(khadas_ts050->supply),
				     "failed to get power supply");

	khadas_ts050->reset_gpio = devm_gpiod_get(dev, "reset",
						  GPIOD_OUT_LOW);
	if (IS_ERR(khadas_ts050->reset_gpio))
		return dev_err_probe(dev, PTR_ERR(khadas_ts050->reset_gpio),
				     "failed to get reset gpio");

	khadas_ts050->enable_gpio = devm_gpiod_get(dev, "enable",
						   GPIOD_OUT_HIGH);
	if (IS_ERR(khadas_ts050->enable_gpio))
		return dev_err_probe(dev, PTR_ERR(khadas_ts050->enable_gpio),
				     "failed to get enable gpio");

	drm_panel_init(&khadas_ts050->base, &khadas_ts050->link->dev,
		       &khadas_ts050_panel_funcs, DRM_MODE_CONNECTOR_DSI);

	err = drm_panel_of_backlight(&khadas_ts050->base);
	if (err)
		return err;

	drm_panel_add(&khadas_ts050->base);

	return 0;
}

static int khadas_ts050_panel_probe(struct mipi_dsi_device *dsi)
{
	struct khadas_ts050_panel *khadas_ts050;
	int err;

	dsi->lanes = 4;
	dsi->format = MIPI_DSI_FMT_RGB888;
	dsi->mode_flags = MIPI_DSI_MODE_VIDEO | MIPI_DSI_MODE_VIDEO_BURST |
			  MIPI_DSI_MODE_LPM | MIPI_DSI_MODE_NO_EOT_PACKET;

	khadas_ts050 = devm_kzalloc(&dsi->dev, sizeof(*khadas_ts050),
				    GFP_KERNEL);
	if (!khadas_ts050)
		return -ENOMEM;

	mipi_dsi_set_drvdata(dsi, khadas_ts050);
	khadas_ts050->link = dsi;

	err = khadas_ts050_panel_add(khadas_ts050);
	if (err < 0)
		return err;

	err = mipi_dsi_attach(dsi);
	if (err)
		drm_panel_remove(&khadas_ts050->base);

	return err;
}

static void khadas_ts050_panel_remove(struct mipi_dsi_device *dsi)
{
	struct khadas_ts050_panel *khadas_ts050 = mipi_dsi_get_drvdata(dsi);
	int err;

	err = mipi_dsi_detach(dsi);
	if (err < 0)
		dev_err(&dsi->dev, "failed to detach from DSI host: %d\n", err);

	drm_panel_remove(&khadas_ts050->base);
	drm_panel_disable(&khadas_ts050->base);
	drm_panel_unprepare(&khadas_ts050->base);
}

static void khadas_ts050_panel_shutdown(struct mipi_dsi_device *dsi)
{
	struct khadas_ts050_panel *khadas_ts050 = mipi_dsi_get_drvdata(dsi);

	drm_panel_disable(&khadas_ts050->base);
	drm_panel_unprepare(&khadas_ts050->base);
}

static struct mipi_dsi_driver khadas_ts050_panel_driver = {
	.driver = {
		.name = "panel-khadas-ts050",
		.of_match_table = khadas_ts050_of_match,
	},
	.probe = khadas_ts050_panel_probe,
	.remove = khadas_ts050_panel_remove,
	.shutdown = khadas_ts050_panel_shutdown,
};
module_mipi_dsi_driver(khadas_ts050_panel_driver);

MODULE_AUTHOR("Neil Armstrong <narmstrong@baylibre.com>");
MODULE_DESCRIPTION("Khadas TS050 panel driver");
MODULE_LICENSE("GPL v2");
