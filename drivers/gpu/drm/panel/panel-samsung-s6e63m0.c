// SPDX-License-Identifier: GPL-2.0
/*
 * S6E63M0 AMOLED LCD drm_panel driver.
 *
 * Copyright (C) 2019 Paweł Chmiel <pawel.mikolaj.chmiel@gmail.com>
 * Derived from drivers/gpu/drm/panel-samsung-ld9040.c
 *
 * Andrzej Hajda <a.hajda@samsung.com>
 */

#include <drm/drm_modes.h>
#include <drm/drm_panel.h>

#include <linux/backlight.h>
#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/module.h>
#include <linux/regulator/consumer.h>
#include <linux/media-bus-format.h>

#include <video/mipi_display.h>

#include "panel-samsung-s6e63m0.h"

#define S6E63M0_LCD_ID_VALUE_M2		0xA4
#define S6E63M0_LCD_ID_VALUE_SM2	0xB4
#define S6E63M0_LCD_ID_VALUE_SM2_1	0xB6

#define NUM_GAMMA_LEVELS	28
#define GAMMA_TABLE_COUNT	23

#define MAX_BRIGHTNESS		(NUM_GAMMA_LEVELS - 1)

/* array of gamma tables for gamma value 2.2 */
static u8 const s6e63m0_gamma_22[NUM_GAMMA_LEVELS][GAMMA_TABLE_COUNT] = {
	/* 30 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0xA1, 0x51, 0x7B, 0xCE,
	  0xCB, 0xC2, 0xC7, 0xCB, 0xBC, 0xDA, 0xDD,
	  0xD3, 0x00, 0x53, 0x00, 0x52, 0x00, 0x6F, },
	/* 40 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x97, 0x58, 0x71, 0xCC,
	  0xCB, 0xC0, 0xC5, 0xC9, 0xBA, 0xD9, 0xDC,
	  0xD1, 0x00, 0x5B, 0x00, 0x5A, 0x00, 0x7A, },
	/* 50 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x96, 0x58, 0x72, 0xCB,
	  0xCA, 0xBF, 0xC6, 0xC9, 0xBA, 0xD6, 0xD9,
	  0xCD, 0x00, 0x61, 0x00, 0x61, 0x00, 0x83, },
	/* 60 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x91, 0x5E, 0x6E, 0xC9,
	  0xC9, 0xBD, 0xC4, 0xC9, 0xB8, 0xD3, 0xD7,
	  0xCA, 0x00, 0x69, 0x00, 0x67, 0x00, 0x8D, },
	/* 70 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x8E, 0x62, 0x6B, 0xC7,
	  0xC9, 0xBB, 0xC3, 0xC7, 0xB7, 0xD3, 0xD7,
	  0xCA, 0x00, 0x6E, 0x00, 0x6C, 0x00, 0x94, },
	/* 80 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x89, 0x68, 0x65, 0xC9,
	  0xC9, 0xBC, 0xC1, 0xC5, 0xB6, 0xD2, 0xD5,
	  0xC9, 0x00, 0x73, 0x00, 0x72, 0x00, 0x9A, },
	/* 90 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x89, 0x69, 0x64, 0xC7,
	  0xC8, 0xBB, 0xC0, 0xC5, 0xB4, 0xD2, 0xD5,
	  0xC9, 0x00, 0x77, 0x00, 0x76, 0x00, 0xA0, },
	/* 100 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x86, 0x69, 0x60, 0xC6,
	  0xC8, 0xBA, 0xBF, 0xC4, 0xB4, 0xD0, 0xD4,
	  0xC6, 0x00, 0x7C, 0x00, 0x7A, 0x00, 0xA7, },
	/* 110 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x86, 0x6A, 0x60, 0xC5,
	  0xC7, 0xBA, 0xBD, 0xC3, 0xB2, 0xD0, 0xD4,
	  0xC5, 0x00, 0x80, 0x00, 0x7E, 0x00, 0xAD, },
	/* 120 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x82, 0x6B, 0x5E, 0xC4,
	  0xC8, 0xB9, 0xBD, 0xC2, 0xB1, 0xCE, 0xD2,
	  0xC4, 0x00, 0x85, 0x00, 0x82, 0x00, 0xB3, },
	/* 130 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x8C, 0x6C, 0x60, 0xC3,
	  0xC7, 0xB9, 0xBC, 0xC1, 0xAF, 0xCE, 0xD2,
	  0xC3, 0x00, 0x88, 0x00, 0x86, 0x00, 0xB8, },
	/* 140 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x80, 0x6C, 0x5F, 0xC1,
	  0xC6, 0xB7, 0xBC, 0xC1, 0xAE, 0xCD, 0xD0,
	  0xC2, 0x00, 0x8C, 0x00, 0x8A, 0x00, 0xBE, },
	/* 150 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x80, 0x6E, 0x5F, 0xC1,
	  0xC6, 0xB6, 0xBC, 0xC0, 0xAE, 0xCC, 0xD0,
	  0xC2, 0x00, 0x8F, 0x00, 0x8D, 0x00, 0xC2, },
	/* 160 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x7F, 0x6E, 0x5F, 0xC0,
	  0xC6, 0xB5, 0xBA, 0xBF, 0xAD, 0xCB, 0xCF,
	  0xC0, 0x00, 0x94, 0x00, 0x91, 0x00, 0xC8, },
	/* 170 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x7C, 0x6D, 0x5C, 0xC0,
	  0xC6, 0xB4, 0xBB, 0xBE, 0xAD, 0xCA, 0xCF,
	  0xC0, 0x00, 0x96, 0x00, 0x94, 0x00, 0xCC, },
	/* 180 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x7B, 0x6D, 0x5B, 0xC0,
	  0xC5, 0xB3, 0xBA, 0xBE, 0xAD, 0xCA, 0xCE,
	  0xBF,	0x00, 0x99, 0x00, 0x97, 0x00, 0xD0, },
	/* 190 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x7A, 0x6D, 0x59, 0xC1,
	  0xC5, 0xB4, 0xB8, 0xBD, 0xAC, 0xC9, 0xCE,
	  0xBE, 0x00, 0x9D, 0x00, 0x9A, 0x00, 0xD5, },
	/* 200 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x79, 0x6D, 0x58, 0xC1,
	  0xC4, 0xB4, 0xB6, 0xBD, 0xAA, 0xCA, 0xCD,
	  0xBE, 0x00, 0x9F, 0x00, 0x9D, 0x00, 0xD9, },
	/* 210 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x79, 0x6D, 0x57, 0xC0,
	  0xC4, 0xB4, 0xB7, 0xBD, 0xAA, 0xC8, 0xCC,
	  0xBD, 0x00, 0xA2, 0x00, 0xA0, 0x00, 0xDD, },
	/* 220 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x78, 0x6F, 0x58, 0xBF,
	  0xC4, 0xB3, 0xB5, 0xBB, 0xA9, 0xC8, 0xCC,
	  0xBC, 0x00, 0xA6, 0x00, 0xA3, 0x00, 0xE2, },
	/* 230 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x75, 0x6F, 0x56, 0xBF,
	  0xC3, 0xB2, 0xB6, 0xBB, 0xA8, 0xC7, 0xCB,
	  0xBC, 0x00, 0xA8, 0x00, 0xA6, 0x00, 0xE6, },
	/* 240 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x76, 0x6F, 0x56, 0xC0,
	  0xC3, 0xB2, 0xB5, 0xBA, 0xA8, 0xC6, 0xCB,
	  0xBB, 0x00, 0xAA, 0x00, 0xA8, 0x00, 0xE9, },
	/* 250 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x74, 0x6D, 0x54, 0xBF,
	  0xC3, 0xB2, 0xB4, 0xBA, 0xA7, 0xC6, 0xCA,
	  0xBA, 0x00, 0xAD, 0x00, 0xAB, 0x00, 0xED, },
	/* 260 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x74, 0x6E, 0x54, 0xBD,
	  0xC2, 0xB0, 0xB5, 0xBA, 0xA7, 0xC5, 0xC9,
	  0xBA, 0x00, 0xB0, 0x00, 0xAE, 0x00, 0xF1, },
	/* 270 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x71, 0x6C, 0x50, 0xBD,
	  0xC3, 0xB0, 0xB4, 0xB8, 0xA6, 0xC6, 0xC9,
	  0xBB, 0x00, 0xB2, 0x00, 0xB1, 0x00, 0xF4, },
	/* 280 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x6E, 0x6C, 0x4D, 0xBE,
	  0xC3, 0xB1, 0xB3, 0xB8, 0xA5, 0xC6, 0xC8,
	  0xBB, 0x00, 0xB4, 0x00, 0xB3, 0x00, 0xF7, },
	/* 290 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x71, 0x70, 0x50, 0xBD,
	  0xC1, 0xB0, 0xB2, 0xB8, 0xA4, 0xC6, 0xC7,
	  0xBB, 0x00, 0xB6, 0x00, 0xB6, 0x00, 0xFA, },
	/* 300 cd */
	{ MCS_PGAMMACTL, 0x02,
	  0x18, 0x08, 0x24, 0x70, 0x6E, 0x4E, 0xBC,
	  0xC0, 0xAF, 0xB3, 0xB8, 0xA5, 0xC5, 0xC7,
	  0xBB, 0x00, 0xB9, 0x00, 0xB8, 0x00, 0xFC, },
};

#define NUM_ACL_LEVELS 7
#define ACL_TABLE_COUNT 28

static u8 const s6e63m0_acl[NUM_ACL_LEVELS][ACL_TABLE_COUNT] = {
	/* NULL ACL */
	{ MCS_BCMODE,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00 },
	/* 40P ACL */
	{ MCS_BCMODE,
	  0x4D, 0x96, 0x1D, 0x00, 0x00, 0x01, 0xDF, 0x00,
	  0x00, 0x03, 0x1F, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x01, 0x06, 0x0C, 0x11, 0x16, 0x1C, 0x21, 0x26,
	  0x2B, 0x31, 0x36 },
	/* 43P ACL */
	{ MCS_BCMODE,
	  0x4D, 0x96, 0x1D, 0x00, 0x00, 0x01, 0xDF, 0x00,
	  0x00, 0x03, 0x1F, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x01, 0x07, 0x0C, 0x12, 0x18, 0x1E, 0x23, 0x29,
	  0x2F, 0x34, 0x3A },
	/* 45P ACL */
	{ MCS_BCMODE,
	  0x4D, 0x96, 0x1D, 0x00, 0x00, 0x01, 0xDF, 0x00,
	  0x00, 0x03, 0x1F, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x01, 0x07, 0x0D, 0x13, 0x19, 0x1F, 0x25, 0x2B,
	  0x31, 0x37, 0x3D },
	/* 47P ACL */
	{ MCS_BCMODE,
	  0x4D, 0x96, 0x1D, 0x00, 0x00, 0x01, 0xDF, 0x00,
	  0x00, 0x03, 0x1F, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x01, 0x07, 0x0E, 0x14, 0x1B, 0x21, 0x27, 0x2E,
	  0x34, 0x3B, 0x41 },
	/* 48P ACL */
	{ MCS_BCMODE,
	  0x4D, 0x96, 0x1D, 0x00, 0x00, 0x01, 0xDF, 0x00,
	  0x00, 0x03, 0x1F, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x01, 0x08, 0x0E, 0x15, 0x1B, 0x22, 0x29, 0x2F,
	  0x36, 0x3C, 0x43 },
	/* 50P ACL */
	{ MCS_BCMODE,
	  0x4D, 0x96, 0x1D, 0x00, 0x00, 0x01, 0xDF, 0x00,
	  0x00, 0x03, 0x1F, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x01, 0x08, 0x0F, 0x16, 0x1D, 0x24, 0x2A, 0x31,
	  0x38, 0x3F, 0x46 },
};

/* This tells us which ACL level goes with which gamma */
static u8 const s6e63m0_acl_per_gamma[NUM_GAMMA_LEVELS] = {
	/* 30 - 60 cd: ACL off/NULL */
	0, 0, 0, 0,
	/* 70 - 250 cd: 40P ACL */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	/* 260 - 300 cd: 50P ACL */
	6, 6, 6, 6, 6,
};

/* The ELVSS backlight regulator has 5 levels */
#define S6E63M0_ELVSS_LEVELS 5

static u8 const s6e63m0_elvss_offsets[S6E63M0_ELVSS_LEVELS] = {
	0x00,   /* not set */
	0x0D,   /* 30 cd - 100 cd */
	0x09,   /* 110 cd - 160 cd */
	0x07,   /* 170 cd - 200 cd */
	0x00,   /* 210 cd - 300 cd */
};

/* This tells us which ELVSS level goes with which gamma */
static u8 const s6e63m0_elvss_per_gamma[NUM_GAMMA_LEVELS] = {
	/* 30 - 100 cd */
	1, 1, 1, 1, 1, 1, 1, 1,
	/* 110 - 160 cd */
	2, 2, 2, 2, 2, 2,
	/* 170 - 200 cd */
	3, 3, 3, 3,
	/* 210 - 300 cd */
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
};

struct s6e63m0 {
	struct device *dev;
	void *transport_data;
	int (*dcs_read)(struct device *dev, void *trsp, const u8 cmd, u8 *val);
	int (*dcs_write)(struct device *dev, void *trsp, const u8 *data, size_t len);
	struct drm_panel panel;
	struct backlight_device *bl_dev;
	u8 lcd_type;
	u8 elvss_pulse;
	bool dsi_mode;

	struct regulator_bulk_data supplies[2];
	struct gpio_desc *reset_gpio;

	/*
	 * This field is tested by functions directly accessing bus before
	 * transfer, transfer is skipped if it is set. In case of transfer
	 * failure or unexpected response the field is set to error value.
	 * Such construct allows to eliminate many checks in higher level
	 * functions.
	 */
	int error;
};

static const struct drm_display_mode default_mode = {
	.clock		= 25628,
	.hdisplay	= 480,
	.hsync_start	= 480 + 16,
	.hsync_end	= 480 + 16 + 2,
	.htotal		= 480 + 16 + 2 + 16,
	.vdisplay	= 800,
	.vsync_start	= 800 + 28,
	.vsync_end	= 800 + 28 + 2,
	.vtotal		= 800 + 28 + 2 + 1,
	.width_mm	= 53,
	.height_mm	= 89,
	.flags		= DRM_MODE_FLAG_NVSYNC | DRM_MODE_FLAG_NHSYNC,
};

static inline struct s6e63m0 *panel_to_s6e63m0(struct drm_panel *panel)
{
	return container_of(panel, struct s6e63m0, panel);
}

static int s6e63m0_clear_error(struct s6e63m0 *ctx)
{
	int ret = ctx->error;

	ctx->error = 0;
	return ret;
}

static void s6e63m0_dcs_read(struct s6e63m0 *ctx, const u8 cmd, u8 *data)
{
	if (ctx->error < 0)
		return;

	ctx->error = ctx->dcs_read(ctx->dev, ctx->transport_data, cmd, data);
}

static void s6e63m0_dcs_write(struct s6e63m0 *ctx, const u8 *data, size_t len)
{
	if (ctx->error < 0 || len == 0)
		return;

	ctx->error = ctx->dcs_write(ctx->dev, ctx->transport_data, data, len);
}

#define s6e63m0_dcs_write_seq_static(ctx, seq ...) \
	({ \
		static const u8 d[] = { seq }; \
		s6e63m0_dcs_write(ctx, d, ARRAY_SIZE(d)); \
	})

static int s6e63m0_check_lcd_type(struct s6e63m0 *ctx)
{
	u8 id1, id2, id3;
	int ret;

	s6e63m0_dcs_read(ctx, MCS_READ_ID1, &id1);
	s6e63m0_dcs_read(ctx, MCS_READ_ID2, &id2);
	s6e63m0_dcs_read(ctx, MCS_READ_ID3, &id3);

	ret = s6e63m0_clear_error(ctx);
	if (ret) {
		dev_err(ctx->dev, "error checking LCD type (%d)\n", ret);
		ctx->lcd_type = 0x00;
		return ret;
	}

	dev_info(ctx->dev, "MTP ID: %02x %02x %02x\n", id1, id2, id3);

	/*
	 * We attempt to detect what panel is mounted on the controller.
	 * The third ID byte represents the desired ELVSS pulse for
	 * some displays.
	 */
	switch (id2) {
	case S6E63M0_LCD_ID_VALUE_M2:
		dev_info(ctx->dev, "detected LCD panel AMS397GE MIPI M2\n");
		ctx->elvss_pulse = id3;
		break;
	case S6E63M0_LCD_ID_VALUE_SM2:
	case S6E63M0_LCD_ID_VALUE_SM2_1:
		dev_info(ctx->dev, "detected LCD panel AMS397GE MIPI SM2\n");
		ctx->elvss_pulse = id3;
		break;
	default:
		dev_info(ctx->dev, "unknown LCD panel type %02x\n", id2);
		/* Default ELVSS pulse level */
		ctx->elvss_pulse = 0x16;
		break;
	}

	ctx->lcd_type = id2;

	return 0;
}

static void s6e63m0_init(struct s6e63m0 *ctx)
{
	/*
	 * We do not know why there is a difference in the DSI mode.
	 * (No datasheet.)
	 *
	 * In the vendor driver this sequence is called
	 * "SEQ_PANEL_CONDITION_SET" or "DCS_CMD_SEQ_PANEL_COND_SET".
	 */
	if (ctx->dsi_mode)
		s6e63m0_dcs_write_seq_static(ctx, MCS_PANELCTL,
					     0x01, 0x2c, 0x2c, 0x07, 0x07, 0x5f, 0xb3,
					     0x6d, 0x97, 0x1d, 0x3a, 0x0f, 0x00, 0x00);
	else
		s6e63m0_dcs_write_seq_static(ctx, MCS_PANELCTL,
					     0x01, 0x27, 0x27, 0x07, 0x07, 0x54, 0x9f,
					     0x63, 0x8f, 0x1a, 0x33, 0x0d, 0x00, 0x00);

	s6e63m0_dcs_write_seq_static(ctx, MCS_DISCTL,
				     0x02, 0x03, 0x1c, 0x10, 0x10);
	s6e63m0_dcs_write_seq_static(ctx, MCS_IFCTL,
				     0x03, 0x00, 0x00);

	s6e63m0_dcs_write_seq_static(ctx, MCS_PGAMMACTL,
				     0x00, 0x18, 0x08, 0x24, 0x64, 0x56, 0x33,
				     0xb6, 0xba, 0xa8, 0xac, 0xb1, 0x9d, 0xc1,
				     0xc1, 0xb7, 0x00, 0x9c, 0x00, 0x9f, 0x00,
				     0xd6);
	s6e63m0_dcs_write_seq_static(ctx, MCS_PGAMMACTL,
				     0x01);

	s6e63m0_dcs_write_seq_static(ctx, MCS_SRCCTL,
				     0x00, 0x8e, 0x07);
	s6e63m0_dcs_write_seq_static(ctx, MCS_PENTILE_1, 0x6c);

	s6e63m0_dcs_write_seq_static(ctx, MCS_GAMMA_DELTA_Y_RED,
				     0x2c, 0x12, 0x0c, 0x0a, 0x10, 0x0e, 0x17,
				     0x13, 0x1f, 0x1a, 0x2a, 0x24, 0x1f, 0x1b,
				     0x1a, 0x17, 0x2b, 0x26, 0x22, 0x20, 0x3a,
				     0x34, 0x30, 0x2c, 0x29, 0x26, 0x25, 0x23,
				     0x21, 0x20, 0x1e, 0x1e);

	s6e63m0_dcs_write_seq_static(ctx, MCS_GAMMA_DELTA_X_RED,
				     0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x44,
				     0x44, 0x55, 0x55, 0x66, 0x66, 0x66, 0x66,
				     0x66, 0x66);

	s6e63m0_dcs_write_seq_static(ctx, MCS_GAMMA_DELTA_Y_GREEN,
				     0x2c, 0x12, 0x0c, 0x0a, 0x10, 0x0e, 0x17,
				     0x13, 0x1f, 0x1a, 0x2a, 0x24, 0x1f, 0x1b,
				     0x1a, 0x17, 0x2b, 0x26, 0x22, 0x20, 0x3a,
				     0x34, 0x30, 0x2c, 0x29, 0x26, 0x25, 0x23,
				     0x21, 0x20, 0x1e, 0x1e);

	s6e63m0_dcs_write_seq_static(ctx, MCS_GAMMA_DELTA_X_GREEN,
				     0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x44,
				     0x44, 0x55, 0x55, 0x66, 0x66, 0x66, 0x66,
				     0x66, 0x66);

	s6e63m0_dcs_write_seq_static(ctx, MCS_GAMMA_DELTA_Y_BLUE,
				     0x2c, 0x12, 0x0c, 0x0a, 0x10, 0x0e, 0x17,
				     0x13, 0x1f, 0x1a, 0x2a, 0x24, 0x1f, 0x1b,
				     0x1a, 0x17, 0x2b, 0x26, 0x22, 0x20, 0x3a,
				     0x34, 0x30, 0x2c, 0x29, 0x26, 0x25, 0x23,
				     0x21, 0x20, 0x1e, 0x1e);

	s6e63m0_dcs_write_seq_static(ctx, MCS_GAMMA_DELTA_X_BLUE,
				     0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x44,
				     0x44, 0x55, 0x55, 0x66, 0x66, 0x66, 0x66,
				     0x66, 0x66);

	s6e63m0_dcs_write_seq_static(ctx, MCS_BCMODE,
				     0x4d, 0x96, 0x1d, 0x00, 0x00, 0x01, 0xdf,
				     0x00, 0x00, 0x03, 0x1f, 0x00, 0x00, 0x00,
				     0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x06,
				     0x09, 0x0d, 0x0f, 0x12, 0x15, 0x18);

	s6e63m0_dcs_write_seq_static(ctx, MCS_TEMP_SWIRE,
				     0x10, 0x10, 0x0b, 0x05);

	s6e63m0_dcs_write_seq_static(ctx, MCS_MIECTL1,
				     0x01);

	s6e63m0_dcs_write_seq_static(ctx, MCS_ELVSS_ON,
				     0x0b);
}

static int s6e63m0_power_on(struct s6e63m0 *ctx)
{
	int ret;

	ret = regulator_bulk_enable(ARRAY_SIZE(ctx->supplies), ctx->supplies);
	if (ret < 0)
		return ret;

	msleep(25);

	/* Be sure to send a reset pulse */
	gpiod_set_value(ctx->reset_gpio, 1);
	msleep(5);
	gpiod_set_value(ctx->reset_gpio, 0);
	msleep(120);

	return 0;
}

static int s6e63m0_power_off(struct s6e63m0 *ctx)
{
	int ret;

	gpiod_set_value(ctx->reset_gpio, 1);
	msleep(120);

	ret = regulator_bulk_disable(ARRAY_SIZE(ctx->supplies), ctx->supplies);
	if (ret < 0)
		return ret;

	return 0;
}

static int s6e63m0_disable(struct drm_panel *panel)
{
	struct s6e63m0 *ctx = panel_to_s6e63m0(panel);

	backlight_disable(ctx->bl_dev);

	s6e63m0_dcs_write_seq_static(ctx, MIPI_DCS_SET_DISPLAY_OFF);
	msleep(10);
	s6e63m0_dcs_write_seq_static(ctx, MIPI_DCS_ENTER_SLEEP_MODE);
	msleep(120);

	return 0;
}

static int s6e63m0_unprepare(struct drm_panel *panel)
{
	struct s6e63m0 *ctx = panel_to_s6e63m0(panel);
	int ret;

	s6e63m0_clear_error(ctx);

	ret = s6e63m0_power_off(ctx);
	if (ret < 0)
		return ret;

	return 0;
}

static int s6e63m0_prepare(struct drm_panel *panel)
{
	struct s6e63m0 *ctx = panel_to_s6e63m0(panel);
	int ret;

	ret = s6e63m0_power_on(ctx);
	if (ret < 0)
		return ret;

	/* Magic to unlock level 2 control of the display */
	s6e63m0_dcs_write_seq_static(ctx, MCS_LEVEL_2_KEY, 0x5a, 0x5a);
	/* Magic to unlock MTP reading */
	s6e63m0_dcs_write_seq_static(ctx, MCS_MTP_KEY, 0x5a, 0x5a);

	ret = s6e63m0_check_lcd_type(ctx);
	if (ret < 0)
		return ret;

	s6e63m0_init(ctx);

	ret = s6e63m0_clear_error(ctx);

	if (ret < 0)
		s6e63m0_unprepare(panel);

	return ret;
}

static int s6e63m0_enable(struct drm_panel *panel)
{
	struct s6e63m0 *ctx = panel_to_s6e63m0(panel);

	s6e63m0_dcs_write_seq_static(ctx, MIPI_DCS_EXIT_SLEEP_MODE);
	msleep(120);
	s6e63m0_dcs_write_seq_static(ctx, MIPI_DCS_SET_DISPLAY_ON);
	msleep(10);

	s6e63m0_dcs_write_seq_static(ctx, MCS_ERROR_CHECK,
				     0xE7, 0x14, 0x60, 0x17, 0x0A, 0x49, 0xC3,
				     0x8F, 0x19, 0x64, 0x91, 0x84, 0x76, 0x20,
				     0x0F, 0x00);

	backlight_enable(ctx->bl_dev);

	return 0;
}

static int s6e63m0_get_modes(struct drm_panel *panel,
			     struct drm_connector *connector)
{
	struct drm_display_mode *mode;
	static const u32 bus_format = MEDIA_BUS_FMT_RGB888_1X24;

	mode = drm_mode_duplicate(connector->dev, &default_mode);
	if (!mode) {
		dev_err(panel->dev, "failed to add mode %ux%u@%u\n",
			default_mode.hdisplay, default_mode.vdisplay,
			drm_mode_vrefresh(&default_mode));
		return -ENOMEM;
	}

	connector->display_info.width_mm = mode->width_mm;
	connector->display_info.height_mm = mode->height_mm;
	drm_display_info_set_bus_formats(&connector->display_info,
					 &bus_format, 1);
	connector->display_info.bus_flags = DRM_BUS_FLAG_DE_LOW |
		DRM_BUS_FLAG_PIXDATA_DRIVE_NEGEDGE;

	drm_mode_set_name(mode);

	mode->type = DRM_MODE_TYPE_DRIVER | DRM_MODE_TYPE_PREFERRED;
	drm_mode_probed_add(connector, mode);

	return 1;
}

static const struct drm_panel_funcs s6e63m0_drm_funcs = {
	.disable	= s6e63m0_disable,
	.unprepare	= s6e63m0_unprepare,
	.prepare	= s6e63m0_prepare,
	.enable		= s6e63m0_enable,
	.get_modes	= s6e63m0_get_modes,
};

static int s6e63m0_set_brightness(struct backlight_device *bd)
{
	struct s6e63m0 *ctx = bl_get_data(bd);
	int brightness = bd->props.brightness;
	u8 elvss_val;
	u8 elvss_cmd_set[5];
	int i;

	/* Adjust ELVSS to candela level */
	i = s6e63m0_elvss_per_gamma[brightness];
	elvss_val = ctx->elvss_pulse + s6e63m0_elvss_offsets[i];
	if (elvss_val > 0x1f)
		elvss_val = 0x1f;
	elvss_cmd_set[0] = MCS_TEMP_SWIRE;
	elvss_cmd_set[1] = elvss_val;
	elvss_cmd_set[2] = elvss_val;
	elvss_cmd_set[3] = elvss_val;
	elvss_cmd_set[4] = elvss_val;
	s6e63m0_dcs_write(ctx, elvss_cmd_set, 5);

	/* Update the ACL per gamma value */
	i = s6e63m0_acl_per_gamma[brightness];
	s6e63m0_dcs_write(ctx, s6e63m0_acl[i],
			  ARRAY_SIZE(s6e63m0_acl[i]));

	/* Update gamma table */
	s6e63m0_dcs_write(ctx, s6e63m0_gamma_22[brightness],
			  ARRAY_SIZE(s6e63m0_gamma_22[brightness]));
	s6e63m0_dcs_write_seq_static(ctx, MCS_PGAMMACTL, 0x03);


	return s6e63m0_clear_error(ctx);
}

static const struct backlight_ops s6e63m0_backlight_ops = {
	.update_status	= s6e63m0_set_brightness,
};

static int s6e63m0_backlight_register(struct s6e63m0 *ctx, u32 max_brightness)
{
	struct backlight_properties props = {
		.type		= BACKLIGHT_RAW,
		.brightness	= max_brightness,
		.max_brightness = max_brightness,
	};
	struct device *dev = ctx->dev;
	int ret = 0;

	ctx->bl_dev = devm_backlight_device_register(dev, "panel", dev, ctx,
						     &s6e63m0_backlight_ops,
						     &props);
	if (IS_ERR(ctx->bl_dev)) {
		ret = PTR_ERR(ctx->bl_dev);
		dev_err(dev, "error registering backlight device (%d)\n", ret);
	}

	return ret;
}

int s6e63m0_probe(struct device *dev, void *trsp,
		  int (*dcs_read)(struct device *dev, void *trsp, const u8 cmd, u8 *val),
		  int (*dcs_write)(struct device *dev, void *trsp, const u8 *data, size_t len),
		  bool dsi_mode)
{
	struct s6e63m0 *ctx;
	u32 max_brightness;
	int ret;

	ctx = devm_kzalloc(dev, sizeof(struct s6e63m0), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->transport_data = trsp;
	ctx->dsi_mode = dsi_mode;
	ctx->dcs_read = dcs_read;
	ctx->dcs_write = dcs_write;
	dev_set_drvdata(dev, ctx);

	ctx->dev = dev;

	ret = device_property_read_u32(dev, "max-brightness", &max_brightness);
	if (ret)
		max_brightness = MAX_BRIGHTNESS;
	if (max_brightness > MAX_BRIGHTNESS) {
		dev_err(dev, "illegal max brightness specified\n");
		max_brightness = MAX_BRIGHTNESS;
	}

	ctx->supplies[0].supply = "vdd3";
	ctx->supplies[1].supply = "vci";
	ret = devm_regulator_bulk_get(dev, ARRAY_SIZE(ctx->supplies),
				      ctx->supplies);
	if (ret < 0) {
		dev_err(dev, "failed to get regulators: %d\n", ret);
		return ret;
	}

	ctx->reset_gpio = devm_gpiod_get(dev, "reset", GPIOD_OUT_HIGH);
	if (IS_ERR(ctx->reset_gpio)) {
		dev_err(dev, "cannot get reset-gpios %ld\n", PTR_ERR(ctx->reset_gpio));
		return PTR_ERR(ctx->reset_gpio);
	}

	drm_panel_init(&ctx->panel, dev, &s6e63m0_drm_funcs,
		       dsi_mode ? DRM_MODE_CONNECTOR_DSI :
		       DRM_MODE_CONNECTOR_DPI);

	ret = s6e63m0_backlight_register(ctx, max_brightness);
	if (ret < 0)
		return ret;

	drm_panel_add(&ctx->panel);

	return 0;
}
EXPORT_SYMBOL_GPL(s6e63m0_probe);

void s6e63m0_remove(struct device *dev)
{
	struct s6e63m0 *ctx = dev_get_drvdata(dev);

	drm_panel_remove(&ctx->panel);
}
EXPORT_SYMBOL_GPL(s6e63m0_remove);

MODULE_AUTHOR("Paweł Chmiel <pawel.mikolaj.chmiel@gmail.com>");
MODULE_DESCRIPTION("s6e63m0 LCD Driver");
MODULE_LICENSE("GPL v2");
