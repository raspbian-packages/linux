/*
 * Support for Intel Camera Imaging ISP subsystem.
 * Copyright (c) 2015, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef __IA_CSS_SDIS_COMMON_TYPES_H
#define __IA_CSS_SDIS_COMMON_TYPES_H

/** @file
* CSS-API header file for DVS statistics parameters.
*/

#include <type_support.h>

/** DVS statistics grid dimensions in number of cells.
 */

struct ia_css_dvs_grid_dim {
	uint32_t width;		/**< Width of DVS grid table in cells */
	uint32_t height;	/**< Height of DVS grid table in cells */
};

/** DVS statistics dimensions in number of cells for
 * grid, coeffieicient and projection.
 */

struct ia_css_sdis_info {
	struct {
		struct ia_css_dvs_grid_dim dim; /* Dimensions */
		struct ia_css_dvs_grid_dim pad; /* Padded dimensions */
	} grid, coef, proj;
	uint32_t deci_factor_log2;
};

#define IA_CSS_DEFAULT_SDIS_INFO \
	{	\
		{	{ 0, 0 },	/* dim */ \
			{ 0, 0 },	/* pad */ \
		},	/* grid */ \
		{	{ 0, 0 },	/* dim */ \
			{ 0, 0 },	/* pad */ \
		},	/* coef */ \
		{	{ 0, 0 },	/* dim */ \
			{ 0, 0 },	/* pad */ \
		},	/* proj */ \
		0,	/* dis_deci_factor_log2 */ \
	}

/** DVS statistics grid
 *
 *  ISP block: SDVS1 (DIS/DVS Support for DIS/DVS ver.1 (2-axes))
 *             SDVS2 (DVS Support for DVS ver.2 (6-axes))
 *  ISP1: SDVS1 is used.
 *  ISP2: SDVS2 is used.
 */
struct ia_css_dvs_grid_res {
	uint32_t width;	    	/**< Width of DVS grid table.
					(= Horizontal number of grid cells
					in table, which cells have effective
					statistics.)
					For DVS1, this is equal to
					 the number of vertical statistics. */
	uint32_t aligned_width; /**< Stride of each grid line.
					(= Horizontal number of grid cells
					in table, which means
					the allocated width.) */
	uint32_t height;	/**< Height of DVS grid table.
					(= Vertical number of grid cells
					in table, which cells have effective
					statistics.)
					For DVS1, This is equal to
					the number of horizontal statistics. */
	uint32_t aligned_height;/**< Stride of each grid column.
					(= Vertical number of grid cells
					in table, which means
					the allocated height.) */
};

/* TODO: use ia_css_dvs_grid_res in here.
 * However, that implies driver I/F changes
 */
struct ia_css_dvs_grid_info {
	uint32_t enable;        /**< DVS statistics enabled.
					0:disabled, 1:enabled */
	uint32_t width;	    	/**< Width of DVS grid table.
					(= Horizontal number of grid cells
					in table, which cells have effective
					statistics.)
					For DVS1, this is equal to
					 the number of vertical statistics. */
	uint32_t aligned_width; /**< Stride of each grid line.
					(= Horizontal number of grid cells
					in table, which means
					the allocated width.) */
	uint32_t height;	/**< Height of DVS grid table.
					(= Vertical number of grid cells
					in table, which cells have effective
					statistics.)
					For DVS1, This is equal to
					the number of horizontal statistics. */
	uint32_t aligned_height;/**< Stride of each grid column.
					(= Vertical number of grid cells
					in table, which means
					the allocated height.) */
	uint32_t bqs_per_grid_cell; /**< Grid cell size in BQ(Bayer Quad) unit.
					(1BQ means {Gr,R,B,Gb}(2x2 pixels).)
					For DVS1, valid value is 64.
					For DVS2, valid value is only 64,
					currently. */
	uint32_t num_hor_coefs;	/**< Number of horizontal coefficients. */
	uint32_t num_ver_coefs;	/**< Number of vertical coefficients. */
};

/** Number of DVS statistics levels
 */
#define IA_CSS_DVS_STAT_NUM_OF_LEVELS	3

/** DVS statistics generated by accelerator global configuration
 */
struct dvs_stat_public_dvs_global_cfg {
	unsigned char kappa;
	/**< DVS statistics global configuration - kappa */
	unsigned char match_shift;
	/**< DVS statistics global configuration - match_shift */
	unsigned char ybin_mode;
	/**< DVS statistics global configuration - y binning mode */
};

/** DVS statistics generated by accelerator level grid
 *  configuration
 */
struct dvs_stat_public_dvs_level_grid_cfg {
	unsigned char grid_width;
	/**< DVS statistics grid width */
	unsigned char grid_height;
	/**< DVS statistics grid height */
	unsigned char block_width;
	/**< DVS statistics block width */
	unsigned char block_height;
	/**< DVS statistics block  height */
};

/** DVS statistics generated by accelerator level grid start
 *  configuration
 */
struct dvs_stat_public_dvs_level_grid_start {
	unsigned short x_start;
	/**< DVS statistics level x start */
	unsigned short y_start;
	/**< DVS statistics level y start */
	unsigned char enable;
	/**< DVS statistics level enable */
};

/** DVS statistics generated by accelerator level grid end
 *  configuration
 */
struct dvs_stat_public_dvs_level_grid_end {
	unsigned short x_end;
	/**< DVS statistics level x end */
	unsigned short y_end;
	/**< DVS statistics level y end */
};

/** DVS statistics generated by accelerator Feature Extraction
 *  Region Of Interest (FE-ROI) configuration
 */
struct dvs_stat_public_dvs_level_fe_roi_cfg {
	unsigned char x_start;
	/**< DVS statistics fe-roi level x start */
	unsigned char y_start;
	/**< DVS statistics fe-roi level y start */
	unsigned char x_end;
	/**< DVS statistics fe-roi level x end */
	unsigned char y_end;
	/**< DVS statistics fe-roi level y end */
};

/** DVS statistics generated by accelerator public configuration
 */
struct dvs_stat_public_dvs_grd_cfg {
	struct dvs_stat_public_dvs_level_grid_cfg    grd_cfg;
	/**< DVS statistics level grid configuration */
	struct dvs_stat_public_dvs_level_grid_start  grd_start;
	/**< DVS statistics level grid start configuration */
	struct dvs_stat_public_dvs_level_grid_end    grd_end;
	/**< DVS statistics level grid end configuration */
};

/** DVS statistics grid generated by accelerator
 */
struct ia_css_dvs_stat_grid_info {
	struct dvs_stat_public_dvs_global_cfg       dvs_gbl_cfg;
	/**< DVS statistics global configuration (kappa, match, binning) */
	struct dvs_stat_public_dvs_grd_cfg       grd_cfg[IA_CSS_DVS_STAT_NUM_OF_LEVELS];
	/**< DVS statistics grid configuration (blocks and grids) */
	struct dvs_stat_public_dvs_level_fe_roi_cfg fe_roi_cfg[IA_CSS_DVS_STAT_NUM_OF_LEVELS];
	/**< DVS statistics FE ROI (region of interest) configuration */
};

/** DVS statistics generated by accelerator default grid info
 */
#define DEFAULT_DVS_GRID_INFO { \
{ \
	{ 0, 0, 0},	/* GBL CFG reg: kappa, match_shifrt, binning mode*/ \
	{{{0, 0, 0, 0}, {0, 0, 0}, {0, 0} }, \
	{{0, 0, 0, 0}, {0, 0, 0}, {0, 0} }, \
	{{0, 0, 0, 0}, {0, 0, 0}, {0, 0} } }, \
	{{0, 0, 0, 0}, {4, 0, 0, 0}, {0, 0, 0, 0} } } \
}


/** Union that holds all types of DVS statistics grid info in
 *  CSS format
 * */
union ia_css_dvs_grid_u {
	struct ia_css_dvs_stat_grid_info dvs_stat_grid_info;
	/**< DVS statistics produced by accelerator grid info */
	struct ia_css_dvs_grid_info dvs_grid_info;
	/**< DVS (DVS1/DVS2) grid info */
};

#endif /* __IA_CSS_SDIS_COMMON_TYPES_H */
