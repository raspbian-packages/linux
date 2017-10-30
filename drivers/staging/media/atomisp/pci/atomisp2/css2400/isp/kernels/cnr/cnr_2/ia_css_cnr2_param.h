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

#ifndef __IA_CSS_CNR2_PARAM_H
#define __IA_CSS_CNR2_PARAM_H

#include "type_support.h"

/* CNR (Chroma Noise Reduction) */
struct sh_css_isp_cnr_params {
	int32_t coring_u;
	int32_t coring_v;
	int32_t sense_gain_vy;
	int32_t sense_gain_vu;
	int32_t sense_gain_vv;
	int32_t sense_gain_hy;
	int32_t sense_gain_hu;
	int32_t sense_gain_hv;
};

#endif /* __IA_CSS_CNR2_PARAM_H */
