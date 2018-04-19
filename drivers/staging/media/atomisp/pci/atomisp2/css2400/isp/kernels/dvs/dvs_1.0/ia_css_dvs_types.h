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

#ifndef __IA_CSS_DVS_TYPES_H
#define __IA_CSS_DVS_TYPES_H

/* DVS frame
 *
 *  ISP block: dvs frame
 */

#include "ia_css_frame_public.h"

struct ia_css_dvs_configuration {
	const struct ia_css_frame_info *info;
};

#endif /* __IA_CSS_DVS_TYPES_H */

