/* SPDX-License-Identifier: GPL-2.0 */
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

#ifndef __SH_CSS_MIPI_H
#define __SH_CSS_MIPI_H

#include <ia_css_err.h>		  /* ia_css_err */
#include <ia_css_types.h>	  /* ia_css_pipe */
#include <ia_css_stream_public.h> /* ia_css_stream_config */

void
mipi_init(void);

bool mipi_is_free(void);

int
allocate_mipi_frames(struct ia_css_pipe *pipe, struct ia_css_stream_info *info);

int
free_mipi_frames(struct ia_css_pipe *pipe);

int
send_mipi_frames(struct ia_css_pipe *pipe);

#endif /* __SH_CSS_MIPI_H */
