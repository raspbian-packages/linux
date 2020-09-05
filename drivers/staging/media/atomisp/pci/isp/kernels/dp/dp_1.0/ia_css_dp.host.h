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

#ifndef __IA_CSS_DP_HOST_H
#define __IA_CSS_DP_HOST_H

#include "ia_css_dp_types.h"
#include "ia_css_dp_param.h"

extern const struct ia_css_dp_config default_dp_config;

/* ISP2401 */
extern const struct ia_css_dp_config default_dp_10bpp_config;

void
ia_css_dp_encode(
    struct sh_css_isp_dp_params *to,
    const struct ia_css_dp_config *from,
    unsigned int size);

void
ia_css_dp_dump(
    const struct sh_css_isp_dp_params *dp,
    unsigned int level);

void
ia_css_dp_debug_dtrace(
    const struct ia_css_dp_config *config,
    unsigned int level);

void
ia_css_init_dp_state(
    void/*struct sh_css_isp_dp_vmem_state*/ * state,
    size_t size);

#endif /* __IA_CSS_DP_HOST_H */
