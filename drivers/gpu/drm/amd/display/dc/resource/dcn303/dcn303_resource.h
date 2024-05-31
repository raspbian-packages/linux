// SPDX-License-Identifier: MIT
/*
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: AMD
 */

#ifndef _DCN303_RESOURCE_H_
#define _DCN303_RESOURCE_H_

#include "core_types.h"

extern struct _vcs_dpi_ip_params_st dcn3_03_ip;
extern struct _vcs_dpi_soc_bounding_box_st dcn3_03_soc;

struct resource_pool *dcn303_create_resource_pool(const struct dc_init_data *init_data, struct dc *dc);

void dcn303_update_bw_bounding_box(struct dc *dc, struct clk_bw_params *bw_params);

#endif /* _DCN303_RESOURCE_H_ */
