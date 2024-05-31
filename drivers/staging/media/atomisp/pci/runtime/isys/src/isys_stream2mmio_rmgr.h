/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Support for Intel Camera Imaging ISP subsystem.
 * Copyright (c) 2010 - 2015, Intel Corporation.
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

#ifndef __ISYS_STREAM2MMIO_RMGR_H_INCLUDED__
#define __ISYS_STREAM2MMIO_RMGR_H_INCLUDED__

typedef struct isys_stream2mmio_rsrc_s isys_stream2mmio_rsrc_t;
struct isys_stream2mmio_rsrc_s {
	u32	active_table;
	u16	num_active;
};

#endif /* __ISYS_STREAM2MMIO_RMGR_H_INCLUDED__ */
