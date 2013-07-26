/******************************************************************************
 *
 * Copyright(c) 2007 - 2011 Realtek Corporation. All rights reserved.
 *                                        
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110, USA
 *
 *
 ******************************************************************************/
#ifndef __RTW_IOL_H_
#define __RTW_IOL_H_

#include <drv_conf.h>
#include <osdep_service.h>
#include <drv_types.h>

typedef struct _io_offload_cmd {
	u8 rsvd0;
	u8 cmd;
	u16 address;
	u32 value;
} IO_OFFLOAD_CMD, IOL_CMD;

#define IOL_CMD_LLT			0x00
//#define IOL_CMD_R_EFUSE	0x01
#define IOL_CMD_WB_REG		0x02
#define IOL_CMD_WW_REG 	0x03
#define IOL_CMD_WD_REG		0x04
//#define IOL_CMD_W_RF		0x05
#define IOL_CMD_DELAY_US	0x80
#define IOL_CMD_DELAY_MS	0x81
//#define IOL_CMD_DELAY_S	0x82
#define IOL_CMD_END			0x83

/*****************************************************
CMD					Address			Value
(B1)					(B2/B3:H/L addr)	(B4:B7 : MSB:LSB)
******************************************************
IOL_CMD_LLT			-				B7: PGBNDY
//IOL_CMD_R_EFUSE	-				-
IOL_CMD_WB_REG		0x0~0xFFFF		B7
IOL_CMD_WW_REG	0x0~0xFFFF		B6~B7
IOL_CMD_WD_REG	0x0~0xFFFF		B4~B7
//IOL_CMD_W_RF		RF Reg			B5~B7
IOL_CMD_DELAY_US	-				B6~B7
IOL_CMD_DELAY_MS	-				B6~B7
//IOL_CMD_DELAY_S	-				B6~B7
IOL_CMD_END		-				-
******************************************************/

struct xmit_frame	*rtw_IOL_accquire_xmit_frame(ADAPTER *adapter);
int rtw_IOL_append_cmds(struct xmit_frame *xmit_frame, u8 *IOL_cmds, u32 cmd_len);
int rtw_IOL_append_LLT_cmd(struct xmit_frame *xmit_frame, u8 page_boundary);
int _rtw_IOL_append_WB_cmd(struct xmit_frame *xmit_frame, u16 addr, u8 value);
int _rtw_IOL_append_WW_cmd(struct xmit_frame *xmit_frame, u16 addr, u16 value);
int _rtw_IOL_append_WD_cmd(struct xmit_frame *xmit_frame, u16 addr, u32 value);
int rtw_IOL_append_DELAY_US_cmd(struct xmit_frame *xmit_frame, u16 us);
int rtw_IOL_append_DELAY_MS_cmd(struct xmit_frame *xmit_frame, u16 ms);
int rtw_IOL_append_END_cmd(struct xmit_frame *xmit_frame);
int rtw_IOL_exec_cmds_sync(ADAPTER *adapter, struct xmit_frame *xmit_frame, u32 max_wating_ms);
int rtw_IOL_exec_cmd_array_sync(PADAPTER adapter, u8 *IOL_cmds, u32 cmd_num, u32 max_wating_ms);
int rtw_IOL_exec_empty_cmds_sync(ADAPTER *adapter, u32 max_wating_ms);

#ifdef DBG_IO
int dbg_rtw_IOL_append_WB_cmd(struct xmit_frame *xmit_frame, u16 addr, u8 value, const char *caller, const int line);
int dbg_rtw_IOL_append_WW_cmd(struct xmit_frame *xmit_frame, u16 addr, u16 value, const char *caller, const int line);
int dbg_rtw_IOL_append_WD_cmd(struct xmit_frame *xmit_frame, u16 addr, u32 value, const char *caller, const int line);
#define rtw_IOL_append_WB_cmd(xmit_frame, addr, value) dbg_rtw_IOL_append_WB_cmd((xmit_frame), (addr), (value), __FUNCTION__, __LINE__)
#define rtw_IOL_append_WW_cmd(xmit_frame, addr, value) dbg_rtw_IOL_append_WW_cmd((xmit_frame), (addr), (value), __FUNCTION__, __LINE__)
#define rtw_IOL_append_WD_cmd(xmit_frame, addr, value) dbg_rtw_IOL_append_WD_cmd((xmit_frame), (addr), (value), __FUNCTION__, __LINE__)
#else
#define rtw_IOL_append_WB_cmd(xmit_frame, addr, value) _rtw_IOL_append_WB_cmd((xmit_frame), (addr), (value))
#define rtw_IOL_append_WW_cmd(xmit_frame, addr, value) _rtw_IOL_append_WW_cmd((xmit_frame), (addr), (value))
#define rtw_IOL_append_WD_cmd(xmit_frame, addr, value) _rtw_IOL_append_WD_cmd((xmit_frame), (addr), (value))
#endif

bool rtw_IOL_applied(ADAPTER *adapter);

#endif //__RTW_IOL_H_
