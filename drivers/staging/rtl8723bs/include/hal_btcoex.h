/******************************************************************************
 *
 * Copyright(c) 2013 Realtek Corporation. All rights reserved.
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
 ******************************************************************************/
#ifndef __HAL_BTCOEX_H__
#define __HAL_BTCOEX_H__

#include <drv_types.h>

/*  Some variables can't get from outsrc BT-Coex, */
/*  so we need to save here */
typedef struct _BT_COEXIST
{
	u8 bBtExist;
	u8 btTotalAntNum;
	u8 btChipType;
	u8 bInitlized;
} BT_COEXIST, *PBT_COEXIST;

void DBG_BT_INFO(u8 *dbgmsg);

void hal_btcoex_SetBTCoexist(struct adapter *padapter, u8 bBtExist);
u8 hal_btcoex_IsBtExist(struct adapter *padapter);
u8 hal_btcoex_IsBtDisabled(struct adapter *);
void hal_btcoex_SetChipType(struct adapter *padapter, u8 chipType);
void hal_btcoex_SetPgAntNum(struct adapter *padapter, u8 antNum);
void hal_btcoex_SetSingleAntPath(struct adapter *padapter, u8 singleAntPath);

u8 hal_btcoex_Initialize(struct adapter *padapter);
void hal_btcoex_PowerOnSetting(struct adapter *padapter);
void hal_btcoex_InitHwConfig(struct adapter *padapter, u8 bWifiOnly);

void hal_btcoex_IpsNotify(struct adapter *padapter, u8 type);
void hal_btcoex_LpsNotify(struct adapter *padapter, u8 type);
void hal_btcoex_ScanNotify(struct adapter *padapter, u8 type);
void hal_btcoex_ConnectNotify(struct adapter *padapter, u8 action);
void hal_btcoex_MediaStatusNotify(struct adapter *padapter, u8 mediaStatus);
void hal_btcoex_SpecialPacketNotify(struct adapter *padapter, u8 pktType);
void hal_btcoex_IQKNotify(struct adapter *padapter, u8 state);
void hal_btcoex_BtInfoNotify(struct adapter *padapter, u8 length, u8 *tmpBuf);
void hal_btcoex_SuspendNotify(struct adapter *padapter, u8 state);
void hal_btcoex_HaltNotify(struct adapter *padapter);

void hal_btcoex_Hanlder(struct adapter *padapter);

s32 hal_btcoex_IsBTCoexCtrlAMPDUSize(struct adapter *padapter);
void hal_btcoex_SetManualControl(struct adapter *padapter, u8 bmanual);
u8 hal_btcoex_IsBtControlLps(struct adapter *);
u8 hal_btcoex_IsLpsOn(struct adapter *);
u8 hal_btcoex_RpwmVal(struct adapter *);
u8 hal_btcoex_LpsVal(struct adapter *);
u32 hal_btcoex_GetRaMask(struct adapter *);
void hal_btcoex_RecordPwrMode(struct adapter *padapter, u8 *pCmdBuf, u8 cmdLen);
void hal_btcoex_DisplayBtCoexInfo(struct adapter *, u8 *pbuf, u32 bufsize);
void hal_btcoex_SetDBG(struct adapter *, u32 *pDbgModule);
u32 hal_btcoex_GetDBG(struct adapter *, u8 *pStrBuf, u32 bufSize);

#endif /*  !__HAL_BTCOEX_H__ */
