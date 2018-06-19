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
 ******************************************************************************/
#ifndef _RTW_IOCTL_H_
#define _RTW_IOCTL_H_

/* 	00 - Success */
/* 	11 - Error */
#define STATUS_SUCCESS				(0x00000000L)
#define STATUS_PENDING				(0x00000103L)

#define STATUS_UNSUCCESSFUL			(0xC0000001L)
#define STATUS_INSUFFICIENT_RESOURCES		(0xC000009AL)
#define STATUS_NOT_SUPPORTED			(0xC00000BBL)

#define NDIS_STATUS_SUCCESS			((uint)STATUS_SUCCESS)
#define NDIS_STATUS_PENDING			((uint)STATUS_PENDING)
#define NDIS_STATUS_NOT_RECOGNIZED		((uint)0x00010001L)
#define NDIS_STATUS_NOT_COPIED			((uint)0x00010002L)
#define NDIS_STATUS_NOT_ACCEPTED		((uint)0x00010003L)
#define NDIS_STATUS_CALL_ACTIVE			((uint)0x00010007L)

#define NDIS_STATUS_FAILURE			((uint)STATUS_UNSUCCESSFUL)
#define NDIS_STATUS_RESOURCES			((uint)STATUS_INSUFFICIENT_RESOURCES)
#define NDIS_STATUS_CLOSING			((uint)0xC0010002L)
#define NDIS_STATUS_BAD_VERSION			((uint)0xC0010004L)
#define NDIS_STATUS_BAD_CHARACTERISTICS		((uint)0xC0010005L)
#define NDIS_STATUS_ADAPTER_NOT_FOUND		((uint)0xC0010006L)
#define NDIS_STATUS_OPEN_FAILED			((uint)0xC0010007L)
#define NDIS_STATUS_DEVICE_FAILED		((uint)0xC0010008L)
#define NDIS_STATUS_MULTICAST_FULL		((uint)0xC0010009L)
#define NDIS_STATUS_MULTICAST_EXISTS		((uint)0xC001000AL)
#define NDIS_STATUS_MULTICAST_NOT_FOUND		((uint)0xC001000BL)
#define NDIS_STATUS_REQUEST_ABORTED		((uint)0xC001000CL)
#define NDIS_STATUS_RESET_IN_PROGRESS		((uint)0xC001000DL)
#define NDIS_STATUS_CLOSING_INDICATING		((uint)0xC001000EL)
#define NDIS_STATUS_NOT_SUPPORTED		((uint)STATUS_NOT_SUPPORTED)
#define NDIS_STATUS_INVALID_PACKET		((uint)0xC001000FL)
#define NDIS_STATUS_OPEN_LIST_FULL		((uint)0xC0010010L)
#define NDIS_STATUS_ADAPTER_NOT_READY		((uint)0xC0010011L)
#define NDIS_STATUS_ADAPTER_NOT_OPEN		((uint)0xC0010012L)
#define NDIS_STATUS_NOT_INDICATING		((uint)0xC0010013L)
#define NDIS_STATUS_INVALID_LENGTH		((uint)0xC0010014L)
#define NDIS_STATUS_INVALID_DATA		((uint)0xC0010015L)
#define NDIS_STATUS_BUFFER_TOO_SHORT		((uint)0xC0010016L)
#define NDIS_STATUS_INVALID_OID			((uint)0xC0010017L)
#define NDIS_STATUS_ADAPTER_REMOVED		((uint)0xC0010018L)
#define NDIS_STATUS_UNSUPPORTED_MEDIA		((uint)0xC0010019L)
#define NDIS_STATUS_GROUP_ADDRESS_IN_USE	((uint)0xC001001AL)
#define NDIS_STATUS_FILE_NOT_FOUND		((uint)0xC001001BL)
#define NDIS_STATUS_ERROR_READING_FILE		((uint)0xC001001CL)
#define NDIS_STATUS_ALREADY_MAPPED		((uint)0xC001001DL)
#define NDIS_STATUS_RESOURCE_CONFLICT		((uint)0xC001001EL)
#define NDIS_STATUS_NO_CABLE			((uint)0xC001001FL)

#define NDIS_STATUS_INVALID_SAP			((uint)0xC0010020L)
#define NDIS_STATUS_SAP_IN_USE			((uint)0xC0010021L)
#define NDIS_STATUS_INVALID_ADDRESS		((uint)0xC0010022L)
#define NDIS_STATUS_VC_NOT_ACTIVATED		((uint)0xC0010023L)
#define NDIS_STATUS_DEST_OUT_OF_ORDER		((uint)0xC0010024L)  /*  cause 27 */
#define NDIS_STATUS_VC_NOT_AVAILABLE		((uint)0xC0010025L)  /*  cause 35, 45 */
#define NDIS_STATUS_CELLRATE_NOT_AVAILABLE	((uint)0xC0010026L)  /*  cause 37 */
#define NDIS_STATUS_INCOMPATABLE_QOS		((uint)0xC0010027L)  /*  cause 49 */
#define NDIS_STATUS_AAL_PARAMS_UNSUPPORTED	((uint)0xC0010028L)  /*  cause 93 */
#define NDIS_STATUS_NO_ROUTE_TO_DESTINATION	((uint)0xC0010029L)  /*  cause 3 */

extern struct iw_handler_def  rtw_handlers_def;

#endif /*  #ifndef __INC_CEINFO_ */
