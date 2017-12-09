/*
 * Copyright(c) 2007 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Maintained at www.Open-FCoE.org
 */

#ifndef _FC_FCOE_H_
#define	_FC_FCOE_H_

/*
 * FCoE - Fibre Channel over Ethernet.
 * See T11 FC-BB-5 Rev 2.00 (09-056v5.pdf)
 */

/*
 * Default FC_FCOE_OUI / FC-MAP value.
 */
#define	FC_FCOE_OUI	0x0efc00	/* upper 24 bits of FCOE MAC */

/*
 * Fabric Login (FLOGI) MAC for non-FIP use.  Non-FIP use is deprecated.
 */
#define	FC_FCOE_FLOGI_MAC { 0x0e, 0xfc, 0x00, 0xff, 0xff, 0xfe }

#define	FC_FCOE_VER	0			/* version */

/*
 * Ethernet Addresses based on FC S_ID and D_ID.
 * Generated by FC_FCOE_OUI | S_ID/D_ID
 */
#define	FC_FCOE_ENCAPS_ID(n)	(((u64) FC_FCOE_OUI << 24) | (n))
#define	FC_FCOE_DECAPS_ID(n)	((n) >> 24)

/*
 * FCoE frame header - 14 bytes
 * This follows the VLAN header, which includes the ethertype.
 */
struct fcoe_hdr {
	__u8		fcoe_ver;	/* version field - upper 4 bits */
	__u8		fcoe_resvd[12];	/* reserved - send zero and ignore */
	__u8		fcoe_sof;	/* start of frame per RFC 3643 */
};

#define FC_FCOE_DECAPS_VER(hp)	    ((hp)->fcoe_ver >> 4)
#define FC_FCOE_ENCAPS_VER(hp, ver) ((hp)->fcoe_ver = (ver) << 4)

/*
 * FCoE CRC & EOF - 8 bytes.
 */
struct fcoe_crc_eof {
	__le32		fcoe_crc32;	/* CRC for FC packet */
	__u8		fcoe_eof;	/* EOF from RFC 3643 */
	__u8		fcoe_resvd[3];	/* reserved - send zero and ignore */
} __attribute__((packed));

/*
 * Minimum FCoE + FC header length
 * 14 bytes FCoE header + 24 byte FC header = 38 bytes
 */
#define FCOE_HEADER_LEN 38

/*
 * Minimum FCoE frame size
 * 14 bytes FCoE header + 24 byte FC header + 8 byte FCoE trailer = 46 bytes
 */
#define FCOE_MIN_FRAME 46

/*
 * FCoE Link Error Status Block: T11 FC-BB-5 Rev2.0, Clause 7.10.
 */
struct fcoe_fc_els_lesb {
	__be32		lesb_link_fail;	/* link failure count */
	__be32		lesb_vlink_fail; /* virtual link failure count */
	__be32		lesb_miss_fka;	/* missing FIP keep-alive count */
	__be32		lesb_symb_err;	/* symbol error during carrier count */
	__be32		lesb_err_block;	/* errored block count */
	__be32		lesb_fcs_error; /* frame check sequence error count */
};

/*
 * fc_fcoe_set_mac - Store OUI + DID into MAC address field.
 * @mac: mac address to be set
 * @did: fc dest id to use
 */
static inline void fc_fcoe_set_mac(u8 *mac, u8 *did)
{
	mac[0] = (u8) (FC_FCOE_OUI >> 16);
	mac[1] = (u8) (FC_FCOE_OUI >> 8);
	mac[2] = (u8) FC_FCOE_OUI;
	mac[3] = did[0];
	mac[4] = did[1];
	mac[5] = did[2];
}

#endif /* _FC_FCOE_H_ */
