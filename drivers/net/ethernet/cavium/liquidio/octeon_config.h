/**********************************************************************
* Author: Cavium, Inc.
*
* Contact: support@cavium.com
*          Please include "LiquidIO" in the subject.
*
* Copyright (c) 2003-2015 Cavium, Inc.
*
* This file is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License, Version 2, as
* published by the Free Software Foundation.
*
* This file is distributed in the hope that it will be useful, but
* AS-IS and WITHOUT ANY WARRANTY; without even the implied warranty
* of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE, TITLE, or
* NONINFRINGEMENT.  See the GNU General Public License for more
* details.
*
* This file may also be available under a different license from Cavium.
* Contact Cavium, Inc. for more information
**********************************************************************/

/*! \file  octeon_config.h
 *  \brief Host Driver: Configuration data structures for the host driver.
 */

#ifndef __OCTEON_CONFIG_H__
#define __OCTEON_CONFIG_H__

/*--------------------------CONFIG VALUES------------------------*/

/* The following macros affect the way the driver data structures
 * are generated for Octeon devices.
 * They can be modified.
 */

/* Maximum octeon devices defined as MAX_OCTEON_NICIF to support
 * multiple(<= MAX_OCTEON_NICIF) Miniports
 */
#define   MAX_OCTEON_NICIF             128
#define   MAX_OCTEON_DEVICES           MAX_OCTEON_NICIF
#define   MAX_OCTEON_LINKS	       MAX_OCTEON_NICIF
#define   MAX_OCTEON_MULTICAST_ADDR    32

/* CN6xxx IQ configuration macros */
#define   CN6XXX_MAX_INPUT_QUEUES      32
#define   CN6XXX_MAX_IQ_DESCRIPTORS    2048
#define   CN6XXX_DB_MIN                1
#define   CN6XXX_DB_MAX                8
#define   CN6XXX_DB_TIMEOUT            1

/* CN6xxx OQ configuration macros */
#define   CN6XXX_MAX_OUTPUT_QUEUES     32
#define   CN6XXX_MAX_OQ_DESCRIPTORS    2048
#define   CN6XXX_OQ_BUF_SIZE           1536
#define   CN6XXX_OQ_PKTSPER_INTR       ((CN6XXX_MAX_OQ_DESCRIPTORS < 512) ? \
					(CN6XXX_MAX_OQ_DESCRIPTORS / 4) : 128)
#define   CN6XXX_OQ_REFIL_THRESHOLD    ((CN6XXX_MAX_OQ_DESCRIPTORS < 512) ? \
					(CN6XXX_MAX_OQ_DESCRIPTORS / 4) : 128)

#define   CN6XXX_OQ_INTR_PKT           64
#define   CN6XXX_OQ_INTR_TIME          100
#define   DEFAULT_NUM_NIC_PORTS_66XX   2
#define   DEFAULT_NUM_NIC_PORTS_68XX   4
#define   DEFAULT_NUM_NIC_PORTS_68XX_210NV  2

/* common OCTEON configuration macros */
#define   CN6XXX_CFG_IO_QUEUES         32
#define   OCTEON_32BYTE_INSTR          32
#define   OCTEON_64BYTE_INSTR          64
#define   OCTEON_MAX_BASE_IOQ          4
#define   OCTEON_OQ_BUFPTR_MODE        0
#define   OCTEON_OQ_INFOPTR_MODE       1

#define   OCTEON_DMA_INTR_PKT          64
#define   OCTEON_DMA_INTR_TIME         1000

#define MAX_TXQS_PER_INTF  8
#define MAX_RXQS_PER_INTF  8
#define DEF_TXQS_PER_INTF  4
#define DEF_RXQS_PER_INTF  4

#define INVALID_IOQ_NO          0xff

#define   DEFAULT_POW_GRP       0

/* Macros to get octeon config params */
#define CFG_GET_IQ_CFG(cfg)                      ((cfg)->iq)
#define CFG_GET_IQ_MAX_Q(cfg)                    ((cfg)->iq.max_iqs)
#define CFG_GET_IQ_PENDING_LIST_SIZE(cfg)        ((cfg)->iq.pending_list_size)
#define CFG_GET_IQ_INSTR_TYPE(cfg)               ((cfg)->iq.instr_type)
#define CFG_GET_IQ_DB_MIN(cfg)                   ((cfg)->iq.db_min)
#define CFG_GET_IQ_DB_TIMEOUT(cfg)               ((cfg)->iq.db_timeout)

#define CFG_GET_OQ_MAX_Q(cfg)                    ((cfg)->oq.max_oqs)
#define CFG_GET_OQ_INFO_PTR(cfg)                 ((cfg)->oq.info_ptr)
#define CFG_GET_OQ_PKTS_PER_INTR(cfg)            ((cfg)->oq.pkts_per_intr)
#define CFG_GET_OQ_REFILL_THRESHOLD(cfg)         ((cfg)->oq.refill_threshold)
#define CFG_GET_OQ_INTR_PKT(cfg)                 ((cfg)->oq.oq_intr_pkt)
#define CFG_GET_OQ_INTR_TIME(cfg)                ((cfg)->oq.oq_intr_time)
#define CFG_SET_OQ_INTR_PKT(cfg, val)            (cfg)->oq.oq_intr_pkt = val
#define CFG_SET_OQ_INTR_TIME(cfg, val)           (cfg)->oq.oq_intr_time = val

#define CFG_GET_DMA_INTR_PKT(cfg)                ((cfg)->dma.dma_intr_pkt)
#define CFG_GET_DMA_INTR_TIME(cfg)               ((cfg)->dma.dma_intr_time)
#define CFG_GET_NUM_NIC_PORTS(cfg)               ((cfg)->num_nic_ports)
#define CFG_GET_NUM_DEF_TX_DESCS(cfg)            ((cfg)->num_def_tx_descs)
#define CFG_GET_NUM_DEF_RX_DESCS(cfg)            ((cfg)->num_def_rx_descs)
#define CFG_GET_DEF_RX_BUF_SIZE(cfg)             ((cfg)->def_rx_buf_size)

#define CFG_GET_MAX_TXQS_NIC_IF(cfg, idx) \
				((cfg)->nic_if_cfg[idx].max_txqs)
#define CFG_GET_NUM_TXQS_NIC_IF(cfg, idx) \
				((cfg)->nic_if_cfg[idx].num_txqs)
#define CFG_GET_MAX_RXQS_NIC_IF(cfg, idx) \
				((cfg)->nic_if_cfg[idx].max_rxqs)
#define CFG_GET_NUM_RXQS_NIC_IF(cfg, idx) \
				((cfg)->nic_if_cfg[idx].num_rxqs)
#define CFG_GET_NUM_RX_DESCS_NIC_IF(cfg, idx) \
				((cfg)->nic_if_cfg[idx].num_rx_descs)
#define CFG_GET_NUM_TX_DESCS_NIC_IF(cfg, idx) \
				((cfg)->nic_if_cfg[idx].num_tx_descs)
#define CFG_GET_NUM_RX_BUF_SIZE_NIC_IF(cfg, idx) \
				((cfg)->nic_if_cfg[idx].rx_buf_size)
#define CFG_GET_BASE_QUE_NIC_IF(cfg, idx) \
				((cfg)->nic_if_cfg[idx].base_queue)
#define CFG_GET_GMXID_NIC_IF(cfg, idx) \
				((cfg)->nic_if_cfg[idx].gmx_port_id)

#define CFG_GET_CTRL_Q_GRP(cfg)                  ((cfg)->misc.ctrlq_grp)
#define CFG_GET_HOST_LINK_QUERY_INTERVAL(cfg) \
				((cfg)->misc.host_link_query_interval)
#define CFG_GET_OCT_LINK_QUERY_INTERVAL(cfg) \
				((cfg)->misc.oct_link_query_interval)
#define CFG_GET_IS_SLI_BP_ON(cfg)                ((cfg)->misc.enable_sli_oq_bp)

/* Max IOQs per OCTEON Link */
#define MAX_IOQS_PER_NICIF              64

enum lio_card_type {
	LIO_210SV = 0, /* Two port, 66xx */
	LIO_210NV,     /* Two port, 68xx */
	LIO_410NV      /* Four port, 68xx */
};

#define LIO_210SV_NAME "210sv"
#define LIO_210NV_NAME "210nv"
#define LIO_410NV_NAME "410nv"

/** Structure to define the configuration attributes for each Input queue.
 *  Applicable to all Octeon processors
 **/
struct octeon_iq_config {
#ifdef __BIG_ENDIAN_BITFIELD
	u64 reserved:32;

	/** Minimum ticks to wait before checking for pending instructions. */
	u64 db_timeout:16;

	/** Minimum number of commands pending to be posted to Octeon
	 *  before driver hits the Input queue doorbell.
	 */
	u64 db_min:8;

	/** Command size - 32 or 64 bytes */
	u64 instr_type:32;

	/** Pending list size (usually set to the sum of the size of all Input
	 *  queues)
	 */
	u64 pending_list_size:32;

	/* Max number of IQs available */
	u64 max_iqs:8;
#else
	/* Max number of IQs available */
	u64 max_iqs:8;

	/** Pending list size (usually set to the sum of the size of all Input
	 *  queues)
	 */
	u64 pending_list_size:32;

	/** Command size - 32 or 64 bytes */
	u64 instr_type:32;

	/** Minimum number of commands pending to be posted to Octeon
	 *  before driver hits the Input queue doorbell.
	 */
	u64 db_min:8;

	/** Minimum ticks to wait before checking for pending instructions. */
	u64 db_timeout:16;

	u64 reserved:32;
#endif
};

/** Structure to define the configuration attributes for each Output queue.
 *  Applicable to all Octeon processors
 **/
struct octeon_oq_config {
#ifdef __BIG_ENDIAN_BITFIELD
	u64 reserved:16;

	u64 pkts_per_intr:16;

	/** Interrupt Coalescing (Time Interval). Octeon will interrupt the
	 *  host if atleast one packet was sent in the time interval specified
	 *  by this field. The driver uses time interval interrupt coalescing
	 *  by default. The time is specified in microseconds.
	 */
	u64 oq_intr_time:16;

	/** Interrupt Coalescing (Packet Count). Octeon will interrupt the host
	 *  only if it sent as many packets as specified by this field.
	 *  The driver
	 *  usually does not use packet count interrupt coalescing.
	 */
	u64 oq_intr_pkt:16;

	/** The number of buffers that were consumed during packet processing by
	 *   the driver on this Output queue before the driver attempts to
	 *   replenish
	 *   the descriptor ring with new buffers.
	 */
	u64 refill_threshold:16;

	/** If set, the Output queue uses info-pointer mode. (Default: 1) */
	u64 info_ptr:32;

	/* Max number of OQs available */
	u64 max_oqs:8;

#else
	/* Max number of OQs available */
	u64 max_oqs:8;

	/** If set, the Output queue uses info-pointer mode. (Default: 1) */
	u64 info_ptr:32;

	/** The number of buffers that were consumed during packet processing by
	 *   the driver on this Output queue before the driver attempts to
	 *   replenish
	 *   the descriptor ring with new buffers.
	 */
	u64 refill_threshold:16;

	/** Interrupt Coalescing (Packet Count). Octeon will interrupt the host
	 *  only if it sent as many packets as specified by this field.
	 *  The driver
	 *  usually does not use packet count interrupt coalescing.
	 */
	u64 oq_intr_pkt:16;

	/** Interrupt Coalescing (Time Interval). Octeon will interrupt the
	 *  host if atleast one packet was sent in the time interval specified
	 *  by this field. The driver uses time interval interrupt coalescing
	 *  by default.  The time is specified in microseconds.
	 */
	u64 oq_intr_time:16;

	u64 pkts_per_intr:16;

	u64 reserved:16;
#endif

};

/** This structure conatins the NIC link configuration attributes,
 *  common for all the OCTEON Modles.
 */
struct octeon_nic_if_config {
#ifdef __BIG_ENDIAN_BITFIELD
	u64 reserved:56;

	u64 base_queue:16;

	u64 gmx_port_id:8;

	/* SKB size, We need not change buf size even for Jumbo frames.
	 * Octeon can send jumbo frames in 4 consecutive descriptors,
	 */
	u64 rx_buf_size:16;

	/* Num of desc for tx rings */
	u64 num_tx_descs:16;

	/* Num of desc for rx rings */
	u64 num_rx_descs:16;

	/* Actual configured value. Range could be: 1...max_rxqs */
	u64 num_rxqs:16;

	/* Max Rxqs: Half for each of the two ports :max_oq/2  */
	u64 max_rxqs:16;

	/* Actual configured value. Range could be: 1...max_txqs */
	u64 num_txqs:16;

	/* Max Txqs: Half for each of the two ports :max_iq/2 */
	u64 max_txqs:16;
#else
	/* Max Txqs: Half for each of the two ports :max_iq/2 */
	u64 max_txqs:16;

	/* Actual configured value. Range could be: 1...max_txqs */
	u64 num_txqs:16;

	/* Max Rxqs: Half for each of the two ports :max_oq/2  */
	u64 max_rxqs:16;

	/* Actual configured value. Range could be: 1...max_rxqs */
	u64 num_rxqs:16;

	/* Num of desc for rx rings */
	u64 num_rx_descs:16;

	/* Num of desc for tx rings */
	u64 num_tx_descs:16;

	/* SKB size, We need not change buf size even for Jumbo frames.
	 * Octeon can send jumbo frames in 4 consecutive descriptors,
	 */
	u64 rx_buf_size:16;

	u64 gmx_port_id:8;

	u64 base_queue:16;

	u64 reserved:56;
#endif

};

/** Structure to define the configuration attributes for meta data.
 *  Applicable to all Octeon processors.
 */

struct octeon_misc_config {
#ifdef __BIG_ENDIAN_BITFIELD
	/** Host link status polling period */
	u64 host_link_query_interval:32;
	/** Oct link status polling period */
	u64 oct_link_query_interval:32;

	u64 enable_sli_oq_bp:1;
	/** Control IQ Group */
	u64 ctrlq_grp:4;
#else
	/** Control IQ Group */
	u64 ctrlq_grp:4;
	/** BP for SLI OQ */
	u64 enable_sli_oq_bp:1;
	/** Host link status polling period */
	u64 oct_link_query_interval:32;
	/** Oct link status polling period */
	u64 host_link_query_interval:32;
#endif
};

/** Structure to define the configuration for all OCTEON processors. */
struct octeon_config {
	u16 card_type;
	char *card_name;

	/** Input Queue attributes. */
	struct octeon_iq_config iq;

	/** Output Queue attributes. */
	struct octeon_oq_config oq;

	/** NIC Port Configuration */
	struct octeon_nic_if_config nic_if_cfg[MAX_OCTEON_NICIF];

	/** Miscellaneous attributes */
	struct octeon_misc_config misc;

	int num_nic_ports;

	int num_def_tx_descs;

	/* Num of desc for rx rings */
	int num_def_rx_descs;

	int def_rx_buf_size;

};

/* The following config values are fixed and should not be modified. */

/* Maximum address space to be mapped for Octeon's BAR1 index-based access. */
#define  MAX_BAR1_MAP_INDEX                     2
#define  OCTEON_BAR1_ENTRY_SIZE         (4 * 1024 * 1024)

/* BAR1 Index 0 to (MAX_BAR1_MAP_INDEX - 1) for normal mapped memory access.
 * Bar1 register at MAX_BAR1_MAP_INDEX used by driver for dynamic access.
 */
#define  MAX_BAR1_IOREMAP_SIZE  ((MAX_BAR1_MAP_INDEX + 1) * \
				 OCTEON_BAR1_ENTRY_SIZE)

/* Response lists - 1 ordered, 1 unordered-blocking, 1 unordered-nonblocking
 * NoResponse Lists are now maintained with each IQ. (Dec' 2007).
 */
#define MAX_RESPONSE_LISTS           4

/* Opcode hash bits. The opcode is hashed on the lower 6-bits to lookup the
 * dispatch table.
 */
#define OPCODE_MASK_BITS             6

/* Mask for the 6-bit lookup hash */
#define OCTEON_OPCODE_MASK           0x3f

/* Size of the dispatch table. The 6-bit hash can index into 2^6 entries */
#define DISPATCH_LIST_SIZE                      BIT(OPCODE_MASK_BITS)

/* Maximum number of Octeon Instruction (command) queues */
#define MAX_OCTEON_INSTR_QUEUES(oct)         CN6XXX_MAX_INPUT_QUEUES
/* Maximum number of Octeon Output queues */
#define MAX_OCTEON_OUTPUT_QUEUES(oct)         CN6XXX_MAX_OUTPUT_QUEUES

#define MAX_POSSIBLE_OCTEON_INSTR_QUEUES       CN6XXX_MAX_INPUT_QUEUES
#define MAX_POSSIBLE_OCTEON_OUTPUT_QUEUES      CN6XXX_MAX_OUTPUT_QUEUES

#endif /* __OCTEON_CONFIG_H__  */
