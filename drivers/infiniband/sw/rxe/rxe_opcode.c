// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include <rdma/ib_pack.h>
#include "rxe_opcode.h"
#include "rxe_hdr.h"

/* useful information about work request opcodes and pkt opcodes in
 * table form
 */
struct rxe_wr_opcode_info rxe_wr_opcode_info[] = {
	[IB_WR_RDMA_WRITE]				= {
		.name	= "IB_WR_RDMA_WRITE",
		.mask	= {
			[IB_QPT_RC]	= WR_INLINE_MASK | WR_WRITE_MASK,
			[IB_QPT_UC]	= WR_INLINE_MASK | WR_WRITE_MASK,
		},
	},
	[IB_WR_RDMA_WRITE_WITH_IMM]			= {
		.name	= "IB_WR_RDMA_WRITE_WITH_IMM",
		.mask	= {
			[IB_QPT_RC]	= WR_INLINE_MASK | WR_WRITE_MASK,
			[IB_QPT_UC]	= WR_INLINE_MASK | WR_WRITE_MASK,
		},
	},
	[IB_WR_SEND]					= {
		.name	= "IB_WR_SEND",
		.mask	= {
			[IB_QPT_SMI]	= WR_INLINE_MASK | WR_SEND_MASK,
			[IB_QPT_GSI]	= WR_INLINE_MASK | WR_SEND_MASK,
			[IB_QPT_RC]	= WR_INLINE_MASK | WR_SEND_MASK,
			[IB_QPT_UC]	= WR_INLINE_MASK | WR_SEND_MASK,
			[IB_QPT_UD]	= WR_INLINE_MASK | WR_SEND_MASK,
		},
	},
	[IB_WR_SEND_WITH_IMM]				= {
		.name	= "IB_WR_SEND_WITH_IMM",
		.mask	= {
			[IB_QPT_SMI]	= WR_INLINE_MASK | WR_SEND_MASK,
			[IB_QPT_GSI]	= WR_INLINE_MASK | WR_SEND_MASK,
			[IB_QPT_RC]	= WR_INLINE_MASK | WR_SEND_MASK,
			[IB_QPT_UC]	= WR_INLINE_MASK | WR_SEND_MASK,
			[IB_QPT_UD]	= WR_INLINE_MASK | WR_SEND_MASK,
		},
	},
	[IB_WR_RDMA_READ]				= {
		.name	= "IB_WR_RDMA_READ",
		.mask	= {
			[IB_QPT_RC]	= WR_READ_MASK,
		},
	},
	[IB_WR_ATOMIC_CMP_AND_SWP]			= {
		.name	= "IB_WR_ATOMIC_CMP_AND_SWP",
		.mask	= {
			[IB_QPT_RC]	= WR_ATOMIC_MASK,
		},
	},
	[IB_WR_ATOMIC_FETCH_AND_ADD]			= {
		.name	= "IB_WR_ATOMIC_FETCH_AND_ADD",
		.mask	= {
			[IB_QPT_RC]	= WR_ATOMIC_MASK,
		},
	},
	[IB_WR_LSO]					= {
		.name	= "IB_WR_LSO",
		.mask	= {
			/* not supported */
		},
	},
	[IB_WR_SEND_WITH_INV]				= {
		.name	= "IB_WR_SEND_WITH_INV",
		.mask	= {
			[IB_QPT_RC]	= WR_INLINE_MASK | WR_SEND_MASK,
			[IB_QPT_UC]	= WR_INLINE_MASK | WR_SEND_MASK,
			[IB_QPT_UD]	= WR_INLINE_MASK | WR_SEND_MASK,
		},
	},
	[IB_WR_RDMA_READ_WITH_INV]			= {
		.name	= "IB_WR_RDMA_READ_WITH_INV",
		.mask	= {
			[IB_QPT_RC]	= WR_READ_MASK,
		},
	},
	[IB_WR_LOCAL_INV]				= {
		.name	= "IB_WR_LOCAL_INV",
		.mask	= {
			[IB_QPT_RC]	= WR_REG_MASK,
		},
	},
	[IB_WR_REG_MR]					= {
		.name	= "IB_WR_REG_MR",
		.mask	= {
			[IB_QPT_RC]	= WR_REG_MASK,
		},
	},
};

struct rxe_opcode_info rxe_opcode[RXE_NUM_OPCODE] = {
	[IB_OPCODE_RC_SEND_FIRST]			= {
		.name	= "IB_OPCODE_RC_SEND_FIRST",
		.mask	= RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_RWR_MASK
				| RXE_SEND_MASK | RXE_START_MASK,
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_RC_SEND_MIDDLE]		= {
		.name	= "IB_OPCODE_RC_SEND_MIDDLE]",
		.mask	= RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_SEND_MASK
				| RXE_MIDDLE_MASK,
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_RC_SEND_LAST]			= {
		.name	= "IB_OPCODE_RC_SEND_LAST",
		.mask	= RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_COMP_MASK
				| RXE_SEND_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE",
		.mask	= RXE_IMMDT_MASK | RXE_PAYLOAD_MASK | RXE_REQ_MASK
				| RXE_COMP_MASK | RXE_SEND_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_IMMDT]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RC_SEND_ONLY]			= {
		.name	= "IB_OPCODE_RC_SEND_ONLY",
		.mask	= RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_COMP_MASK
				| RXE_RWR_MASK | RXE_SEND_MASK
				| RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE",
		.mask	= RXE_IMMDT_MASK | RXE_PAYLOAD_MASK | RXE_REQ_MASK
				| RXE_COMP_MASK | RXE_RWR_MASK | RXE_SEND_MASK
				| RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_IMMDT]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_WRITE_FIRST]		= {
		.name	= "IB_OPCODE_RC_RDMA_WRITE_FIRST",
		.mask	= RXE_RETH_MASK | RXE_PAYLOAD_MASK | RXE_REQ_MASK
				| RXE_WRITE_MASK | RXE_START_MASK,
		.length = RXE_BTH_BYTES + RXE_RETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RETH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_WRITE_MIDDLE]		= {
		.name	= "IB_OPCODE_RC_RDMA_WRITE_MIDDLE",
		.mask	= RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_WRITE_MASK
				| RXE_MIDDLE_MASK,
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_WRITE_LAST]			= {
		.name	= "IB_OPCODE_RC_RDMA_WRITE_LAST",
		.mask	= RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_WRITE_MASK
				| RXE_END_MASK,
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE",
		.mask	= RXE_IMMDT_MASK | RXE_PAYLOAD_MASK | RXE_REQ_MASK
				| RXE_WRITE_MASK | RXE_COMP_MASK | RXE_RWR_MASK
				| RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_IMMDT]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_WRITE_ONLY]			= {
		.name	= "IB_OPCODE_RC_RDMA_WRITE_ONLY",
		.mask	= RXE_RETH_MASK | RXE_PAYLOAD_MASK | RXE_REQ_MASK
				| RXE_WRITE_MASK | RXE_START_MASK
				| RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_RETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RETH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE",
		.mask	= RXE_RETH_MASK | RXE_IMMDT_MASK | RXE_PAYLOAD_MASK
				| RXE_REQ_MASK | RXE_WRITE_MASK
				| RXE_COMP_MASK | RXE_RWR_MASK
				| RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_RETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RETH]	= RXE_BTH_BYTES,
			[RXE_IMMDT]	= RXE_BTH_BYTES
						+ RXE_RETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RETH_BYTES
						+ RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_READ_REQUEST]			= {
		.name	= "IB_OPCODE_RC_RDMA_READ_REQUEST",
		.mask	= RXE_RETH_MASK | RXE_REQ_MASK | RXE_READ_MASK
				| RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_RETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RETH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST]		= {
		.name	= "IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST",
		.mask	= RXE_AETH_MASK | RXE_PAYLOAD_MASK | RXE_ACK_MASK
				| RXE_START_MASK,
		.length = RXE_BTH_BYTES + RXE_AETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_AETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_AETH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE]		= {
		.name	= "IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE",
		.mask	= RXE_PAYLOAD_MASK | RXE_ACK_MASK | RXE_MIDDLE_MASK,
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST]		= {
		.name	= "IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST",
		.mask	= RXE_AETH_MASK | RXE_PAYLOAD_MASK | RXE_ACK_MASK
				| RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_AETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_AETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_AETH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY]		= {
		.name	= "IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY",
		.mask	= RXE_AETH_MASK | RXE_PAYLOAD_MASK | RXE_ACK_MASK
				| RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_AETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_AETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_AETH_BYTES,
		}
	},
	[IB_OPCODE_RC_ACKNOWLEDGE]			= {
		.name	= "IB_OPCODE_RC_ACKNOWLEDGE",
		.mask	= RXE_AETH_MASK | RXE_ACK_MASK | RXE_START_MASK
				| RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_AETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_AETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_AETH_BYTES,
		}
	},
	[IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE]			= {
		.name	= "IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE",
		.mask	= RXE_AETH_MASK | RXE_ATMACK_MASK | RXE_ACK_MASK
				| RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_ATMACK_BYTES + RXE_AETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_AETH]	= RXE_BTH_BYTES,
			[RXE_ATMACK]	= RXE_BTH_BYTES
						+ RXE_AETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
					+ RXE_ATMACK_BYTES + RXE_AETH_BYTES,
		}
	},
	[IB_OPCODE_RC_COMPARE_SWAP]			= {
		.name	= "IB_OPCODE_RC_COMPARE_SWAP",
		.mask	= RXE_ATMETH_MASK | RXE_REQ_MASK | RXE_ATOMIC_MASK
				| RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_ATMETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_ATMETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_ATMETH_BYTES,
		}
	},
	[IB_OPCODE_RC_FETCH_ADD]			= {
		.name	= "IB_OPCODE_RC_FETCH_ADD",
		.mask	= RXE_ATMETH_MASK | RXE_REQ_MASK | RXE_ATOMIC_MASK
				| RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_ATMETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_ATMETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_ATMETH_BYTES,
		}
	},
	[IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE]		= {
		.name	= "IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE",
		.mask	= RXE_IETH_MASK | RXE_PAYLOAD_MASK | RXE_REQ_MASK
				| RXE_COMP_MASK | RXE_SEND_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_IETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_IETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_IETH_BYTES,
		}
	},
	[IB_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE]		= {
		.name	= "IB_OPCODE_RC_SEND_ONLY_INV",
		.mask	= RXE_IETH_MASK | RXE_PAYLOAD_MASK | RXE_REQ_MASK
				| RXE_COMP_MASK | RXE_RWR_MASK | RXE_SEND_MASK
				| RXE_END_MASK  | RXE_START_MASK,
		.length = RXE_BTH_BYTES + RXE_IETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_IETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_IETH_BYTES,
		}
	},

	/* UC */
	[IB_OPCODE_UC_SEND_FIRST]			= {
		.name	= "IB_OPCODE_UC_SEND_FIRST",
		.mask	= RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_RWR_MASK
				| RXE_SEND_MASK | RXE_START_MASK,
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_UC_SEND_MIDDLE]		= {
		.name	= "IB_OPCODE_UC_SEND_MIDDLE",
		.mask	= RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_SEND_MASK
				| RXE_MIDDLE_MASK,
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_UC_SEND_LAST]			= {
		.name	= "IB_OPCODE_UC_SEND_LAST",
		.mask	= RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_COMP_MASK
				| RXE_SEND_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE",
		.mask	= RXE_IMMDT_MASK | RXE_PAYLOAD_MASK | RXE_REQ_MASK
				| RXE_COMP_MASK | RXE_SEND_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_IMMDT]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_UC_SEND_ONLY]			= {
		.name	= "IB_OPCODE_UC_SEND_ONLY",
		.mask	= RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_COMP_MASK
				| RXE_RWR_MASK | RXE_SEND_MASK
				| RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE",
		.mask	= RXE_IMMDT_MASK | RXE_PAYLOAD_MASK | RXE_REQ_MASK
				| RXE_COMP_MASK | RXE_RWR_MASK | RXE_SEND_MASK
				| RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_IMMDT]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_UC_RDMA_WRITE_FIRST]		= {
		.name	= "IB_OPCODE_UC_RDMA_WRITE_FIRST",
		.mask	= RXE_RETH_MASK | RXE_PAYLOAD_MASK | RXE_REQ_MASK
				| RXE_WRITE_MASK | RXE_START_MASK,
		.length = RXE_BTH_BYTES + RXE_RETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RETH_BYTES,
		}
	},
	[IB_OPCODE_UC_RDMA_WRITE_MIDDLE]		= {
		.name	= "IB_OPCODE_UC_RDMA_WRITE_MIDDLE",
		.mask	= RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_WRITE_MASK
				| RXE_MIDDLE_MASK,
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_UC_RDMA_WRITE_LAST]			= {
		.name	= "IB_OPCODE_UC_RDMA_WRITE_LAST",
		.mask	= RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_WRITE_MASK
				| RXE_END_MASK,
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE",
		.mask	= RXE_IMMDT_MASK | RXE_PAYLOAD_MASK | RXE_REQ_MASK
				| RXE_WRITE_MASK | RXE_COMP_MASK | RXE_RWR_MASK
				| RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_IMMDT]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_UC_RDMA_WRITE_ONLY]			= {
		.name	= "IB_OPCODE_UC_RDMA_WRITE_ONLY",
		.mask	= RXE_RETH_MASK | RXE_PAYLOAD_MASK | RXE_REQ_MASK
				| RXE_WRITE_MASK | RXE_START_MASK
				| RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_RETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RETH_BYTES,
		}
	},
	[IB_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE",
		.mask	= RXE_RETH_MASK | RXE_IMMDT_MASK | RXE_PAYLOAD_MASK
				| RXE_REQ_MASK | RXE_WRITE_MASK
				| RXE_COMP_MASK | RXE_RWR_MASK
				| RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_RETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RETH]	= RXE_BTH_BYTES,
			[RXE_IMMDT]	= RXE_BTH_BYTES
						+ RXE_RETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RETH_BYTES
						+ RXE_IMMDT_BYTES,
		}
	},

	/* RD */
	[IB_OPCODE_RD_SEND_FIRST]			= {
		.name	= "IB_OPCODE_RD_SEND_FIRST",
		.mask	= RXE_RDETH_MASK | RXE_DETH_MASK | RXE_PAYLOAD_MASK
				| RXE_REQ_MASK | RXE_RWR_MASK | RXE_SEND_MASK
				| RXE_START_MASK,
		.length = RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES,
		}
	},
	[IB_OPCODE_RD_SEND_MIDDLE]		= {
		.name	= "IB_OPCODE_RD_SEND_MIDDLE",
		.mask	= RXE_RDETH_MASK | RXE_DETH_MASK | RXE_PAYLOAD_MASK
				| RXE_REQ_MASK | RXE_SEND_MASK
				| RXE_MIDDLE_MASK,
		.length = RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES,
		}
	},
	[IB_OPCODE_RD_SEND_LAST]			= {
		.name	= "IB_OPCODE_RD_SEND_LAST",
		.mask	= RXE_RDETH_MASK | RXE_DETH_MASK | RXE_PAYLOAD_MASK
				| RXE_REQ_MASK | RXE_COMP_MASK | RXE_SEND_MASK
				| RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES,
		}
	},
	[IB_OPCODE_RD_SEND_LAST_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RD_SEND_LAST_WITH_IMMEDIATE",
		.mask	= RXE_RDETH_MASK | RXE_DETH_MASK | RXE_IMMDT_MASK
				| RXE_PAYLOAD_MASK | RXE_REQ_MASK
				| RXE_COMP_MASK | RXE_SEND_MASK
				| RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_DETH_BYTES
				+ RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES,
			[RXE_IMMDT]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES
						+ RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RD_SEND_ONLY]			= {
		.name	= "IB_OPCODE_RD_SEND_ONLY",
		.mask	= RXE_RDETH_MASK | RXE_DETH_MASK | RXE_PAYLOAD_MASK
				| RXE_REQ_MASK | RXE_COMP_MASK | RXE_RWR_MASK
				| RXE_SEND_MASK | RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES,
		}
	},
	[IB_OPCODE_RD_SEND_ONLY_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RD_SEND_ONLY_WITH_IMMEDIATE",
		.mask	= RXE_RDETH_MASK | RXE_DETH_MASK | RXE_IMMDT_MASK
				| RXE_PAYLOAD_MASK | RXE_REQ_MASK
				| RXE_COMP_MASK | RXE_RWR_MASK | RXE_SEND_MASK
				| RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_DETH_BYTES
				+ RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES,
			[RXE_IMMDT]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES
						+ RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_WRITE_FIRST]		= {
		.name	= "IB_OPCODE_RD_RDMA_WRITE_FIRST",
		.mask	= RXE_RDETH_MASK | RXE_DETH_MASK | RXE_RETH_MASK
				| RXE_PAYLOAD_MASK | RXE_REQ_MASK
				| RXE_WRITE_MASK | RXE_START_MASK,
		.length = RXE_BTH_BYTES + RXE_RETH_BYTES + RXE_DETH_BYTES
				+ RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES,
			[RXE_RETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES
						+ RXE_RETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_WRITE_MIDDLE]		= {
		.name	= "IB_OPCODE_RD_RDMA_WRITE_MIDDLE",
		.mask	= RXE_RDETH_MASK | RXE_DETH_MASK | RXE_PAYLOAD_MASK
				| RXE_REQ_MASK | RXE_WRITE_MASK
				| RXE_MIDDLE_MASK,
		.length = RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_WRITE_LAST]			= {
		.name	= "IB_OPCODE_RD_RDMA_WRITE_LAST",
		.mask	= RXE_RDETH_MASK | RXE_DETH_MASK | RXE_PAYLOAD_MASK
				| RXE_REQ_MASK | RXE_WRITE_MASK
				| RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_WRITE_LAST_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RD_RDMA_WRITE_LAST_WITH_IMMEDIATE",
		.mask	= RXE_RDETH_MASK | RXE_DETH_MASK | RXE_IMMDT_MASK
				| RXE_PAYLOAD_MASK | RXE_REQ_MASK
				| RXE_WRITE_MASK | RXE_COMP_MASK | RXE_RWR_MASK
				| RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_DETH_BYTES
				+ RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES,
			[RXE_IMMDT]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES
						+ RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_WRITE_ONLY]			= {
		.name	= "IB_OPCODE_RD_RDMA_WRITE_ONLY",
		.mask	= RXE_RDETH_MASK | RXE_DETH_MASK | RXE_RETH_MASK
				| RXE_PAYLOAD_MASK | RXE_REQ_MASK
				| RXE_WRITE_MASK | RXE_START_MASK
				| RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_RETH_BYTES + RXE_DETH_BYTES
				+ RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES,
			[RXE_RETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES
						+ RXE_RETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_WRITE_ONLY_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RD_RDMA_WRITE_ONLY_WITH_IMMEDIATE",
		.mask	= RXE_RDETH_MASK | RXE_DETH_MASK | RXE_RETH_MASK
				| RXE_IMMDT_MASK | RXE_PAYLOAD_MASK
				| RXE_REQ_MASK | RXE_WRITE_MASK
				| RXE_COMP_MASK | RXE_RWR_MASK
				| RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_RETH_BYTES
				+ RXE_DETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES,
			[RXE_RETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES,
			[RXE_IMMDT]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES
						+ RXE_RETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES
						+ RXE_RETH_BYTES
						+ RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_READ_REQUEST]			= {
		.name	= "IB_OPCODE_RD_RDMA_READ_REQUEST",
		.mask	= RXE_RDETH_MASK | RXE_DETH_MASK | RXE_RETH_MASK
				| RXE_REQ_MASK | RXE_READ_MASK
				| RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_RETH_BYTES + RXE_DETH_BYTES
				+ RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES,
			[RXE_RETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RETH_BYTES
						+ RXE_DETH_BYTES
						+ RXE_RDETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_READ_RESPONSE_FIRST]		= {
		.name	= "IB_OPCODE_RD_RDMA_READ_RESPONSE_FIRST",
		.mask	= RXE_RDETH_MASK | RXE_AETH_MASK
				| RXE_PAYLOAD_MASK | RXE_ACK_MASK
				| RXE_START_MASK,
		.length = RXE_BTH_BYTES + RXE_AETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_AETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_AETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_READ_RESPONSE_MIDDLE]		= {
		.name	= "IB_OPCODE_RD_RDMA_READ_RESPONSE_MIDDLE",
		.mask	= RXE_RDETH_MASK | RXE_PAYLOAD_MASK | RXE_ACK_MASK
				| RXE_MIDDLE_MASK,
		.length = RXE_BTH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_READ_RESPONSE_LAST]		= {
		.name	= "IB_OPCODE_RD_RDMA_READ_RESPONSE_LAST",
		.mask	= RXE_RDETH_MASK | RXE_AETH_MASK | RXE_PAYLOAD_MASK
				| RXE_ACK_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_AETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_AETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_AETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_READ_RESPONSE_ONLY]		= {
		.name	= "IB_OPCODE_RD_RDMA_READ_RESPONSE_ONLY",
		.mask	= RXE_RDETH_MASK | RXE_AETH_MASK | RXE_PAYLOAD_MASK
				| RXE_ACK_MASK | RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_AETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_AETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_AETH_BYTES,
		}
	},
	[IB_OPCODE_RD_ACKNOWLEDGE]			= {
		.name	= "IB_OPCODE_RD_ACKNOWLEDGE",
		.mask	= RXE_RDETH_MASK | RXE_AETH_MASK | RXE_ACK_MASK
				| RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_AETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_AETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES,
		}
	},
	[IB_OPCODE_RD_ATOMIC_ACKNOWLEDGE]			= {
		.name	= "IB_OPCODE_RD_ATOMIC_ACKNOWLEDGE",
		.mask	= RXE_RDETH_MASK | RXE_AETH_MASK | RXE_ATMACK_MASK
				| RXE_ACK_MASK | RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_ATMACK_BYTES + RXE_AETH_BYTES
				+ RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_AETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES,
			[RXE_ATMACK]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_AETH_BYTES,
		}
	},
	[IB_OPCODE_RD_COMPARE_SWAP]			= {
		.name	= "RD_COMPARE_SWAP",
		.mask	= RXE_RDETH_MASK | RXE_DETH_MASK | RXE_ATMETH_MASK
				| RXE_REQ_MASK | RXE_ATOMIC_MASK
				| RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_ATMETH_BYTES + RXE_DETH_BYTES
				+ RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES,
			[RXE_ATMETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
						+ RXE_ATMETH_BYTES
						+ RXE_DETH_BYTES +
						+ RXE_RDETH_BYTES,
		}
	},
	[IB_OPCODE_RD_FETCH_ADD]			= {
		.name	= "IB_OPCODE_RD_FETCH_ADD",
		.mask	= RXE_RDETH_MASK | RXE_DETH_MASK | RXE_ATMETH_MASK
				| RXE_REQ_MASK | RXE_ATOMIC_MASK
				| RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_ATMETH_BYTES + RXE_DETH_BYTES
				+ RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES,
			[RXE_ATMETH]	= RXE_BTH_BYTES
						+ RXE_RDETH_BYTES
						+ RXE_DETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
						+ RXE_ATMETH_BYTES
						+ RXE_DETH_BYTES +
						+ RXE_RDETH_BYTES,
		}
	},

	/* UD */
	[IB_OPCODE_UD_SEND_ONLY]			= {
		.name	= "IB_OPCODE_UD_SEND_ONLY",
		.mask	= RXE_DETH_MASK | RXE_PAYLOAD_MASK | RXE_REQ_MASK
				| RXE_COMP_MASK | RXE_RWR_MASK | RXE_SEND_MASK
				| RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_DETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_DETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_DETH_BYTES,
		}
	},
	[IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE",
		.mask	= RXE_DETH_MASK | RXE_IMMDT_MASK | RXE_PAYLOAD_MASK
				| RXE_REQ_MASK | RXE_COMP_MASK | RXE_RWR_MASK
				| RXE_SEND_MASK | RXE_START_MASK | RXE_END_MASK,
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_DETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_DETH]	= RXE_BTH_BYTES,
			[RXE_IMMDT]	= RXE_BTH_BYTES
						+ RXE_DETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES
						+ RXE_DETH_BYTES
						+ RXE_IMMDT_BYTES,
		}
	},

};
