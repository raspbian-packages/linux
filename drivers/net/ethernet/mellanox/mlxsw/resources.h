/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2016-2018 Mellanox Technologies. All rights reserved */

#ifndef _MLXSW_RESOURCES_H
#define _MLXSW_RESOURCES_H

#include <linux/kernel.h>
#include <linux/types.h>

enum mlxsw_res_id {
	MLXSW_RES_ID_KVD_SIZE,
	MLXSW_RES_ID_KVD_SINGLE_MIN_SIZE,
	MLXSW_RES_ID_KVD_DOUBLE_MIN_SIZE,
	MLXSW_RES_ID_PGT_SIZE,
	MLXSW_RES_ID_MAX_KVD_LINEAR_RANGE,
	MLXSW_RES_ID_MAX_KVD_ACTION_SETS,
	MLXSW_RES_ID_MAX_TRAP_GROUPS,
	MLXSW_RES_ID_CQE_V0,
	MLXSW_RES_ID_CQE_V1,
	MLXSW_RES_ID_CQE_V2,
	MLXSW_RES_ID_COUNTER_POOL_SIZE,
	MLXSW_RES_ID_COUNTER_BANK_SIZE,
	MLXSW_RES_ID_MAX_SPAN,
	MLXSW_RES_ID_COUNTER_SIZE_PACKETS_BYTES,
	MLXSW_RES_ID_COUNTER_SIZE_ROUTER_BASIC,
	MLXSW_RES_ID_MAX_SYSTEM_PORT,
	MLXSW_RES_ID_FID,
	MLXSW_RES_ID_MAX_LAG,
	MLXSW_RES_ID_MAX_LAG_MEMBERS,
	MLXSW_RES_ID_GUARANTEED_SHARED_BUFFER,
	MLXSW_RES_ID_CELL_SIZE,
	MLXSW_RES_ID_MAX_HEADROOM_SIZE,
	MLXSW_RES_ID_ACL_MAX_TCAM_REGIONS,
	MLXSW_RES_ID_ACL_MAX_TCAM_RULES,
	MLXSW_RES_ID_ACL_MAX_REGIONS,
	MLXSW_RES_ID_ACL_MAX_GROUPS,
	MLXSW_RES_ID_ACL_MAX_GROUP_SIZE,
	MLXSW_RES_ID_ACL_MAX_DEFAULT_ACTIONS,
	MLXSW_RES_ID_ACL_FLEX_KEYS,
	MLXSW_RES_ID_ACL_MAX_ACTION_PER_RULE,
	MLXSW_RES_ID_ACL_ACTIONS_PER_SET,
	MLXSW_RES_ID_ACL_MAX_ERPT_BANKS,
	MLXSW_RES_ID_ACL_MAX_ERPT_BANK_SIZE,
	MLXSW_RES_ID_ACL_MAX_LARGE_KEY_ID,
	MLXSW_RES_ID_ACL_ERPT_ENTRIES_2KB,
	MLXSW_RES_ID_ACL_ERPT_ENTRIES_4KB,
	MLXSW_RES_ID_ACL_ERPT_ENTRIES_8KB,
	MLXSW_RES_ID_ACL_ERPT_ENTRIES_12KB,
	MLXSW_RES_ID_ACL_MAX_BF_LOG,
	MLXSW_RES_ID_MAX_GLOBAL_POLICERS,
	MLXSW_RES_ID_MAX_CPU_POLICERS,
	MLXSW_RES_ID_MAX_VRS,
	MLXSW_RES_ID_MAX_RIFS,
	MLXSW_RES_ID_MC_ERIF_LIST_ENTRIES,
	MLXSW_RES_ID_MAX_RIF_MAC_PROFILES,
	MLXSW_RES_ID_MAX_LPM_TREES,
	MLXSW_RES_ID_MAX_NVE_MC_ENTRIES_IPV4,
	MLXSW_RES_ID_MAX_NVE_MC_ENTRIES_IPV6,

	/* Internal resources.
	 * Determined by the SW, not queried from the HW.
	 */
	MLXSW_RES_ID_KVD_SINGLE_SIZE,
	MLXSW_RES_ID_KVD_DOUBLE_SIZE,
	MLXSW_RES_ID_KVD_LINEAR_SIZE,

	__MLXSW_RES_ID_MAX,
};

static u16 mlxsw_res_ids[] = {
	[MLXSW_RES_ID_KVD_SIZE] = 0x1001,
	[MLXSW_RES_ID_KVD_SINGLE_MIN_SIZE] = 0x1002,
	[MLXSW_RES_ID_KVD_DOUBLE_MIN_SIZE] = 0x1003,
	[MLXSW_RES_ID_PGT_SIZE] = 0x1004,
	[MLXSW_RES_ID_MAX_KVD_LINEAR_RANGE] = 0x1005,
	[MLXSW_RES_ID_MAX_KVD_ACTION_SETS] = 0x1007,
	[MLXSW_RES_ID_MAX_TRAP_GROUPS] = 0x2201,
	[MLXSW_RES_ID_CQE_V0] = 0x2210,
	[MLXSW_RES_ID_CQE_V1] = 0x2211,
	[MLXSW_RES_ID_CQE_V2] = 0x2212,
	[MLXSW_RES_ID_COUNTER_POOL_SIZE] = 0x2410,
	[MLXSW_RES_ID_COUNTER_BANK_SIZE] = 0x2411,
	[MLXSW_RES_ID_MAX_SPAN] = 0x2420,
	[MLXSW_RES_ID_COUNTER_SIZE_PACKETS_BYTES] = 0x2443,
	[MLXSW_RES_ID_COUNTER_SIZE_ROUTER_BASIC] = 0x2449,
	[MLXSW_RES_ID_MAX_SYSTEM_PORT] = 0x2502,
	[MLXSW_RES_ID_FID] = 0x2512,
	[MLXSW_RES_ID_MAX_LAG] = 0x2520,
	[MLXSW_RES_ID_MAX_LAG_MEMBERS] = 0x2521,
	[MLXSW_RES_ID_GUARANTEED_SHARED_BUFFER] = 0x2805,	/* Bytes */
	[MLXSW_RES_ID_CELL_SIZE] = 0x2803,	/* Bytes */
	[MLXSW_RES_ID_MAX_HEADROOM_SIZE] = 0x2811,	/* Bytes */
	[MLXSW_RES_ID_ACL_MAX_TCAM_REGIONS] = 0x2901,
	[MLXSW_RES_ID_ACL_MAX_TCAM_RULES] = 0x2902,
	[MLXSW_RES_ID_ACL_MAX_REGIONS] = 0x2903,
	[MLXSW_RES_ID_ACL_MAX_GROUPS] = 0x2904,
	[MLXSW_RES_ID_ACL_MAX_GROUP_SIZE] = 0x2905,
	[MLXSW_RES_ID_ACL_MAX_DEFAULT_ACTIONS] = 0x2908,
	[MLXSW_RES_ID_ACL_FLEX_KEYS] = 0x2910,
	[MLXSW_RES_ID_ACL_MAX_ACTION_PER_RULE] = 0x2911,
	[MLXSW_RES_ID_ACL_ACTIONS_PER_SET] = 0x2912,
	[MLXSW_RES_ID_ACL_MAX_ERPT_BANKS] = 0x2940,
	[MLXSW_RES_ID_ACL_MAX_ERPT_BANK_SIZE] = 0x2941,
	[MLXSW_RES_ID_ACL_MAX_LARGE_KEY_ID] = 0x2942,
	[MLXSW_RES_ID_ACL_ERPT_ENTRIES_2KB] = 0x2950,
	[MLXSW_RES_ID_ACL_ERPT_ENTRIES_4KB] = 0x2951,
	[MLXSW_RES_ID_ACL_ERPT_ENTRIES_8KB] = 0x2952,
	[MLXSW_RES_ID_ACL_ERPT_ENTRIES_12KB] = 0x2953,
	[MLXSW_RES_ID_ACL_MAX_BF_LOG] = 0x2960,
	[MLXSW_RES_ID_MAX_GLOBAL_POLICERS] = 0x2A10,
	[MLXSW_RES_ID_MAX_CPU_POLICERS] = 0x2A13,
	[MLXSW_RES_ID_MAX_VRS] = 0x2C01,
	[MLXSW_RES_ID_MAX_RIFS] = 0x2C02,
	[MLXSW_RES_ID_MC_ERIF_LIST_ENTRIES] = 0x2C10,
	[MLXSW_RES_ID_MAX_RIF_MAC_PROFILES] = 0x2C14,
	[MLXSW_RES_ID_MAX_LPM_TREES] = 0x2C30,
	[MLXSW_RES_ID_MAX_NVE_MC_ENTRIES_IPV4] = 0x2E02,
	[MLXSW_RES_ID_MAX_NVE_MC_ENTRIES_IPV6] = 0x2E03,
};

struct mlxsw_res {
	bool valid[__MLXSW_RES_ID_MAX];
	u64 values[__MLXSW_RES_ID_MAX];
};

static inline bool mlxsw_res_valid(struct mlxsw_res *res,
				   enum mlxsw_res_id res_id)
{
	return res->valid[res_id];
}

#define MLXSW_RES_VALID(res, short_res_id)			\
	mlxsw_res_valid(res, MLXSW_RES_ID_##short_res_id)

static inline u64 mlxsw_res_get(struct mlxsw_res *res,
				enum mlxsw_res_id res_id)
{
	if (WARN_ON(!res->valid[res_id]))
		return 0;
	return res->values[res_id];
}

#define MLXSW_RES_GET(res, short_res_id)			\
	mlxsw_res_get(res, MLXSW_RES_ID_##short_res_id)

static inline void mlxsw_res_set(struct mlxsw_res *res,
				 enum mlxsw_res_id res_id, u64 value)
{
	res->valid[res_id] = true;
	res->values[res_id] = value;
}

#define MLXSW_RES_SET(res, short_res_id, value)			\
	mlxsw_res_set(res, MLXSW_RES_ID_##short_res_id, value)

static inline void mlxsw_res_parse(struct mlxsw_res *res, u16 id, u64 value)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(mlxsw_res_ids); i++) {
		if (mlxsw_res_ids[i] == id) {
			mlxsw_res_set(res, i, value);
			return;
		}
	}
}

#endif
