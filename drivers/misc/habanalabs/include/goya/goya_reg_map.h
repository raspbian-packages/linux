/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef GOYA_REG_MAP_H_
#define GOYA_REG_MAP_H_

/*
 * PSOC scratch-pad registers
 */
#define mmCPU_PQ_BASE_ADDR_LOW	mmPSOC_GLOBAL_CONF_SCRATCHPAD_0
#define mmCPU_PQ_BASE_ADDR_HIGH	mmPSOC_GLOBAL_CONF_SCRATCHPAD_1
#define mmCPU_EQ_BASE_ADDR_LOW	mmPSOC_GLOBAL_CONF_SCRATCHPAD_2
#define mmCPU_EQ_BASE_ADDR_HIGH	mmPSOC_GLOBAL_CONF_SCRATCHPAD_3
#define mmCPU_EQ_LENGTH		mmPSOC_GLOBAL_CONF_SCRATCHPAD_4
#define mmCPU_PQ_LENGTH		mmPSOC_GLOBAL_CONF_SCRATCHPAD_5
#define mmCPU_EQ_CI		mmPSOC_GLOBAL_CONF_SCRATCHPAD_6
#define mmCPU_PQ_INIT_STATUS	mmPSOC_GLOBAL_CONF_SCRATCHPAD_7
#define mmCPU_CQ_BASE_ADDR_LOW	mmPSOC_GLOBAL_CONF_SCRATCHPAD_8
#define mmCPU_CQ_BASE_ADDR_HIGH	mmPSOC_GLOBAL_CONF_SCRATCHPAD_9
#define mmCPU_CQ_LENGTH		mmPSOC_GLOBAL_CONF_SCRATCHPAD_10
#define mmUPD_STS		mmPSOC_GLOBAL_CONF_SCRATCHPAD_26
#define mmUPD_CMD		mmPSOC_GLOBAL_CONF_SCRATCHPAD_27
#define mmPREBOOT_VER_OFFSET	mmPSOC_GLOBAL_CONF_SCRATCHPAD_28
#define mmUBOOT_VER_OFFSET	mmPSOC_GLOBAL_CONF_SCRATCHPAD_29
#define mmUBOOT_OFFSET		mmPSOC_GLOBAL_CONF_SCRATCHPAD_30
#define mmBTL_ID		mmPSOC_GLOBAL_CONF_SCRATCHPAD_31

#define mmHW_STATE		mmPSOC_GLOBAL_CONF_APP_STATUS

#endif /* GOYA_REG_MAP_H_ */
