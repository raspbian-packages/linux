/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Intel Speed Select -- Enumerate and control features
 * Copyright (c) 2019 Intel Corporation.
 */

#ifndef _ISST_H_
#define _ISST_H_

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <getopt.h>
#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <cpuid.h>
#include <dirent.h>
#include <errno.h>

#include <stdarg.h>
#include <sys/ioctl.h>

#define BIT(x) (1 << (x))
#define BIT_ULL(nr) (1ULL << (nr))
#define GENMASK(h, l) (((~0UL) << (l)) & (~0UL >> (sizeof(long) * 8 - 1 - (h))))
#define GENMASK_ULL(h, l)                                                      \
	(((~0ULL) << (l)) & (~0ULL >> (sizeof(long long) * 8 - 1 - (h))))

#define CONFIG_TDP				0x7f
#define CONFIG_TDP_GET_LEVELS_INFO		0x00
#define CONFIG_TDP_GET_TDP_CONTROL		0x01
#define CONFIG_TDP_SET_TDP_CONTROL		0x02
#define CONFIG_TDP_GET_TDP_INFO			0x03
#define CONFIG_TDP_GET_PWR_INFO			0x04
#define CONFIG_TDP_GET_TJMAX_INFO		0x05
#define CONFIG_TDP_GET_CORE_MASK		0x06
#define CONFIG_TDP_GET_TURBO_LIMIT_RATIOS	0x07
#define CONFIG_TDP_SET_LEVEL			0x08
#define CONFIG_TDP_GET_UNCORE_P0_P1_INFO	0X09
#define CONFIG_TDP_GET_P1_INFO			0x0a
#define CONFIG_TDP_GET_MEM_FREQ			0x0b

#define CONFIG_TDP_GET_FACT_HP_TURBO_LIMIT_NUMCORES	0x10
#define CONFIG_TDP_GET_FACT_HP_TURBO_LIMIT_RATIOS	0x11
#define CONFIG_TDP_GET_FACT_LP_CLIPPING_RATIO		0x12

#define CONFIG_TDP_PBF_GET_CORE_MASK_INFO	0x20
#define CONFIG_TDP_PBF_GET_P1HI_P1LO_INFO	0x21
#define CONFIG_TDP_PBF_GET_TJ_MAX_INFO		0x22
#define CONFIG_TDP_PBF_GET_TDP_INFO		0X23

#define CONFIG_CLOS				0xd0
#define CLOS_PQR_ASSOC				0x00
#define CLOS_PM_CLOS				0x01
#define CLOS_PM_QOS_CONFIG			0x02
#define CLOS_STATUS				0x03

#define MBOX_CMD_WRITE_BIT			0x08

#define PM_QOS_INFO_OFFSET			0x00
#define PM_QOS_CONFIG_OFFSET			0x04
#define PM_CLOS_OFFSET				0x08
#define PQR_ASSOC_OFFSET			0x20

#define READ_PM_CONFIG				0x94
#define WRITE_PM_CONFIG				0x95
#define PM_FEATURE				0x03

#define DISP_FREQ_MULTIPLIER 100

#define MAX_PACKAGE_COUNT 8
#define MAX_DIE_PER_PACKAGE 2

/* Unified structure to specific a CPU or a Power Domain */
struct isst_id {
	int cpu;
	int pkg;
	int die;
};

struct isst_clos_config {
	unsigned char epp;
	unsigned char clos_prop_prio;
	unsigned char clos_min;
	unsigned char clos_max;
	unsigned char clos_desired;
};

struct isst_fact_bucket_info {
	int high_priority_cores_count;
	int sse_trl;
	int avx_trl;
	int avx512_trl;
};

struct isst_pbf_info {
	int pbf_acticated;
	int pbf_available;
	size_t core_cpumask_size;
	cpu_set_t *core_cpumask;
	int p1_high;
	int p1_low;
	int t_control;
	int t_prochot;
	int tdp;
};

#define ISST_TRL_MAX_ACTIVE_CORES	8
#define ISST_FACT_MAX_BUCKETS		8
struct isst_fact_info {
	int lp_clipping_ratio_license_sse;
	int lp_clipping_ratio_license_avx2;
	int lp_clipping_ratio_license_avx512;
	struct isst_fact_bucket_info bucket_info[ISST_FACT_MAX_BUCKETS];
};

struct isst_pkg_ctdp_level_info {
	int processed;
	int control_cpu;
	int pkg_id;
	int die_id;
	int level;
	int fact_support;
	int pbf_support;
	int fact_enabled;
	int pbf_enabled;
	int sst_cp_support;
	int sst_cp_enabled;
	int tdp_ratio;
	int active;
	int tdp_control;
	int pkg_tdp;
	int pkg_min_power;
	int pkg_max_power;
	int fact;
	int t_proc_hot;
	int uncore_p0;
	int uncore_p1;
	int sse_p1;
	int avx2_p1;
	int avx512_p1;
	int mem_freq;
	size_t core_cpumask_size;
	cpu_set_t *core_cpumask;
	int cpu_count;
	unsigned long long buckets_info;
	int trl_sse_active_cores[ISST_TRL_MAX_ACTIVE_CORES];
	int trl_avx_active_cores[ISST_TRL_MAX_ACTIVE_CORES];
	int trl_avx_512_active_cores[ISST_TRL_MAX_ACTIVE_CORES];
	int kobj_bucket_index;
	int active_bucket;
	int fact_max_index;
	int fact_max_config;
	int pbf_found;
	int pbf_active;
	struct isst_pbf_info pbf_info;
	struct isst_fact_info fact_info;
};

#define ISST_MAX_TDP_LEVELS	(4 + 1) /* +1 for base config */
struct isst_pkg_ctdp {
	int locked;
	int version;
	int processed;
	int levels;
	int current_level;
	int enabled;
	struct isst_pkg_ctdp_level_info ctdp_level[ISST_MAX_TDP_LEVELS];
};

extern int is_cpu_in_power_domain(int cpu, struct isst_id *id);
extern int get_topo_max_cpus(void);
extern int get_cpu_count(struct isst_id *id);
extern int get_max_punit_core_id(struct isst_id *id);

/* Common interfaces */
FILE *get_output_file(void);
extern void debug_printf(const char *format, ...);
extern int out_format_is_json(void);
extern void set_isst_id(struct isst_id *id, int cpu);
extern size_t alloc_cpu_set(cpu_set_t **cpu_set);
extern void free_cpu_set(cpu_set_t *cpu_set);
extern int find_phy_core_num(int logical_cpu);
extern void set_cpu_mask_from_punit_coremask(struct isst_id *id,
					     unsigned long long core_mask,
					     size_t core_cpumask_size,
					     cpu_set_t *core_cpumask,
					     int *cpu_cnt);

extern int isst_send_mbox_command(unsigned int cpu, unsigned char command,
				  unsigned char sub_command,
				  unsigned int write,
				  unsigned int req_data, unsigned int *resp);

extern int isst_send_msr_command(unsigned int cpu, unsigned int command,
				 int write, unsigned long long *req_resp);

extern int isst_get_ctdp_levels(struct isst_id *id, struct isst_pkg_ctdp *pkg_dev);
extern int isst_get_ctdp_control(struct isst_id *id, int config_index,
				 struct isst_pkg_ctdp_level_info *ctdp_level);
extern int isst_get_coremask_info(struct isst_id *id, int config_index,
			   struct isst_pkg_ctdp_level_info *ctdp_level);
extern int isst_get_process_ctdp(struct isst_id *id, int tdp_level,
				 struct isst_pkg_ctdp *pkg_dev);
extern void isst_get_process_ctdp_complete(struct isst_id *id,
					   struct isst_pkg_ctdp *pkg_dev);
extern void isst_ctdp_display_information(struct isst_id *id, FILE *outf, int tdp_level,
					  struct isst_pkg_ctdp *pkg_dev);
extern void isst_ctdp_display_core_info(struct isst_id *id, FILE *outf, char *prefix,
					unsigned int val, char *str0, char *str1);
extern void isst_ctdp_display_information_start(FILE *outf);
extern void isst_ctdp_display_information_end(FILE *outf);
extern void isst_pbf_display_information(struct isst_id *id, FILE *outf, int level,
					 struct isst_pbf_info *info);
extern int isst_set_tdp_level(struct isst_id *id, int tdp_level);
extern int isst_set_pbf_fact_status(struct isst_id *id, int pbf, int enable);
extern int isst_get_pbf_info(struct isst_id *id, int level,
			     struct isst_pbf_info *pbf_info);
extern void isst_get_pbf_info_complete(struct isst_pbf_info *pbf_info);
extern int isst_get_fact_info(struct isst_id *id, int level, int fact_bucket,
			      struct isst_fact_info *fact_info);
extern int isst_get_fact_bucket_info(struct isst_id *id, int level,
				     struct isst_fact_bucket_info *bucket_info);
extern void isst_fact_display_information(struct isst_id *id, FILE *outf, int level,
					  int fact_bucket, int fact_avx,
					  struct isst_fact_info *fact_info);
extern int isst_set_trl(struct isst_id *id, unsigned long long trl);
extern int isst_get_trl(struct isst_id *id, unsigned long long *trl);
extern int isst_set_trl_from_current_tdp(struct isst_id *id, unsigned long long trl);
extern int isst_get_config_tdp_lock_status(struct isst_id *id);

extern int isst_pm_qos_config(struct isst_id *id, int enable_clos, int priority_type);
extern int isst_pm_get_clos(struct isst_id *id, int clos,
			    struct isst_clos_config *clos_config);
extern int isst_set_clos(struct isst_id *id, int clos,
			 struct isst_clos_config *clos_config);
extern int isst_clos_associate(struct isst_id *id, int clos);
extern int isst_clos_get_assoc_status(struct isst_id *id, int *clos_id);
extern void isst_clos_display_information(struct isst_id *id, FILE *outf, int clos,
					  struct isst_clos_config *clos_config);
extern void isst_clos_display_assoc_information(struct isst_id *id, FILE *outf, int clos);

extern void isst_display_result(struct isst_id *id, FILE *outf, char *feature, char *cmd,
				int result);

extern int isst_clos_get_clos_information(struct isst_id *id, int *enable, int *type);
extern void isst_clos_display_clos_information(struct isst_id *id, FILE *outf,
					       int clos_enable, int type,
					       int state, int cap);
extern int is_clx_n_platform(void);
extern int get_cpufreq_base_freq(int cpu);
extern int isst_read_pm_config(struct isst_id *id, int *cp_state, int *cp_cap);
extern void isst_display_error_info_message(int error, char *msg, int arg_valid, int arg);
extern int is_skx_based_platform(void);
extern int is_spr_platform(void);
extern int is_icx_platform(void);
extern void isst_trl_display_information(struct isst_id *id, FILE *outf, unsigned long long trl);

extern void set_cpu_online_offline(int cpu, int state);
extern void for_each_online_package_in_set(void (*callback)(struct isst_id *, void *, void *,
							    void *, void *),
					   void *arg1, void *arg2, void *arg3,
					   void *arg4);
extern int isst_daemon(int debug_mode, int poll_interval, int no_daemon);
extern void process_level_change(struct isst_id *id);
extern int hfi_main(void);
extern void hfi_exit(void);
#endif
