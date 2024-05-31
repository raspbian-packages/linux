/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright(c) 2021 Intel Corporation. All rights reserved.
 *
 * Authors: Cezary Rojewski <cezary.rojewski@intel.com>
 *          Amadeusz Slawinski <amadeuszx.slawinski@linux.intel.com>
 */

#ifndef __UAPI_SOUND_INTEL_AVS_TOKENS_H
#define __UAPI_SOUND_INTEL_AVS_TOKENS_H

enum avs_tplg_token {
	/* struct avs_tplg */
	AVS_TKN_MANIFEST_NAME_STRING			= 1,
	AVS_TKN_MANIFEST_VERSION_U32			= 2,
	AVS_TKN_MANIFEST_NUM_LIBRARIES_U32		= 3,
	AVS_TKN_MANIFEST_NUM_AFMTS_U32			= 4,
	AVS_TKN_MANIFEST_NUM_MODCFGS_BASE_U32		= 5,
	AVS_TKN_MANIFEST_NUM_MODCFGS_EXT_U32		= 6,
	AVS_TKN_MANIFEST_NUM_PPLCFGS_U32		= 7,
	AVS_TKN_MANIFEST_NUM_BINDINGS_U32		= 8,

	/* struct avs_tplg_library */
	AVS_TKN_LIBRARY_ID_U32				= 101,
	AVS_TKN_LIBRARY_NAME_STRING			= 102,

	/* struct avs_audio_format */
	AVS_TKN_AFMT_ID_U32				= 201,
	AVS_TKN_AFMT_SAMPLE_RATE_U32			= 202,
	AVS_TKN_AFMT_BIT_DEPTH_U32			= 203,
	AVS_TKN_AFMT_CHANNEL_MAP_U32			= 204,
	AVS_TKN_AFMT_CHANNEL_CFG_U32			= 205,
	AVS_TKN_AFMT_INTERLEAVING_U32			= 206,
	AVS_TKN_AFMT_NUM_CHANNELS_U32			= 207,
	AVS_TKN_AFMT_VALID_BIT_DEPTH_U32		= 208,
	AVS_TKN_AFMT_SAMPLE_TYPE_U32			= 209,

	/* struct avs_tplg_modcfg_base */
	AVS_TKN_MODCFG_BASE_ID_U32			= 301,
	AVS_TKN_MODCFG_BASE_CPC_U32			= 302,
	AVS_TKN_MODCFG_BASE_IBS_U32			= 303,
	AVS_TKN_MODCFG_BASE_OBS_U32			= 304,
	AVS_TKN_MODCFG_BASE_PAGES_U32			= 305,

	/* struct avs_tplg_modcfg_ext */
	AVS_TKN_MODCFG_EXT_ID_U32			= 401,
	AVS_TKN_MODCFG_EXT_TYPE_UUID			= 402,
	AVS_TKN_MODCFG_CPR_OUT_AFMT_ID_U32		= 403,
	AVS_TKN_MODCFG_CPR_FEATURE_MASK_U32		= 404,
	AVS_TKN_MODCFG_CPR_DMA_TYPE_U32			= 405,
	AVS_TKN_MODCFG_CPR_DMABUFF_SIZE_U32		= 406,
	AVS_TKN_MODCFG_CPR_VINDEX_U8			= 407,
	AVS_TKN_MODCFG_CPR_BLOB_FMT_ID_U32		= 408,
	AVS_TKN_MODCFG_MICSEL_OUT_AFMT_ID_U32		= 409,
	AVS_TKN_MODCFG_INTELWOV_CPC_LP_MODE_U32		= 410,
	AVS_TKN_MODCFG_SRC_OUT_FREQ_U32			= 411,
	AVS_TKN_MODCFG_MUX_REF_AFMT_ID_U32		= 412,
	AVS_TKN_MODCFG_MUX_OUT_AFMT_ID_U32		= 413,
	AVS_TKN_MODCFG_AEC_REF_AFMT_ID_U32		= 414,
	AVS_TKN_MODCFG_AEC_OUT_AFMT_ID_U32		= 415,
	AVS_TKN_MODCFG_AEC_CPC_LP_MODE_U32		= 416,
	AVS_TKN_MODCFG_ASRC_OUT_FREQ_U32		= 417,
	AVS_TKN_MODCFG_ASRC_MODE_U8			= 418,
	AVS_TKN_MODCFG_ASRC_DISABLE_JITTER_U8		= 419,
	AVS_TKN_MODCFG_UPDOWN_MIX_OUT_CHAN_CFG_U32	= 420,
	AVS_TKN_MODCFG_UPDOWN_MIX_COEFF_SELECT_U32	= 421,
	AVS_TKN_MODCFG_UPDOWN_MIX_COEFF_0_S32		= 422,
	AVS_TKN_MODCFG_UPDOWN_MIX_COEFF_1_S32		= 423,
	AVS_TKN_MODCFG_UPDOWN_MIX_COEFF_2_S32		= 424,
	AVS_TKN_MODCFG_UPDOWN_MIX_COEFF_3_S32		= 425,
	AVS_TKN_MODCFG_UPDOWN_MIX_COEFF_4_S32		= 426,
	AVS_TKN_MODCFG_UPDOWN_MIX_COEFF_5_S32		= 427,
	AVS_TKN_MODCFG_UPDOWN_MIX_COEFF_6_S32		= 428,
	AVS_TKN_MODCFG_UPDOWN_MIX_COEFF_7_S32		= 429,
	AVS_TKN_MODCFG_UPDOWN_MIX_CHAN_MAP_U32		= 430,
	AVS_TKN_MODCFG_EXT_NUM_INPUT_PINS_U16		= 431,
	AVS_TKN_MODCFG_EXT_NUM_OUTPUT_PINS_U16		= 432,

	/* struct avs_tplg_pplcfg */
	AVS_TKN_PPLCFG_ID_U32				= 1401,
	AVS_TKN_PPLCFG_REQ_SIZE_U16			= 1402,
	AVS_TKN_PPLCFG_PRIORITY_U8			= 1403,
	AVS_TKN_PPLCFG_LOW_POWER_BOOL			= 1404,
	AVS_TKN_PPLCFG_ATTRIBUTES_U16			= 1405,
	AVS_TKN_PPLCFG_TRIGGER_U32			= 1406,

	/* struct avs_tplg_binding */
	AVS_TKN_BINDING_ID_U32				= 1501,
	AVS_TKN_BINDING_TARGET_TPLG_NAME_STRING		= 1502,
	AVS_TKN_BINDING_TARGET_PATH_TMPL_ID_U32		= 1503,
	AVS_TKN_BINDING_TARGET_PPL_ID_U32		= 1504,
	AVS_TKN_BINDING_TARGET_MOD_ID_U32		= 1505,
	AVS_TKN_BINDING_TARGET_MOD_PIN_U8		= 1506,
	AVS_TKN_BINDING_MOD_ID_U32			= 1507,
	AVS_TKN_BINDING_MOD_PIN_U8			= 1508,
	AVS_TKN_BINDING_IS_SINK_U8			= 1509,

	/* struct avs_tplg_pipeline */
	AVS_TKN_PPL_ID_U32				= 1601,
	AVS_TKN_PPL_PPLCFG_ID_U32			= 1602,
	AVS_TKN_PPL_NUM_BINDING_IDS_U32			= 1603,
	AVS_TKN_PPL_BINDING_ID_U32			= 1604,

	/* struct avs_tplg_module */
	AVS_TKN_MOD_ID_U32				= 1701,
	AVS_TKN_MOD_MODCFG_BASE_ID_U32			= 1702,
	AVS_TKN_MOD_IN_AFMT_ID_U32			= 1703,
	AVS_TKN_MOD_CORE_ID_U8				= 1704,
	AVS_TKN_MOD_PROC_DOMAIN_U8			= 1705,
	AVS_TKN_MOD_MODCFG_EXT_ID_U32			= 1706,
	AVS_TKN_MOD_KCONTROL_ID_U32			= 1707,

	/* struct avs_tplg_path_template */
	AVS_TKN_PATH_TMPL_ID_U32			= 1801,

	/* struct avs_tplg_path */
	AVS_TKN_PATH_ID_U32				= 1901,
	AVS_TKN_PATH_FE_FMT_ID_U32			= 1902,
	AVS_TKN_PATH_BE_FMT_ID_U32			= 1903,

	/* struct avs_tplg_pin_format */
	AVS_TKN_PIN_FMT_INDEX_U32			= 2201,
	AVS_TKN_PIN_FMT_IOBS_U32			= 2202,
	AVS_TKN_PIN_FMT_AFMT_ID_U32			= 2203,

	/* struct avs_tplg_kcontrol */
	AVS_TKN_KCONTROL_ID_U32				= 2301,
};

#endif
