/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2020-2021 Intel Corporation
 */

#ifndef __INTEL_DP_AUX_H__
#define __INTEL_DP_AUX_H__

enum aux_ch;
struct intel_dp;
struct intel_encoder;

void intel_dp_aux_fini(struct intel_dp *intel_dp);
void intel_dp_aux_init(struct intel_dp *intel_dp);

enum aux_ch intel_dp_aux_ch(struct intel_encoder *encoder);

#endif /* __INTEL_DP_AUX_H__ */
