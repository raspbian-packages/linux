/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * Libbpf legacy APIs (either discouraged or deprecated, as mentioned in [0])
 *
 *   [0] https://docs.google.com/document/d/1UyjTZuPFWiPFyKk1tV5an11_iaRuec6U-ZESZ54nNTY
 *
 * Copyright (C) 2021 Facebook
 */
#ifndef __LIBBPF_LEGACY_BPF_H
#define __LIBBPF_LEGACY_BPF_H

#include <linux/bpf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "libbpf_common.h"

#ifdef __cplusplus
extern "C" {
#endif

enum libbpf_strict_mode {
	/* Turn on all supported strict features of libbpf to simulate libbpf
	 * v1.0 behavior.
	 * This will be the default behavior in libbpf v1.0.
	 */
	LIBBPF_STRICT_ALL = 0xffffffff,

	/*
	 * Disable any libbpf 1.0 behaviors. This is the default before libbpf
	 * v1.0. It won't be supported anymore in v1.0, please update your
	 * code so that it handles LIBBPF_STRICT_ALL mode before libbpf v1.0.
	 */
	LIBBPF_STRICT_NONE = 0x00,
	/*
	 * Return NULL pointers on error, not ERR_PTR(err).
	 * Additionally, libbpf also always sets errno to corresponding Exx
	 * (positive) error code.
	 */
	LIBBPF_STRICT_CLEAN_PTRS = 0x01,
	/*
	 * Return actual error codes from low-level APIs directly, not just -1.
	 * Additionally, libbpf also always sets errno to corresponding Exx
	 * (positive) error code.
	 */
	LIBBPF_STRICT_DIRECT_ERRS = 0x02,

	/*
	 * Enforce strict BPF program section (SEC()) names.
	 * E.g., while prefiously SEC("xdp_whatever") or SEC("perf_event_blah") were
	 * allowed, with LIBBPF_STRICT_SEC_PREFIX this will become
	 * unrecognized by libbpf and would have to be just SEC("xdp") and
	 * SEC("xdp") and SEC("perf_event").
	 *
	 * Note, in this mode the program pin path will be based on the
	 * function name instead of section name.
	 */
	LIBBPF_STRICT_SEC_NAME = 0x04,
	/*
	 * Disable the global 'bpf_objects_list'. Maintaining this list adds
	 * a race condition to bpf_object__open() and bpf_object__close().
	 * Clients can maintain it on their own if it is valuable for them.
	 */
	LIBBPF_STRICT_NO_OBJECT_LIST = 0x08,

	__LIBBPF_STRICT_LAST,
};

LIBBPF_API int libbpf_set_strict_mode(enum libbpf_strict_mode mode);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __LIBBPF_LEGACY_BPF_H */
