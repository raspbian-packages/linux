// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int _version SEC("version") = 1;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, 2); /* invalid */
} nopinmap3 SEC(".maps");

char _license[] SEC("license") = "GPL";
