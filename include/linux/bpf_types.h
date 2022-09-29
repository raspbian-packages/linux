/* SPDX-License-Identifier: GPL-2.0 */
/* internal file - do not include directly */

#ifdef CONFIG_NET
BPF_PROG_TYPE(BPF_PROG_TYPE_SOCKET_FILTER, sk_filter)
BPF_PROG_TYPE(BPF_PROG_TYPE_SCHED_CLS, tc_cls_act)
BPF_PROG_TYPE(BPF_PROG_TYPE_SCHED_ACT, tc_cls_act)
BPF_PROG_TYPE(BPF_PROG_TYPE_XDP, xdp)
BPF_PROG_TYPE(BPF_PROG_TYPE_CGROUP_SKB, cg_skb)
BPF_PROG_TYPE(BPF_PROG_TYPE_CGROUP_SOCK, cg_sock)
BPF_PROG_TYPE(BPF_PROG_TYPE_CGROUP_SOCK_ADDR, cg_sock_addr)
BPF_PROG_TYPE(BPF_PROG_TYPE_LWT_IN, lwt_in)
BPF_PROG_TYPE(BPF_PROG_TYPE_LWT_OUT, lwt_out)
BPF_PROG_TYPE(BPF_PROG_TYPE_LWT_XMIT, lwt_xmit)
BPF_PROG_TYPE(BPF_PROG_TYPE_LWT_SEG6LOCAL, lwt_seg6local)
BPF_PROG_TYPE(BPF_PROG_TYPE_SOCK_OPS, sock_ops)
BPF_PROG_TYPE(BPF_PROG_TYPE_SK_SKB, sk_skb)
BPF_PROG_TYPE(BPF_PROG_TYPE_SK_MSG, sk_msg)
#endif
#ifdef CONFIG_BPF_EVENTS
BPF_PROG_TYPE(BPF_PROG_TYPE_KPROBE, kprobe)
BPF_PROG_TYPE(BPF_PROG_TYPE_TRACEPOINT, tracepoint)
BPF_PROG_TYPE(BPF_PROG_TYPE_PERF_EVENT, perf_event)
BPF_PROG_TYPE(BPF_PROG_TYPE_RAW_TRACEPOINT, raw_tracepoint)
#endif
#ifdef CONFIG_CGROUP_BPF
BPF_PROG_TYPE(BPF_PROG_TYPE_CGROUP_DEVICE, cg_dev)
#endif
#ifdef CONFIG_BPF_LIRC_MODE2
BPF_PROG_TYPE(BPF_PROG_TYPE_LIRC_MODE2, lirc_mode2)
#endif
#ifdef CONFIG_INET
BPF_PROG_TYPE(BPF_PROG_TYPE_SK_REUSEPORT, sk_reuseport)
#endif

BPF_MAP_TYPE(BPF_MAP_TYPE_ARRAY, array_map_ops)
BPF_MAP_TYPE(BPF_MAP_TYPE_PERCPU_ARRAY, percpu_array_map_ops)
BPF_MAP_TYPE(BPF_MAP_TYPE_PROG_ARRAY, prog_array_map_ops)
BPF_MAP_TYPE(BPF_MAP_TYPE_PERF_EVENT_ARRAY, perf_event_array_map_ops)
#ifdef CONFIG_CGROUPS
BPF_MAP_TYPE(BPF_MAP_TYPE_CGROUP_ARRAY, cgroup_array_map_ops)
#endif
#ifdef CONFIG_CGROUP_BPF
BPF_MAP_TYPE(BPF_MAP_TYPE_CGROUP_STORAGE, cgroup_storage_map_ops)
#endif
BPF_MAP_TYPE(BPF_MAP_TYPE_HASH, htab_map_ops)
BPF_MAP_TYPE(BPF_MAP_TYPE_PERCPU_HASH, htab_percpu_map_ops)
BPF_MAP_TYPE(BPF_MAP_TYPE_LRU_HASH, htab_lru_map_ops)
BPF_MAP_TYPE(BPF_MAP_TYPE_LRU_PERCPU_HASH, htab_lru_percpu_map_ops)
BPF_MAP_TYPE(BPF_MAP_TYPE_LPM_TRIE, trie_map_ops)
#ifdef CONFIG_PERF_EVENTS
BPF_MAP_TYPE(BPF_MAP_TYPE_STACK_TRACE, stack_map_ops)
#endif
BPF_MAP_TYPE(BPF_MAP_TYPE_ARRAY_OF_MAPS, array_of_maps_map_ops)
BPF_MAP_TYPE(BPF_MAP_TYPE_HASH_OF_MAPS, htab_of_maps_map_ops)
#ifdef CONFIG_NET
BPF_MAP_TYPE(BPF_MAP_TYPE_DEVMAP, dev_map_ops)
#if defined(CONFIG_STREAM_PARSER) && defined(CONFIG_INET)
BPF_MAP_TYPE(BPF_MAP_TYPE_SOCKMAP, sock_map_ops)
BPF_MAP_TYPE(BPF_MAP_TYPE_SOCKHASH, sock_hash_ops)
#endif
BPF_MAP_TYPE(BPF_MAP_TYPE_CPUMAP, cpu_map_ops)
#if defined(CONFIG_XDP_SOCKETS)
BPF_MAP_TYPE(BPF_MAP_TYPE_XSKMAP, xsk_map_ops)
#endif
#ifdef CONFIG_INET
BPF_MAP_TYPE(BPF_MAP_TYPE_REUSEPORT_SOCKARRAY, reuseport_array_ops)
#endif
#endif
