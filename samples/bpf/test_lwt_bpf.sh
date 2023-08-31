#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# Uncomment to see generated bytecode
#VERBOSE=verbose

NS1=lwt_ns1
NS2=lwt_ns2
VETH0=tst_lwt1a
VETH1=tst_lwt1b
VETH2=tst_lwt2a
VETH3=tst_lwt2b
IPVETH0="192.168.254.1"
IPVETH1="192.168.254.2"
IPVETH1b="192.168.254.3"

IPVETH2="192.168.111.1"
IPVETH3="192.168.111.2"

IP_LOCAL="192.168.99.1"

PROG_SRC="test_lwt_bpf.c"
BPF_PROG="test_lwt_bpf.o"
TRACE_ROOT=/sys/kernel/tracing
CONTEXT_INFO=$(cat ${TRACE_ROOT}/trace_options | grep context)

function lookup_mac()
{
	set +x
	if [ ! -z "$2" ]; then
		MAC=$(ip netns exec $2 ip link show $1 | grep ether | awk '{print $2}')
	else
		MAC=$(ip link show $1 | grep ether | awk '{print $2}')
	fi
	MAC="${MAC//:/}"
	echo "0x${MAC:10:2}${MAC:8:2}${MAC:6:2}${MAC:4:2}${MAC:2:2}${MAC:0:2}"
	set -x
}

function cleanup {
	set +ex
	rm $BPF_PROG 2> /dev/null
	ip link del $VETH0 2> /dev/null
	ip link del $VETH1 2> /dev/null
	ip link del $VETH2 2> /dev/null
	ip link del $VETH3 2> /dev/null
	ip netns exec $NS1 killall netserver
	ip netns delete $NS1 2> /dev/null
	ip netns delete $NS2 2> /dev/null
	set -ex
}

function setup_one_veth {
	ip netns add $1
	ip link add $2 type veth peer name $3
	ip link set dev $2 up
	ip addr add $4/24 dev $2
	ip link set $3 netns $1
	ip netns exec $1 ip link set dev $3 up
	ip netns exec $1 ip addr add $5/24 dev $3

	if [ "$6" ]; then
		ip netns exec $1 ip addr add $6/32 dev $3
	fi
}

function get_trace {
	set +x
	cat ${TRACE_ROOT}/trace | grep -v '^#'
	set -x
}

function cleanup_routes {
	ip route del ${IPVETH1}/32 dev $VETH0 2> /dev/null || true
	ip route del table local local ${IP_LOCAL}/32 dev lo 2> /dev/null || true
}

function install_test {
	cleanup_routes
	cp /dev/null ${TRACE_ROOT}/trace

	OPTS="encap bpf headroom 14 $1 obj $BPF_PROG section $2 $VERBOSE"

	if [ "$1" == "in" ];  then
		ip route add table local local ${IP_LOCAL}/32 $OPTS dev lo
	else
		ip route add ${IPVETH1}/32 $OPTS dev $VETH0
	fi
}

function remove_prog {
	if [ "$1" == "in" ];  then
		ip route del table local local ${IP_LOCAL}/32 dev lo
	else
		ip route del ${IPVETH1}/32 dev $VETH0
	fi
}

function filter_trace {
	# Add newline to allow starting EXPECT= variables on newline
	NL=$'\n'
	echo "${NL}$*" | sed -e 's/bpf_trace_printk: //g'
}

function expect_fail {
	set +x
	echo "FAIL:"
	echo "Expected: $1"
	echo "Got: $2"
	set -x
	exit 1
}

function match_trace {
	set +x
	RET=0
	TRACE=$1
	EXPECT=$2
	GOT="$(filter_trace "$TRACE")"

	[ "$GOT" != "$EXPECT" ] && {
		expect_fail "$EXPECT" "$GOT"
		RET=1
	}
	set -x
	return $RET
}

function test_start {
	set +x
	echo "----------------------------------------------------------------"
	echo "Starting test: $*"
	echo "----------------------------------------------------------------"
	set -x
}

function failure {
	get_trace
	echo "FAIL: $*"
	exit 1
}

function test_ctx_xmit {
	test_start "test_ctx on lwt xmit"
	install_test xmit test_ctx
	ping -c 3 $IPVETH1 || {
		failure "test_ctx xmit: packets are dropped"
	}
	match_trace "$(get_trace)" "
len 84 hash 0 protocol 8
cb 1234 ingress_ifindex 0 ifindex $DST_IFINDEX
len 84 hash 0 protocol 8
cb 1234 ingress_ifindex 0 ifindex $DST_IFINDEX
len 84 hash 0 protocol 8
cb 1234 ingress_ifindex 0 ifindex $DST_IFINDEX" || exit 1
	remove_prog xmit
}

function test_ctx_out {
	test_start "test_ctx on lwt out"
	install_test out test_ctx
	ping -c 3 $IPVETH1 || {
		failure "test_ctx out: packets are dropped"
	}
	match_trace "$(get_trace)" "
len 84 hash 0 protocol 8
cb 1234 ingress_ifindex 0 ifindex 0
len 84 hash 0 protocol 8
cb 1234 ingress_ifindex 0 ifindex 0
len 84 hash 0 protocol 8
cb 1234 ingress_ifindex 0 ifindex 0" || exit 1
	remove_prog out
}

function test_ctx_in {
	test_start "test_ctx on lwt in"
	install_test in test_ctx
	ping -c 3 $IP_LOCAL || {
		failure "test_ctx out: packets are dropped"
	}
	# We will both request & reply packets as the packets will
	# be from $IP_LOCAL => $IP_LOCAL
	match_trace "$(get_trace)" "
len 84 hash 0 protocol 8
cb 1234 ingress_ifindex 1 ifindex 1
len 84 hash 0 protocol 8
cb 1234 ingress_ifindex 1 ifindex 1
len 84 hash 0 protocol 8
cb 1234 ingress_ifindex 1 ifindex 1
len 84 hash 0 protocol 8
cb 1234 ingress_ifindex 1 ifindex 1
len 84 hash 0 protocol 8
cb 1234 ingress_ifindex 1 ifindex 1
len 84 hash 0 protocol 8
cb 1234 ingress_ifindex 1 ifindex 1" || exit 1
	remove_prog in
}

function test_data {
	test_start "test_data on lwt $1"
	install_test $1 test_data
	ping -c 3 $IPVETH1 || {
		failure "test_data ${1}: packets are dropped"
	}
	match_trace "$(get_trace)" "
src: 1fea8c0 dst: 2fea8c0
src: 1fea8c0 dst: 2fea8c0
src: 1fea8c0 dst: 2fea8c0" || exit 1
	remove_prog $1
}

function test_data_in {
	test_start "test_data on lwt in"
	install_test in test_data
	ping -c 3 $IP_LOCAL || {
		failure "test_data in: packets are dropped"
	}
	# We will both request & reply packets as the packets will
	# be from $IP_LOCAL => $IP_LOCAL
	match_trace "$(get_trace)" "
src: 163a8c0 dst: 163a8c0
src: 163a8c0 dst: 163a8c0
src: 163a8c0 dst: 163a8c0
src: 163a8c0 dst: 163a8c0
src: 163a8c0 dst: 163a8c0
src: 163a8c0 dst: 163a8c0" || exit 1
	remove_prog in
}

function test_cb {
	test_start "test_cb on lwt $1"
	install_test $1 test_cb
	ping -c 3 $IPVETH1 || {
		failure "test_cb ${1}: packets are dropped"
	}
	match_trace "$(get_trace)" "
cb0: 0 cb1: 0 cb2: 0
cb3: 0 cb4: 0
cb0: 0 cb1: 0 cb2: 0
cb3: 0 cb4: 0
cb0: 0 cb1: 0 cb2: 0
cb3: 0 cb4: 0" || exit 1
	remove_prog $1
}

function test_cb_in {
	test_start "test_cb on lwt in"
	install_test in test_cb
	ping -c 3 $IP_LOCAL || {
		failure "test_cb in: packets are dropped"
	}
	# We will both request & reply packets as the packets will
	# be from $IP_LOCAL => $IP_LOCAL
	match_trace "$(get_trace)" "
cb0: 0 cb1: 0 cb2: 0
cb3: 0 cb4: 0
cb0: 0 cb1: 0 cb2: 0
cb3: 0 cb4: 0
cb0: 0 cb1: 0 cb2: 0
cb3: 0 cb4: 0
cb0: 0 cb1: 0 cb2: 0
cb3: 0 cb4: 0
cb0: 0 cb1: 0 cb2: 0
cb3: 0 cb4: 0
cb0: 0 cb1: 0 cb2: 0
cb3: 0 cb4: 0" || exit 1
	remove_prog in
}

function test_drop_all {
	test_start "test_drop_all on lwt $1"
	install_test $1 drop_all
	ping -c 3 $IPVETH1 && {
		failure "test_drop_all ${1}: Unexpected success of ping"
	}
	match_trace "$(get_trace)" "
dropping with: 2
dropping with: 2
dropping with: 2" || exit 1
	remove_prog $1
}

function test_drop_all_in {
	test_start "test_drop_all on lwt in"
	install_test in drop_all
	ping -c 3 $IP_LOCAL && {
		failure "test_drop_all in: Unexpected success of ping"
	}
	match_trace "$(get_trace)" "
dropping with: 2
dropping with: 2
dropping with: 2" || exit 1
	remove_prog in
}

function test_push_ll_and_redirect {
	test_start "test_push_ll_and_redirect on lwt xmit"
	install_test xmit push_ll_and_redirect
	ping -c 3 $IPVETH1 || {
		failure "Redirected packets appear to be dropped"
	}
	match_trace "$(get_trace)" "
redirected to $DST_IFINDEX
redirected to $DST_IFINDEX
redirected to $DST_IFINDEX" || exit 1
	remove_prog xmit
}

function test_no_l2_and_redirect {
	test_start "test_no_l2_and_redirect on lwt xmit"
	install_test xmit fill_garbage_and_redirect
	ping -c 3 $IPVETH1 && {
		failure "Unexpected success despite lack of L2 header"
	}
	match_trace "$(get_trace)" "
redirected to $DST_IFINDEX
redirected to $DST_IFINDEX
redirected to $DST_IFINDEX" || exit 1
	remove_prog xmit
}

function test_rewrite {
	test_start "test_rewrite on lwt xmit"
	install_test xmit test_rewrite
	ping -c 3 $IPVETH1 || {
		failure "Rewritten packets appear to be dropped"
	}
	match_trace "$(get_trace)" "
out: rewriting from 2fea8c0 to 3fea8c0
out: rewriting from 2fea8c0 to 3fea8c0
out: rewriting from 2fea8c0 to 3fea8c0" || exit 1
	remove_prog out
}

function test_fill_garbage {
	test_start "test_fill_garbage on lwt xmit"
	install_test xmit fill_garbage
	ping -c 3 $IPVETH1 && {
		failure "test_drop_all ${1}: Unexpected success of ping"
	}
	match_trace "$(get_trace)" "
Set initial 96 bytes of header to FF
Set initial 96 bytes of header to FF
Set initial 96 bytes of header to FF" || exit 1
	remove_prog xmit
}

function test_netperf_nop {
	test_start "test_netperf_nop on lwt xmit"
	install_test xmit nop
	netperf -H $IPVETH1 -t TCP_STREAM || {
		failure "packets appear to be dropped"
	}
	match_trace "$(get_trace)" ""|| exit 1
	remove_prog xmit
}

function test_netperf_redirect {
	test_start "test_netperf_redirect on lwt xmit"
	install_test xmit push_ll_and_redirect_silent
	netperf -H $IPVETH1 -t TCP_STREAM || {
		failure "Rewritten packets appear to be dropped"
	}
	match_trace "$(get_trace)" ""|| exit 1
	remove_prog xmit
}

cleanup
setup_one_veth $NS1 $VETH0 $VETH1 $IPVETH0 $IPVETH1 $IPVETH1b
setup_one_veth $NS2 $VETH2 $VETH3 $IPVETH2 $IPVETH3
ip netns exec $NS1 netserver
echo 1 > ${TRACE_ROOT}/tracing_on
echo nocontext-info > ${TRACE_ROOT}/trace_options

DST_MAC=$(lookup_mac $VETH1 $NS1)
SRC_MAC=$(lookup_mac $VETH0)
DST_IFINDEX=$(cat /sys/class/net/$VETH0/ifindex)

CLANG_OPTS="-O2 -target bpf -I ../include/"
CLANG_OPTS+=" -DSRC_MAC=$SRC_MAC -DDST_MAC=$DST_MAC -DDST_IFINDEX=$DST_IFINDEX"
clang $CLANG_OPTS -c $PROG_SRC -o $BPF_PROG

test_ctx_xmit
test_ctx_out
test_ctx_in
test_data "xmit"
test_data "out"
test_data_in
test_cb "xmit"
test_cb "out"
test_cb_in
test_drop_all "xmit"
test_drop_all "out"
test_drop_all_in
test_rewrite
test_push_ll_and_redirect
test_no_l2_and_redirect
test_fill_garbage
test_netperf_nop
test_netperf_redirect

cleanup
echo 0 > ${TRACE_ROOT}/tracing_on
echo $CONTEXT_INFO > ${TRACE_ROOT}/trace_options
exit 0
