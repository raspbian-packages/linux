#!/bin/sh
# Check Arm SPE trace data recording and synthesized samples

# Uses the 'perf record' to record trace data of Arm SPE events;
# then verify if any SPE event samples are generated by SPE with
# 'perf script' and 'perf report' commands.

# SPDX-License-Identifier: GPL-2.0
# German Gomez <german.gomez@arm.com>, 2021

skip_if_no_arm_spe_event() {
	perf list | egrep -q 'arm_spe_[0-9]+//' && return 0

	# arm_spe event doesn't exist
	return 2
}

skip_if_no_arm_spe_event || exit 2

perfdata=$(mktemp /tmp/__perf_test.perf.data.XXXXX)
glb_err=0

cleanup_files()
{
	rm -f ${perfdata}
	exit $glb_err
}

trap cleanup_files exit term int

arm_spe_report() {
	if [ $2 != 0 ]; then
		echo "$1: FAIL"
		glb_err=$2
	else
		echo "$1: PASS"
	fi
}

perf_script_samples() {
	echo "Looking at perf.data file for dumping samples:"

	# from arm-spe.c/arm_spe_synth_events()
	events="(ld1-miss|ld1-access|llc-miss|lld-access|tlb-miss|tlb-access|branch-miss|remote-access|memory)"

	# Below is an example of the samples dumping:
	#	dd  3048 [002]          1    l1d-access:      ffffaa64999c __GI___libc_write+0x3c (/lib/aarch64-linux-gnu/libc-2.27.so)
	#	dd  3048 [002]          1    tlb-access:      ffffaa64999c __GI___libc_write+0x3c (/lib/aarch64-linux-gnu/libc-2.27.so)
	#	dd  3048 [002]          1        memory:      ffffaa64999c __GI___libc_write+0x3c (/lib/aarch64-linux-gnu/libc-2.27.so)
	perf script -F,-time -i ${perfdata} 2>&1 | \
		egrep " +$1 +[0-9]+ .* +${events}:(.*:)? +" > /dev/null 2>&1
}

perf_report_samples() {
	echo "Looking at perf.data file for reporting samples:"

	# Below is an example of the samples reporting:
	#   73.04%    73.04%  dd    libc-2.27.so      [.] _dl_addr
	#    7.71%     7.71%  dd    libc-2.27.so      [.] getenv
	#    2.59%     2.59%  dd    ld-2.27.so        [.] strcmp
	perf report --stdio -i ${perfdata} 2>&1 | \
		egrep " +[0-9]+\.[0-9]+% +[0-9]+\.[0-9]+% +$1 " > /dev/null 2>&1
}

arm_spe_snapshot_test() {
	echo "Recording trace with snapshot mode $perfdata"
	perf record -o ${perfdata} -e arm_spe// -S \
		-- dd if=/dev/zero of=/dev/null > /dev/null 2>&1 &
	PERFPID=$!

	# Wait for perf program
	sleep 1

	# Send signal to snapshot trace data
	kill -USR2 $PERFPID

	# Stop perf program
	kill $PERFPID
	wait $PERFPID

	perf_script_samples dd &&
	perf_report_samples dd

	err=$?
	arm_spe_report "SPE snapshot testing" $err
}

arm_spe_snapshot_test
exit $glb_err
