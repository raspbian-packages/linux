#!/bin/sh
# Check Arm CoreSight trace data recording and synthesized samples

# Uses the 'perf record' to record trace data with Arm CoreSight sinks;
# then verify if there have any branch samples and instruction samples
# are generated by CoreSight with 'perf script' and 'perf report'
# commands.

# SPDX-License-Identifier: GPL-2.0
# Leo Yan <leo.yan@linaro.org>, 2020

glb_err=0

skip_if_no_cs_etm_event() {
	perf list | grep -q 'cs_etm//' && return 0

	# cs_etm event doesn't exist
	return 2
}

skip_if_no_cs_etm_event || exit 2

perfdata=$(mktemp /tmp/__perf_test.perf.data.XXXXX)
file=$(mktemp /tmp/temporary_file.XXXXX)

cleanup_files()
{
	rm -f ${perfdata}
	rm -f ${file}
	rm -f "${perfdata}.old"
	trap - exit term int
	exit $glb_err
}

trap cleanup_files exit term int

record_touch_file() {
	echo "Recording trace (only user mode) with path: CPU$2 => $1"
	rm -f $file
	perf record -o ${perfdata} -e cs_etm/@$1/u --per-thread \
		-- taskset -c $2 touch $file > /dev/null 2>&1
}

perf_script_branch_samples() {
	echo "Looking at perf.data file for dumping branch samples:"

	# Below is an example of the branch samples dumping:
	#   touch  6512          1         branches:u:      ffffb220824c strcmp+0xc (/lib/aarch64-linux-gnu/ld-2.27.so)
	#   touch  6512          1         branches:u:      ffffb22082e0 strcmp+0xa0 (/lib/aarch64-linux-gnu/ld-2.27.so)
	#   touch  6512          1         branches:u:      ffffb2208320 strcmp+0xe0 (/lib/aarch64-linux-gnu/ld-2.27.so)
	perf script -F,-time -i ${perfdata} 2>&1 | \
		grep -E " +$1 +[0-9]+ .* +branches:(.*:)? +" > /dev/null 2>&1
}

perf_report_branch_samples() {
	echo "Looking at perf.data file for reporting branch samples:"

	# Below is an example of the branch samples reporting:
	#   73.04%    73.04%  touch    libc-2.27.so      [.] _dl_addr
	#    7.71%     7.71%  touch    libc-2.27.so      [.] getenv
	#    2.59%     2.59%  touch    ld-2.27.so        [.] strcmp
	perf report --stdio -i ${perfdata} 2>&1 | \
		grep -E " +[0-9]+\.[0-9]+% +[0-9]+\.[0-9]+% +$1 " > /dev/null 2>&1
}

perf_report_instruction_samples() {
	echo "Looking at perf.data file for instruction samples:"

	# Below is an example of the instruction samples reporting:
	#   68.12%  touch    libc-2.27.so   [.] _dl_addr
	#    5.80%  touch    libc-2.27.so   [.] getenv
	#    4.35%  touch    ld-2.27.so     [.] _dl_fixup
	perf report --itrace=i20i --stdio -i ${perfdata} 2>&1 | \
		grep -E " +[0-9]+\.[0-9]+% +$1" > /dev/null 2>&1
}

arm_cs_report() {
	if [ $2 != 0 ]; then
		echo "$1: FAIL"
		glb_err=$2
	else
		echo "$1: PASS"
	fi
}

is_device_sink() {
	# If the node of "enable_sink" is existed under the device path, this
	# means the device is a sink device.  Need to exclude 'tpiu' since it
	# cannot support perf PMU.
	echo "$1" | grep -E -q -v "tpiu"

	if [ $? -eq 0 -a -e "$1/enable_sink" ]; then

		pmu_dev="/sys/bus/event_source/devices/cs_etm/sinks/$2"

		# Warn if the device is not supported by PMU
		if ! [ -f $pmu_dev ]; then
			echo "PMU doesn't support $pmu_dev"
		fi

		return 0
	fi

	# Otherwise, it's not a sink device
	return 1
}

arm_cs_iterate_devices() {
	for dev in $1/connections/out\:*; do

		# Skip testing if it's not a directory
		! [ -d $dev ] && continue;

		# Read out its symbol link file name
		path=`readlink -f $dev`

		# Extract device name from path, e.g.
		#   path = '/sys/devices/platform/20010000.etf/tmc_etf0'
		#     `> device_name = 'tmc_etf0'
		device_name=$(basename $path)

		if is_device_sink $path $device_name; then

			record_touch_file $device_name $2 &&
			perf_script_branch_samples touch &&
			perf_report_branch_samples touch &&
			perf_report_instruction_samples touch

			err=$?
			arm_cs_report "CoreSight path testing (CPU$2 -> $device_name)" $err
		fi

		arm_cs_iterate_devices $dev $2
	done
}

arm_cs_etm_traverse_path_test() {
	# Iterate for every ETM device
	for dev in /sys/bus/coresight/devices/etm*; do

		# Find the ETM device belonging to which CPU
		cpu=`cat $dev/cpu`

		# Use depth-first search (DFS) to iterate outputs
		arm_cs_iterate_devices $dev $cpu
	done
}

arm_cs_etm_system_wide_test() {
	echo "Recording trace with system wide mode"
	perf record -o ${perfdata} -e cs_etm// -a -- ls > /dev/null 2>&1

	# System-wide mode should include perf samples so test for that
	# instead of ls
	perf_script_branch_samples perf &&
	perf_report_branch_samples perf &&
	perf_report_instruction_samples perf

	err=$?
	arm_cs_report "CoreSight system wide testing" $err
}

arm_cs_etm_snapshot_test() {
	echo "Recording trace with snapshot mode"
	perf record -o ${perfdata} -e cs_etm// -S \
		-- dd if=/dev/zero of=/dev/null > /dev/null 2>&1 &
	PERFPID=$!

	# Wait for perf program
	sleep 1

	# Send signal to snapshot trace data
	kill -USR2 $PERFPID

	# Stop perf program
	kill $PERFPID
	wait $PERFPID

	perf_script_branch_samples dd &&
	perf_report_branch_samples dd &&
	perf_report_instruction_samples dd

	err=$?
	arm_cs_report "CoreSight snapshot testing" $err
}

arm_cs_etm_basic_test() {
	echo "Recording trace with '$*'"
	perf record -o ${perfdata} "$@" -- ls > /dev/null 2>&1

	perf_script_branch_samples ls &&
	perf_report_branch_samples ls &&
	perf_report_instruction_samples ls

	err=$?
	arm_cs_report "CoreSight basic testing with '$*'" $err
}

arm_cs_etm_traverse_path_test
arm_cs_etm_system_wide_test
arm_cs_etm_snapshot_test

# Test all combinations of per-thread, system-wide and normal mode with
# and without timestamps
arm_cs_etm_basic_test -e cs_etm/timestamp=0/ --per-thread
arm_cs_etm_basic_test -e cs_etm/timestamp=1/ --per-thread
arm_cs_etm_basic_test -e cs_etm/timestamp=0/ -a
arm_cs_etm_basic_test -e cs_etm/timestamp=1/ -a
arm_cs_etm_basic_test -e cs_etm/timestamp=0/
arm_cs_etm_basic_test -e cs_etm/timestamp=1/

exit $glb_err
