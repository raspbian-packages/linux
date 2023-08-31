#!/bin/bash
# SPDX-License-Identifier: GPL-2.0+
#
# Carry out a kvm-based run for the specified qemu-cmd file, which might
# have been generated by --build-only kvm.sh run.
#
# Usage: kvm-test-1-run-qemu.sh qemu-cmd-dir
#
# qemu-cmd-dir provides the directory containing qemu-cmd file.
#	This is assumed to be of the form prefix/ds/scenario, where
#	"ds" is the top-level date-stamped directory and "scenario"
#	is the scenario name.  Any required adjustments to this file
#	must have been made by the caller.  The shell-command comments
#	at the end of the qemu-cmd file are not optional.
#
# Copyright (C) 2021 Facebook, Inc.
#
# Authors: Paul E. McKenney <paulmck@kernel.org>

T="`mktemp -d ${TMPDIR-/tmp}/kvm-test-1-run-qemu.sh.XXXXXX`"
trap 'rm -rf $T' 0

resdir="$1"
if ! test -d "$resdir"
then
	echo $0: Nonexistent directory: $resdir
	exit 1
fi
if ! test -f "$resdir/qemu-cmd"
then
	echo $0: Nonexistent qemu-cmd file: $resdir/qemu-cmd
	exit 1
fi

echo ' ---' `date`: Starting kernel, PID $$

# Obtain settings from the qemu-cmd file.
grep '^#' $resdir/qemu-cmd | sed -e 's/^# //' > $T/qemu-cmd-settings
. $T/qemu-cmd-settings

# Decorate qemu-cmd with affinity, redirection, backgrounding, and PID capture
taskset_command=
if test -n "$TORTURE_AFFINITY"
then
	taskset_command="taskset -c $TORTURE_AFFINITY "
fi
sed -e 's/^[^#].*$/'"$taskset_command"'& 2>\&1 \&/' < $resdir/qemu-cmd > $T/qemu-cmd
echo 'qemu_pid=$!' >> $T/qemu-cmd
echo 'echo $qemu_pid > $resdir/qemu-pid' >> $T/qemu-cmd
echo 'taskset -c -p $qemu_pid > $resdir/qemu-affinity' >> $T/qemu-cmd

# In case qemu refuses to run...
echo "NOTE: $QEMU either did not run or was interactive" > $resdir/console.log

# Attempt to run qemu
kstarttime=`gawk 'BEGIN { print systime() }' < /dev/null`
( . $T/qemu-cmd; wait `cat  $resdir/qemu-pid`; echo $? > $resdir/qemu-retval ) &
commandcompleted=0
if test -z "$TORTURE_KCONFIG_GDB_ARG"
then
	sleep 10 # Give qemu's pid a chance to reach the file
	if test -s "$resdir/qemu-pid"
	then
		qemu_pid=`cat "$resdir/qemu-pid"`
		echo Monitoring qemu job at pid $qemu_pid `date`
	else
		qemu_pid=""
		echo Monitoring qemu job at yet-as-unknown pid `date`
	fi
fi
if test -n "$TORTURE_KCONFIG_GDB_ARG"
then
	base_resdir=`echo $resdir | sed -e 's/\.[0-9]\+$//'`
	if ! test -f $base_resdir/vmlinux
	then
		base_resdir="`cat re-run`/$resdir"
		if ! test -f $base_resdir/vmlinux
		then
			base_resdir=/path/to
		fi
	fi
	echo Waiting for you to attach a debug session, for example: > /dev/tty
	echo "    gdb $base_resdir/vmlinux" > /dev/tty
	echo 'After symbols load and the "(gdb)" prompt appears:' > /dev/tty
	echo "    target remote :1234" > /dev/tty
	echo "    continue" > /dev/tty
	kstarttime=`gawk 'BEGIN { print systime() }' < /dev/null`
fi
while :
do
	if test -z "$qemu_pid" && test -s "$resdir/qemu-pid"
	then
		qemu_pid=`cat "$resdir/qemu-pid"`
	fi
	kruntime=`gawk 'BEGIN { print systime() - '"$kstarttime"' }' < /dev/null`
	if test -z "$qemu_pid" || kill -0 "$qemu_pid" > /dev/null 2>&1
	then
		if test -n "$TORTURE_KCONFIG_GDB_ARG"
		then
			:
		elif test $kruntime -ge $seconds || test -f "$resdir/../STOP.1"
		then
			break;
		fi
		sleep 1
	else
		commandcompleted=1
		if test $kruntime -lt $seconds
		then
			echo Completed in $kruntime vs. $seconds >> $resdir/Warnings 2>&1
			grep "^(qemu) qemu:" $resdir/kvm-test-1-run*.sh.out >> $resdir/Warnings 2>&1
			killpid="`sed -n "s/^(qemu) qemu: terminating on signal [0-9]* from pid \([0-9]*\).*$/\1/p" $resdir/Warnings`"
			if test -n "$killpid"
			then
				echo "ps -fp $killpid" >> $resdir/Warnings 2>&1
				ps -fp $killpid >> $resdir/Warnings 2>&1
			fi
		else
			echo ' ---' `date`: "Kernel done"
		fi
		break
	fi
done
if test -z "$qemu_pid" && test -s "$resdir/qemu-pid"
then
	qemu_pid=`cat "$resdir/qemu-pid"`
fi
if test $commandcompleted -eq 0 && test -n "$qemu_pid"
then
	if ! test -f "$resdir/../STOP.1"
	then
		echo Grace period for qemu job at pid $qemu_pid `date`
	fi
	oldline="`tail $resdir/console.log`"
	while :
	do
		if test -f "$resdir/../STOP.1"
		then
			echo "PID $qemu_pid killed due to run STOP.1 request `date`" >> $resdir/Warnings 2>&1
			kill -KILL $qemu_pid
			break
		fi
		kruntime=`gawk 'BEGIN { print systime() - '"$kstarttime"' }' < /dev/null`
		if kill -0 $qemu_pid > /dev/null 2>&1
		then
			:
		else
			break
		fi
		must_continue=no
		newline="`tail $resdir/console.log`"
		if test "$newline" != "$oldline" && echo $newline | grep -q ' [0-9]\+us : '
		then
			must_continue=yes
		fi
		last_ts="`tail $resdir/console.log | grep '^\[ *[0-9]\+\.[0-9]\+]' | tail -1 | sed -e 's/^\[ *//' -e 's/\..*$//'`"
		if test -z "$last_ts"
		then
			last_ts=0
		fi
		if test "$newline" != "$oldline" && test "$last_ts" -lt $((seconds + $TORTURE_SHUTDOWN_GRACE)) && test "$last_ts" -gt "$TORTURE_SHUTDOWN_GRACE"
		then
			must_continue=yes
			if test $kruntime -ge $((seconds + $TORTURE_SHUTDOWN_GRACE))
			then
				echo Continuing at console.log time $last_ts \"`tail -n 1 $resdir/console.log`\" `date`
			fi
		fi
		if test $must_continue = no && test $kruntime -ge $((seconds + $TORTURE_SHUTDOWN_GRACE))
		then
			echo "!!! PID $qemu_pid hung at $kruntime vs. $seconds seconds `date`" >> $resdir/Warnings 2>&1
			kill -KILL $qemu_pid
			break
		fi
		oldline=$newline
		sleep 10
	done
elif test -z "$qemu_pid"
then
	echo Unknown PID, cannot kill qemu command
fi

# Tell the script that this run is done.
rm -f $resdir/build.run
