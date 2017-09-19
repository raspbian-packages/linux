/* set_timer latency test
 *		John Stultz (john.stultz@linaro.org)
 *              (C) Copyright Linaro 2014
 *              Licensed under the GPLv2
 *
 *   This test makes sure the set_timer api is correct
 *
 *  To build:
 *	$ gcc set-timer-lat.c -o set-timer-lat -lrt
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 */


#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#ifdef KTEST
#include "../kselftest.h"
#else
static inline int ksft_exit_pass(void)
{
	exit(0);
}
static inline int ksft_exit_fail(void)
{
	exit(1);
}
#endif

#define CLOCK_REALTIME			0
#define CLOCK_MONOTONIC			1
#define CLOCK_PROCESS_CPUTIME_ID	2
#define CLOCK_THREAD_CPUTIME_ID		3
#define CLOCK_MONOTONIC_RAW		4
#define CLOCK_REALTIME_COARSE		5
#define CLOCK_MONOTONIC_COARSE		6
#define CLOCK_BOOTTIME			7
#define CLOCK_REALTIME_ALARM		8
#define CLOCK_BOOTTIME_ALARM		9
#define CLOCK_HWSPECIFIC		10
#define CLOCK_TAI			11
#define NR_CLOCKIDS			12


#define NSEC_PER_SEC 1000000000ULL
#define UNRESONABLE_LATENCY 40000000 /* 40ms in nanosecs */

#define TIMER_SECS 1
int alarmcount;
int clock_id;
struct timespec start_time;
long long max_latency_ns;

char *clockstring(int clockid)
{
	switch (clockid) {
	case CLOCK_REALTIME:
		return "CLOCK_REALTIME";
	case CLOCK_MONOTONIC:
		return "CLOCK_MONOTONIC";
	case CLOCK_PROCESS_CPUTIME_ID:
		return "CLOCK_PROCESS_CPUTIME_ID";
	case CLOCK_THREAD_CPUTIME_ID:
		return "CLOCK_THREAD_CPUTIME_ID";
	case CLOCK_MONOTONIC_RAW:
		return "CLOCK_MONOTONIC_RAW";
	case CLOCK_REALTIME_COARSE:
		return "CLOCK_REALTIME_COARSE";
	case CLOCK_MONOTONIC_COARSE:
		return "CLOCK_MONOTONIC_COARSE";
	case CLOCK_BOOTTIME:
		return "CLOCK_BOOTTIME";
	case CLOCK_REALTIME_ALARM:
		return "CLOCK_REALTIME_ALARM";
	case CLOCK_BOOTTIME_ALARM:
		return "CLOCK_BOOTTIME_ALARM";
	case CLOCK_TAI:
		return "CLOCK_TAI";
	};
	return "UNKNOWN_CLOCKID";
}


long long timespec_sub(struct timespec a, struct timespec b)
{
	long long ret = NSEC_PER_SEC * b.tv_sec + b.tv_nsec;

	ret -= NSEC_PER_SEC * a.tv_sec + a.tv_nsec;
	return ret;
}


void sigalarm(int signo)
{
	long long delta_ns;
	struct timespec ts;

	clock_gettime(clock_id, &ts);
	alarmcount++;

	delta_ns = timespec_sub(start_time, ts);
	delta_ns -= NSEC_PER_SEC * TIMER_SECS * alarmcount;

	if (delta_ns < 0)
		printf("%s timer fired early: FAIL\n", clockstring(clock_id));

	if (delta_ns > max_latency_ns)
		max_latency_ns = delta_ns;
}

int do_timer(int clock_id, int flags)
{
	struct sigevent se;
	timer_t tm1;
	struct itimerspec its1, its2;
	int err;

	/* Set up timer: */
	memset(&se, 0, sizeof(se));
	se.sigev_notify = SIGEV_SIGNAL;
	se.sigev_signo = SIGRTMAX;
	se.sigev_value.sival_int = 0;

	max_latency_ns = 0;
	alarmcount = 0;

	err = timer_create(clock_id, &se, &tm1);
	if (err) {
		if ((clock_id == CLOCK_REALTIME_ALARM) ||
		    (clock_id == CLOCK_BOOTTIME_ALARM)) {
			printf("%-22s %s missing CAP_WAKE_ALARM?    : [UNSUPPORTED]\n",
					clockstring(clock_id),
					flags ? "ABSTIME":"RELTIME");
			return 0;
		}
		printf("%s - timer_create() failed\n", clockstring(clock_id));
		return -1;
	}

	clock_gettime(clock_id, &start_time);
	if (flags) {
		its1.it_value = start_time;
		its1.it_value.tv_sec += TIMER_SECS;
	} else {
		its1.it_value.tv_sec = TIMER_SECS;
		its1.it_value.tv_nsec = 0;
	}
	its1.it_interval.tv_sec = TIMER_SECS;
	its1.it_interval.tv_nsec = 0;

	err = timer_settime(tm1, flags, &its1, &its2);
	if (err) {
		printf("%s - timer_settime() failed\n", clockstring(clock_id));
		return -1;
	}

	while (alarmcount < 5)
		sleep(1);

	printf("%-22s %s max latency: %10lld ns : ",
			clockstring(clock_id),
			flags ? "ABSTIME":"RELTIME",
			max_latency_ns);

	timer_delete(tm1);
	if (max_latency_ns < UNRESONABLE_LATENCY) {
		printf("[OK]\n");
		return 0;
	}
	printf("[FAILED]\n");
	return -1;
}

int main(void)
{
	struct sigaction act;
	int signum = SIGRTMAX;
	int ret = 0;

	/* Set up signal handler: */
	sigfillset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = sigalarm;
	sigaction(signum, &act, NULL);

	printf("Setting timers for every %i seconds\n", TIMER_SECS);
	for (clock_id = 0; clock_id < NR_CLOCKIDS; clock_id++) {

		if ((clock_id == CLOCK_PROCESS_CPUTIME_ID) ||
				(clock_id == CLOCK_THREAD_CPUTIME_ID) ||
				(clock_id == CLOCK_MONOTONIC_RAW) ||
				(clock_id == CLOCK_REALTIME_COARSE) ||
				(clock_id == CLOCK_MONOTONIC_COARSE) ||
				(clock_id == CLOCK_HWSPECIFIC))
			continue;

		ret |= do_timer(clock_id, TIMER_ABSTIME);
		ret |= do_timer(clock_id, 0);
	}
	if (ret)
		return ksft_exit_fail();
	return ksft_exit_pass();
}
