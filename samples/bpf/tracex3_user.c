// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2013-2015 PLUMgrid, http://plumgrid.com
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <linux/bpf.h>
#include <sys/resource.h>

#include <bpf/bpf.h>
#include "bpf_load.h"
#include "bpf_util.h"

#define SLOTS 100

static void clear_stats(int fd)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	__u64 values[nr_cpus];
	__u32 key;

	memset(values, 0, sizeof(values));
	for (key = 0; key < SLOTS; key++)
		bpf_map_update_elem(fd, &key, values, BPF_ANY);
}

const char *color[] = {
	"\033[48;5;255m",
	"\033[48;5;252m",
	"\033[48;5;250m",
	"\033[48;5;248m",
	"\033[48;5;246m",
	"\033[48;5;244m",
	"\033[48;5;242m",
	"\033[48;5;240m",
	"\033[48;5;238m",
	"\033[48;5;236m",
	"\033[48;5;234m",
	"\033[48;5;232m",
};
const int num_colors = ARRAY_SIZE(color);

const char nocolor[] = "\033[00m";

const char *sym[] = {
	" ",
	" ",
	".",
	".",
	"*",
	"*",
	"o",
	"o",
	"O",
	"O",
	"#",
	"#",
};

bool full_range = false;
bool text_only = false;

static void print_banner(void)
{
	if (full_range)
		printf("|1ns     |10ns     |100ns    |1us      |10us     |100us"
		       "    |1ms      |10ms     |100ms    |1s       |10s\n");
	else
		printf("|1us      |10us     |100us    |1ms      |10ms     "
		       "|100ms    |1s       |10s\n");
}

static void print_hist(int fd)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	__u64 total_events = 0;
	long values[nr_cpus];
	__u64 max_cnt = 0;
	__u64 cnt[SLOTS];
	__u64 value;
	__u32 key;
	int i;

	for (key = 0; key < SLOTS; key++) {
		bpf_map_lookup_elem(fd, &key, values);
		value = 0;
		for (i = 0; i < nr_cpus; i++)
			value += values[i];
		cnt[key] = value;
		total_events += value;
		if (value > max_cnt)
			max_cnt = value;
	}
	clear_stats(fd);
	for (key = full_range ? 0 : 29; key < SLOTS; key++) {
		int c = num_colors * cnt[key] / (max_cnt + 1);

		if (text_only)
			printf("%s", sym[c]);
		else
			printf("%s %s", color[c], nocolor);
	}
	printf(" # %lld\n", total_events);
}

int main(int ac, char **argv)
{
	struct rlimit r = {1024*1024, RLIM_INFINITY};
	char filename[256];
	int i;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		return 1;
	}

	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}

	for (i = 1; i < ac; i++) {
		if (strcmp(argv[i], "-a") == 0) {
			full_range = true;
		} else if (strcmp(argv[i], "-t") == 0) {
			text_only = true;
		} else if (strcmp(argv[i], "-h") == 0) {
			printf("Usage:\n"
			       "  -a display wider latency range\n"
			       "  -t text only\n");
			return 1;
		}
	}

	printf("  heatmap of IO latency\n");
	if (text_only)
		printf("  %s", sym[num_colors - 1]);
	else
		printf("  %s %s", color[num_colors - 1], nocolor);
	printf(" - many events with this latency\n");

	if (text_only)
		printf("  %s", sym[0]);
	else
		printf("  %s %s", color[0], nocolor);
	printf(" - few events\n");

	for (i = 0; ; i++) {
		if (i % 20 == 0)
			print_banner();
		print_hist(map_fd[1]);
		sleep(2);
	}

	return 0;
}
