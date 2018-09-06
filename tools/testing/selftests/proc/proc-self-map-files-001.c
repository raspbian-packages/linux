/*
 * Copyright © 2018 Alexey Dobriyan <adobriyan@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/* Test readlink /proc/self/map_files/... */
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>

static void pass(const char *fmt, unsigned long a, unsigned long b)
{
	char name[64];
	char buf[64];

	snprintf(name, sizeof(name), fmt, a, b);
	if (readlink(name, buf, sizeof(buf)) == -1)
		exit(1);
}

static void fail(const char *fmt, unsigned long a, unsigned long b)
{
	char name[64];
	char buf[64];

	snprintf(name, sizeof(name), fmt, a, b);
	if (readlink(name, buf, sizeof(buf)) == -1 && errno == ENOENT)
		return;
	exit(1);
}

int main(void)
{
	const unsigned int PAGE_SIZE = sysconf(_SC_PAGESIZE);
	void *p;
	int fd;
	unsigned long a, b;

	fd = open("/dev/zero", O_RDONLY);
	if (fd == -1)
		return 1;

	p = mmap(NULL, PAGE_SIZE, PROT_NONE, MAP_PRIVATE|MAP_FILE, fd, 0);
	if (p == MAP_FAILED)
		return 1;

	a = (unsigned long)p;
	b = (unsigned long)p + PAGE_SIZE;

	pass("/proc/self/map_files/%lx-%lx", a, b);
	fail("/proc/self/map_files/ %lx-%lx", a, b);
	fail("/proc/self/map_files/%lx -%lx", a, b);
	fail("/proc/self/map_files/%lx- %lx", a, b);
	fail("/proc/self/map_files/%lx-%lx ", a, b);
	fail("/proc/self/map_files/0%lx-%lx", a, b);
	fail("/proc/self/map_files/%lx-0%lx", a, b);
	if (sizeof(long) == 4) {
		fail("/proc/self/map_files/100000000%lx-%lx", a, b);
		fail("/proc/self/map_files/%lx-100000000%lx", a, b);
	} else if (sizeof(long) == 8) {
		fail("/proc/self/map_files/10000000000000000%lx-%lx", a, b);
		fail("/proc/self/map_files/%lx-10000000000000000%lx", a, b);
	} else
		return 1;

	return 0;
}
