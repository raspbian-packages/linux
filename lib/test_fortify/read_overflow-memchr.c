// SPDX-License-Identifier: GPL-2.0-only
#define TEST	\
	memchr(small, 0x7A, sizeof(small) + 1)

#include "test_fortify.h"
