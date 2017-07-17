/*
 * rodata_test.h: functional test for mark_rodata_ro function
 *
 * (C) Copyright 2008 Intel Corporation
 * Author: Arjan van de Ven <arjan@linux.intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#ifndef _RODATA_TEST_H
#define _RODATA_TEST_H

#ifdef CONFIG_DEBUG_RODATA_TEST
extern const int rodata_test_data;
void rodata_test(void);
#else
static inline void rodata_test(void) {}
#endif

#endif /* _RODATA_TEST_H */
