
/*
 * Copyright 2015 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */
#ifndef PP_DEBUG_H
#define PP_DEBUG_H

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#define PP_ASSERT_WITH_CODE(cond, msg, code)	\
	do {					\
		if (!(cond)) {			\
			printk("%s\n", msg);	\
			code;			\
		}				\
	} while (0)


#define PP_DBG_LOG(fmt, ...) \
	do { \
		if(0)printk(KERN_INFO "[ pp_dbg ] " fmt, ##__VA_ARGS__); \
	} while (0)


#define GET_FLEXIBLE_ARRAY_MEMBER_ADDR(type, member, ptr, n)	\
	(type *)((char *)&(ptr)->member + (sizeof(type) * (n)))

#endif /* PP_DEBUG_H */

