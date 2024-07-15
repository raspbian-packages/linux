// SPDX-License-Identifier: GPL-2.0
/*
 * Test cases for memcpy(), memmove(), and memset().
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <kunit/test.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

struct some_bytes {
	union {
		u8 data[32];
		struct {
			u32 one;
			u16 two;
			u8  three;
			/* 1 byte hole */
			u32 four[4];
		};
	};
};

#define check(instance, v) do {	\
	BUILD_BUG_ON(sizeof(instance.data) != 32);	\
	for (size_t i = 0; i < sizeof(instance.data); i++) {	\
		KUNIT_ASSERT_EQ_MSG(test, instance.data[i], v, \
			"line %d: '%s' not initialized to 0x%02x @ %zu (saw 0x%02x)\n", \
			__LINE__, #instance, v, i, instance.data[i]);	\
	}	\
} while (0)

#define compare(name, one, two) do { \
	BUILD_BUG_ON(sizeof(one) != sizeof(two)); \
	for (size_t i = 0; i < sizeof(one); i++) {	\
		KUNIT_EXPECT_EQ_MSG(test, one.data[i], two.data[i], \
			"line %d: %s.data[%zu] (0x%02x) != %s.data[%zu] (0x%02x)\n", \
			__LINE__, #one, i, one.data[i], #two, i, two.data[i]); \
	}	\
	kunit_info(test, "ok: " TEST_OP "() " name "\n");	\
} while (0)

static void memcpy_test(struct kunit *test)
{
#define TEST_OP "memcpy"
	struct some_bytes control = {
		.data = { 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
			  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
			  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
			  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
			},
	};
	struct some_bytes zero = { };
	struct some_bytes middle = {
		.data = { 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
			  0x20, 0x20, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00,
			  0x00, 0x00, 0x00, 0x20, 0x20, 0x20, 0x20, 0x20,
			  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
			},
	};
	struct some_bytes three = {
		.data = { 0x00, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
			  0x20, 0x00, 0x00, 0x20, 0x20, 0x20, 0x20, 0x20,
			  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
			  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
			},
	};
	struct some_bytes dest = { };
	int count;
	u8 *ptr;

	/* Verify static initializers. */
	check(control, 0x20);
	check(zero, 0);
	compare("static initializers", dest, zero);

	/* Verify assignment. */
	dest = control;
	compare("direct assignment", dest, control);

	/* Verify complete overwrite. */
	memcpy(dest.data, zero.data, sizeof(dest.data));
	compare("complete overwrite", dest, zero);

	/* Verify middle overwrite. */
	dest = control;
	memcpy(dest.data + 12, zero.data, 7);
	compare("middle overwrite", dest, middle);

	/* Verify argument side-effects aren't repeated. */
	dest = control;
	ptr = dest.data;
	count = 1;
	memcpy(ptr++, zero.data, count++);
	ptr += 8;
	memcpy(ptr++, zero.data, count++);
	compare("argument side-effects", dest, three);
#undef TEST_OP
}

static void memmove_test(struct kunit *test)
{
#define TEST_OP "memmove"
	struct some_bytes control = {
		.data = { 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
			  0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
			  0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
			  0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
			},
	};
	struct some_bytes zero = { };
	struct some_bytes middle = {
		.data = { 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
			  0x99, 0x99, 0x99, 0x99, 0x00, 0x00, 0x00, 0x00,
			  0x00, 0x00, 0x00, 0x99, 0x99, 0x99, 0x99, 0x99,
			  0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
			},
	};
	struct some_bytes five = {
		.data = { 0x00, 0x00, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
			  0x99, 0x99, 0x00, 0x00, 0x00, 0x99, 0x99, 0x99,
			  0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
			  0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
			},
	};
	struct some_bytes overlap = {
		.data = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
			  0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
			  0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
			},
	};
	struct some_bytes overlap_expected = {
		.data = { 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x07,
			  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
			  0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
			  0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
			},
	};
	struct some_bytes dest = { };
	int count;
	u8 *ptr;

	/* Verify static initializers. */
	check(control, 0x99);
	check(zero, 0);
	compare("static initializers", zero, dest);

	/* Verify assignment. */
	dest = control;
	compare("direct assignment", dest, control);

	/* Verify complete overwrite. */
	memmove(dest.data, zero.data, sizeof(dest.data));
	compare("complete overwrite", dest, zero);

	/* Verify middle overwrite. */
	dest = control;
	memmove(dest.data + 12, zero.data, 7);
	compare("middle overwrite", dest, middle);

	/* Verify argument side-effects aren't repeated. */
	dest = control;
	ptr = dest.data;
	count = 2;
	memmove(ptr++, zero.data, count++);
	ptr += 9;
	memmove(ptr++, zero.data, count++);
	compare("argument side-effects", dest, five);

	/* Verify overlapping overwrite is correct. */
	ptr = &overlap.data[2];
	memmove(ptr, overlap.data, 5);
	compare("overlapping write", overlap, overlap_expected);
#undef TEST_OP
}

static void memset_test(struct kunit *test)
{
#define TEST_OP "memset"
	struct some_bytes control = {
		.data = { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
			  0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
			  0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
			  0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
			},
	};
	struct some_bytes complete = {
		.data = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			},
	};
	struct some_bytes middle = {
		.data = { 0x30, 0x30, 0x30, 0x30, 0x31, 0x31, 0x31, 0x31,
			  0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
			  0x31, 0x31, 0x31, 0x31, 0x30, 0x30, 0x30, 0x30,
			  0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
			},
	};
	struct some_bytes three = {
		.data = { 0x60, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
			  0x30, 0x61, 0x61, 0x30, 0x30, 0x30, 0x30, 0x30,
			  0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
			  0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
			},
	};
	struct some_bytes after = {
		.data = { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x72,
			  0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72,
			  0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72,
			  0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72,
			},
	};
	struct some_bytes startat = {
		.data = { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
			  0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79,
			  0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79,
			  0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79,
			},
	};
	struct some_bytes dest = { };
	int count, value;
	u8 *ptr;

	/* Verify static initializers. */
	check(control, 0x30);
	check(dest, 0);

	/* Verify assignment. */
	dest = control;
	compare("direct assignment", dest, control);

	/* Verify complete overwrite. */
	memset(dest.data, 0xff, sizeof(dest.data));
	compare("complete overwrite", dest, complete);

	/* Verify middle overwrite. */
	dest = control;
	memset(dest.data + 4, 0x31, 16);
	compare("middle overwrite", dest, middle);

	/* Verify argument side-effects aren't repeated. */
	dest = control;
	ptr = dest.data;
	value = 0x60;
	count = 1;
	memset(ptr++, value++, count++);
	ptr += 8;
	memset(ptr++, value++, count++);
	compare("argument side-effects", dest, three);

	/* Verify memset_after() */
	dest = control;
	memset_after(&dest, 0x72, three);
	compare("memset_after()", dest, after);

	/* Verify memset_startat() */
	dest = control;
	memset_startat(&dest, 0x79, four);
	compare("memset_startat()", dest, startat);
#undef TEST_OP
}

static void strtomem_test(struct kunit *test)
{
	static const char input[sizeof(unsigned long)] = "hi";
	static const char truncate[] = "this is too long";
	struct {
		unsigned long canary1;
		unsigned char output[sizeof(unsigned long)] __nonstring;
		unsigned long canary2;
	} wrap;

	memset(&wrap, 0xFF, sizeof(wrap));
	KUNIT_EXPECT_EQ_MSG(test, wrap.canary1, ULONG_MAX,
			    "bad initial canary value");
	KUNIT_EXPECT_EQ_MSG(test, wrap.canary2, ULONG_MAX,
			    "bad initial canary value");

	/* Check unpadded copy leaves surroundings untouched. */
	strtomem(wrap.output, input);
	KUNIT_EXPECT_EQ(test, wrap.canary1, ULONG_MAX);
	KUNIT_EXPECT_EQ(test, wrap.output[0], input[0]);
	KUNIT_EXPECT_EQ(test, wrap.output[1], input[1]);
	for (size_t i = 2; i < sizeof(wrap.output); i++)
		KUNIT_EXPECT_EQ(test, wrap.output[i], 0xFF);
	KUNIT_EXPECT_EQ(test, wrap.canary2, ULONG_MAX);

	/* Check truncated copy leaves surroundings untouched. */
	memset(&wrap, 0xFF, sizeof(wrap));
	strtomem(wrap.output, truncate);
	KUNIT_EXPECT_EQ(test, wrap.canary1, ULONG_MAX);
	for (size_t i = 0; i < sizeof(wrap.output); i++)
		KUNIT_EXPECT_EQ(test, wrap.output[i], truncate[i]);
	KUNIT_EXPECT_EQ(test, wrap.canary2, ULONG_MAX);

	/* Check padded copy leaves only string padded. */
	memset(&wrap, 0xFF, sizeof(wrap));
	strtomem_pad(wrap.output, input, 0xAA);
	KUNIT_EXPECT_EQ(test, wrap.canary1, ULONG_MAX);
	KUNIT_EXPECT_EQ(test, wrap.output[0], input[0]);
	KUNIT_EXPECT_EQ(test, wrap.output[1], input[1]);
	for (size_t i = 2; i < sizeof(wrap.output); i++)
		KUNIT_EXPECT_EQ(test, wrap.output[i], 0xAA);
	KUNIT_EXPECT_EQ(test, wrap.canary2, ULONG_MAX);

	/* Check truncated padded copy has no padding. */
	memset(&wrap, 0xFF, sizeof(wrap));
	strtomem(wrap.output, truncate);
	KUNIT_EXPECT_EQ(test, wrap.canary1, ULONG_MAX);
	for (size_t i = 0; i < sizeof(wrap.output); i++)
		KUNIT_EXPECT_EQ(test, wrap.output[i], truncate[i]);
	KUNIT_EXPECT_EQ(test, wrap.canary2, ULONG_MAX);
}

static struct kunit_case memcpy_test_cases[] = {
	KUNIT_CASE(memset_test),
	KUNIT_CASE(memcpy_test),
	KUNIT_CASE(memmove_test),
	KUNIT_CASE(strtomem_test),
	{}
};

static struct kunit_suite memcpy_test_suite = {
	.name = "memcpy",
	.test_cases = memcpy_test_cases,
};

kunit_test_suite(memcpy_test_suite);

MODULE_LICENSE("GPL");
