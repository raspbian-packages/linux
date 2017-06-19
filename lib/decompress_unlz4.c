/*
 * Wrapper for decompressing LZ4-compressed kernel, initramfs, and initrd
 *
 * Copyright (C) 2013, LG Electronics, Kyungsik Lee <kyungsik.lee@lge.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifdef STATIC
#define PREBOOT
#include "lz4/lz4_decompress.c"
#else
#include <linux/decompress/unlz4.h>
#endif
#include <linux/types.h>
#include <linux/lz4.h>
#include <linux/decompress/mm.h>
#include <linux/compiler.h>

#include <asm/unaligned.h>

/*
 * Note: Uncompressed chunk size is used in the compressor side
 * (userspace side for compression).
 * It is hardcoded because there is not proper way to extract it
 * from the binary stream which is generated by the preliminary
 * version of LZ4 tool so far.
 */
#define LZ4_DEFAULT_UNCOMPRESSED_CHUNK_SIZE (8 << 20)
#define ARCHIVE_MAGICNUMBER 0x184C2102

STATIC inline int INIT unlz4(u8 *input, long in_len,
				long (*fill)(void *, unsigned long),
				long (*flush)(void *, unsigned long),
				u8 *output, long *posp,
				void (*error) (char *x))
{
	int ret = -1;
	size_t chunksize = 0;
	size_t uncomp_chunksize = LZ4_DEFAULT_UNCOMPRESSED_CHUNK_SIZE;
	u8 *inp;
	u8 *inp_start;
	u8 *outp;
	long size = in_len;
#ifdef PREBOOT
	size_t out_len = get_unaligned_le32(input + in_len);
#endif
	size_t dest_len;


	if (output) {
		outp = output;
	} else if (!flush) {
		error("NULL output pointer and no flush function provided");
		goto exit_0;
	} else {
		outp = large_malloc(uncomp_chunksize);
		if (!outp) {
			error("Could not allocate output buffer");
			goto exit_0;
		}
	}

	if (input && fill) {
		error("Both input pointer and fill function provided,");
		goto exit_1;
	} else if (input) {
		inp = input;
	} else if (!fill) {
		error("NULL input pointer and missing fill function");
		goto exit_1;
	} else {
		inp = large_malloc(LZ4_compressBound(uncomp_chunksize));
		if (!inp) {
			error("Could not allocate input buffer");
			goto exit_1;
		}
	}
	inp_start = inp;

	if (posp)
		*posp = 0;

	if (fill) {
		size = fill(inp, 4);
		if (size < 4) {
			error("data corrupted");
			goto exit_2;
		}
	}

	chunksize = get_unaligned_le32(inp);
	if (chunksize == ARCHIVE_MAGICNUMBER) {
		if (!fill) {
			inp += 4;
			size -= 4;
		}
	} else {
		error("invalid header");
		goto exit_2;
	}

	if (posp)
		*posp += 4;

	for (;;) {

		if (fill) {
			size = fill(inp, 4);
			if (size == 0)
				break;
			if (size < 4) {
				error("data corrupted");
				goto exit_2;
			}
		}

		chunksize = get_unaligned_le32(inp);
		if (chunksize == ARCHIVE_MAGICNUMBER) {
			if (!fill) {
				inp += 4;
				size -= 4;
			}
			if (posp)
				*posp += 4;
			continue;
		}


		if (posp)
			*posp += 4;

		if (!fill) {
			inp += 4;
			size -= 4;
		} else {
			if (chunksize > LZ4_compressBound(uncomp_chunksize)) {
				error("chunk length is longer than allocated");
				goto exit_2;
			}
			size = fill(inp, chunksize);
			if (size < chunksize) {
				error("data corrupted");
				goto exit_2;
			}
		}
#ifdef PREBOOT
		if (out_len >= uncomp_chunksize) {
			dest_len = uncomp_chunksize;
			out_len -= dest_len;
		} else
			dest_len = out_len;

		ret = LZ4_decompress_fast(inp, outp, dest_len);
		chunksize = ret;
#else
		dest_len = uncomp_chunksize;

		ret = LZ4_decompress_safe(inp, outp, chunksize, dest_len);
		dest_len = ret;
#endif
		if (ret < 0) {
			error("Decoding failed");
			goto exit_2;
		}

		ret = -1;
		if (flush && flush(outp, dest_len) != dest_len)
			goto exit_2;
		if (output)
			outp += dest_len;
		if (posp)
			*posp += chunksize;

		if (!fill) {
			size -= chunksize;

			if (size == 0)
				break;
			else if (size < 0) {
				error("data corrupted");
				goto exit_2;
			}
			inp += chunksize;
		}
	}

	ret = 0;
exit_2:
	if (!input)
		large_free(inp_start);
exit_1:
	if (!output)
		large_free(outp);
exit_0:
	return ret;
}

#ifdef PREBOOT
STATIC int INIT __decompress(unsigned char *buf, long in_len,
			      long (*fill)(void*, unsigned long),
			      long (*flush)(void*, unsigned long),
			      unsigned char *output, long out_len,
			      long *posp,
			      void (*error)(char *x)
	)
{
	return unlz4(buf, in_len - 4, fill, flush, output, posp, error);
}
#endif
