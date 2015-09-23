/*
 * Broadcom BM2835 V4L2 driver
 *
 * Copyright © 2013 Raspberry Pi (Trading) Ltd.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details.
 *
 * Authors: Vincent Sanders <vincent.sanders@collabora.co.uk>
 *          Dave Stevenson <dsteve@broadcom.com>
 *          Simon Mellor <simellor@broadcom.com>
 *          Luke Diamand <luked@broadcom.com>
 */

#ifndef MMAL_MSG_FORMAT_H
#define MMAL_MSG_FORMAT_H

#include "mmal-msg-common.h"

/* MMAL_ES_FORMAT_T */


struct mmal_audio_format {
	u32 channels;           /**< Number of audio channels */
	u32 sample_rate;        /**< Sample rate */

	u32 bits_per_sample;    /**< Bits per sample */
	u32 block_align;        /**< Size of a block of data */
};

struct mmal_video_format {
	u32 width;        /**< Width of frame in pixels */
	u32 height;       /**< Height of frame in rows of pixels */
	struct mmal_rect crop;         /**< Visible region of the frame */
	struct mmal_rational frame_rate;   /**< Frame rate */
	struct mmal_rational par;          /**< Pixel aspect ratio */

	/* FourCC specifying the color space of the video stream. See the
	 * \ref MmalColorSpace "pre-defined color spaces" for some examples.
	 */
	u32 color_space;
};

struct mmal_subpicture_format {
	u32 x_offset;
	u32 y_offset;
};

union mmal_es_specific_format {
	struct mmal_audio_format audio;
	struct mmal_video_format video;
	struct mmal_subpicture_format subpicture;
};

/** Definition of an elementary stream format (MMAL_ES_FORMAT_T) */
struct mmal_es_format {
	u32 type;      /* enum mmal_es_type */

	u32 encoding;  /* FourCC specifying encoding of the elementary stream.*/
	u32 encoding_variant; /* FourCC specifying the specific
			       * encoding variant of the elementary
			       * stream.
			       */

	union mmal_es_specific_format *es; /* TODO: pointers in
					    * message serialisation?!?
					    */
					    /* Type specific
					     * information for the
					     * elementary stream
					     */

	u32 bitrate;        /**< Bitrate in bits per second */
	u32 flags; /**< Flags describing properties of the elementary stream. */

	u32 extradata_size;       /**< Size of the codec specific data */
	u8  *extradata;           /**< Codec specific data */
};

#endif /* MMAL_MSG_FORMAT_H */
