/*
 *   Copyright (C) International Business Machines Corp., 2000-2002
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <linux/fs.h>
#include "jfs_unicode.h"

/*
 * Latin upper case
 */
signed char UniUpperTable[512] = {
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 000-00f */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 010-01f */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 020-02f */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 030-03f */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 040-04f */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 050-05f */
   0,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32, /* 060-06f */
 -32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,  0,  0,  0,  0,  0, /* 070-07f */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 080-08f */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 090-09f */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 0a0-0af */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 0b0-0bf */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 0c0-0cf */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 0d0-0df */
 -32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32, /* 0e0-0ef */
 -32,-32,-32,-32,-32,-32,-32,  0,-32,-32,-32,-32,-32,-32,-32,121, /* 0f0-0ff */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 100-10f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 110-11f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 120-12f */
   0,  0,  0, -1,  0, -1,  0, -1,  0,  0, -1,  0, -1,  0, -1,  0, /* 130-13f */
  -1,  0, -1,  0, -1,  0, -1,  0, -1,  0,  0, -1,  0, -1,  0, -1, /* 140-14f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 150-15f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 160-16f */
   0, -1,  0, -1,  0, -1,  0, -1,  0,  0, -1,  0, -1,  0, -1,  0, /* 170-17f */
   0,  0,  0, -1,  0, -1,  0,  0, -1,  0,  0,  0, -1,  0,  0,  0, /* 180-18f */
   0,  0, -1,  0,  0,  0,  0,  0,  0, -1,  0,  0,  0,  0,  0,  0, /* 190-19f */
   0, -1,  0, -1,  0, -1,  0,  0, -1,  0,  0,  0,  0, -1,  0,  0, /* 1a0-1af */
  -1,  0,  0,  0, -1,  0, -1,  0,  0, -1,  0,  0,  0, -1,  0,  0, /* 1b0-1bf */
   0,  0,  0,  0,  0, -1, -2,  0, -1, -2,  0, -1, -2,  0, -1,  0, /* 1c0-1cf */
  -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,-79,  0, -1, /* 1d0-1df */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1e0-1ef */
   0,  0, -1, -2,  0, -1,  0,  0,  0, -1,  0, -1,  0, -1,  0, -1, /* 1f0-1ff */
};

/* Upper case range - Greek */
static signed char UniCaseRangeU03a0[47] = {
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,-38,-37,-37,-37, /* 3a0-3af */
   0,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32, /* 3b0-3bf */
 -32,-32,-31,-32,-32,-32,-32,-32,-32,-32,-32,-32,-64,-63,-63,
};

/* Upper case range - Cyrillic */
static signed char UniCaseRangeU0430[48] = {
 -32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32, /* 430-43f */
 -32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32, /* 440-44f */
   0,-80,-80,-80,-80,-80,-80,-80,-80,-80,-80,-80,-80,  0,-80,-80, /* 450-45f */
};

/* Upper case range - Extended cyrillic */
static signed char UniCaseRangeU0490[61] = {
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 490-49f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 4a0-4af */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 4b0-4bf */
   0,  0, -1,  0, -1,  0,  0,  0, -1,  0,  0,  0, -1,
};

/* Upper case range - Extended latin and greek */
static signed char UniCaseRangeU1e00[509] = {
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1e00-1e0f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1e10-1e1f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1e20-1e2f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1e30-1e3f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1e40-1e4f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1e50-1e5f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1e60-1e6f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1e70-1e7f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1e80-1e8f */
   0, -1,  0, -1,  0, -1,  0,  0,  0,  0,  0,-59,  0, -1,  0, -1, /* 1e90-1e9f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1ea0-1eaf */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1eb0-1ebf */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1ec0-1ecf */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1ed0-1edf */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1ee0-1eef */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0,  0,  0,  0,  0,  0, /* 1ef0-1eff */
   8,  8,  8,  8,  8,  8,  8,  8,  0,  0,  0,  0,  0,  0,  0,  0, /* 1f00-1f0f */
   8,  8,  8,  8,  8,  8,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 1f10-1f1f */
   8,  8,  8,  8,  8,  8,  8,  8,  0,  0,  0,  0,  0,  0,  0,  0, /* 1f20-1f2f */
   8,  8,  8,  8,  8,  8,  8,  8,  0,  0,  0,  0,  0,  0,  0,  0, /* 1f30-1f3f */
   8,  8,  8,  8,  8,  8,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 1f40-1f4f */
   0,  8,  0,  8,  0,  8,  0,  8,  0,  0,  0,  0,  0,  0,  0,  0, /* 1f50-1f5f */
   8,  8,  8,  8,  8,  8,  8,  8,  0,  0,  0,  0,  0,  0,  0,  0, /* 1f60-1f6f */
  74, 74, 86, 86, 86, 86,100,100,  0,  0,112,112,126,126,  0,  0, /* 1f70-1f7f */
   8,  8,  8,  8,  8,  8,  8,  8,  0,  0,  0,  0,  0,  0,  0,  0, /* 1f80-1f8f */
   8,  8,  8,  8,  8,  8,  8,  8,  0,  0,  0,  0,  0,  0,  0,  0, /* 1f90-1f9f */
   8,  8,  8,  8,  8,  8,  8,  8,  0,  0,  0,  0,  0,  0,  0,  0, /* 1fa0-1faf */
   8,  8,  0,  9,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 1fb0-1fbf */
   0,  0,  0,  9,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 1fc0-1fcf */
   8,  8,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 1fd0-1fdf */
   8,  8,  0,  0,  0,  7,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 1fe0-1fef */
   0,  0,  0,  9,  0,  0,  0,  0,  0,  0,  0,  0,  0,
};

/* Upper case range - Wide latin */
static signed char UniCaseRangeUff40[27] = {
   0,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32, /* ff40-ff4f */
 -32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,
};

/*
 * Upper Case Range
 */
UNICASERANGE UniUpperRange[] = {
    { 0x03a0,  0x03ce,  UniCaseRangeU03a0 },
    { 0x0430,  0x045f,  UniCaseRangeU0430 },
    { 0x0490,  0x04cc,  UniCaseRangeU0490 },
    { 0x1e00,  0x1ffc,  UniCaseRangeU1e00 },
    { 0xff40,  0xff5a,  UniCaseRangeUff40 },
    { 0 }
};
