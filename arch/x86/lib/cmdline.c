/*
 * This file is part of the Linux kernel, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * Misc librarized functions for cmdline poking.
 */
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <asm/setup.h>

static inline int myisspace(u8 c)
{
	return c <= ' ';	/* Close enough approximation */
}

/**
 * Find a boolean option (like quiet,noapic,nosmp....)
 *
 * @cmdline: the cmdline string
 * @option: option string to look for
 *
 * Returns the position of that @option (starts counting with 1)
 * or 0 on not found.  @option will only be found if it is found
 * as an entire word in @cmdline.  For instance, if @option="car"
 * then a cmdline which contains "cart" will not match.
 */
static int
__cmdline_find_option_bool(const char *cmdline, int max_cmdline_size,
			   const char *option)
{
	char c;
	int pos = 0, wstart = 0;
	const char *opptr = NULL;
	enum {
		st_wordstart = 0,	/* Start of word/after whitespace */
		st_wordcmp,	/* Comparing this word */
		st_wordskip,	/* Miscompare, skip */
	} state = st_wordstart;

	if (!cmdline)
		return -1;      /* No command line */

	/*
	 * This 'pos' check ensures we do not overrun
	 * a non-NULL-terminated 'cmdline'
	 */
	while (pos < max_cmdline_size) {
		c = *(char *)cmdline++;
		pos++;

		switch (state) {
		case st_wordstart:
			if (!c)
				return 0;
			else if (myisspace(c))
				break;

			state = st_wordcmp;
			opptr = option;
			wstart = pos;
			/* fall through */

		case st_wordcmp:
			if (!*opptr) {
				/*
				 * We matched all the way to the end of the
				 * option we were looking for.  If the
				 * command-line has a space _or_ ends, then
				 * we matched!
				 */
				if (!c || myisspace(c))
					return wstart;
				/*
				 * We hit the end of the option, but _not_
				 * the end of a word on the cmdline.  Not
				 * a match.
				 */
			} else if (!c) {
				/*
				 * Hit the NULL terminator on the end of
				 * cmdline.
				 */
				return 0;
			} else if (c == *opptr++) {
				/*
				 * We are currently matching, so continue
				 * to the next character on the cmdline.
				 */
				break;
			}
			state = st_wordskip;
			/* fall through */

		case st_wordskip:
			if (!c)
				return 0;
			else if (myisspace(c))
				state = st_wordstart;
			break;
		}
	}

	return 0;	/* Buffer overrun */
}

int cmdline_find_option_bool(const char *cmdline, const char *option)
{
	return __cmdline_find_option_bool(cmdline, COMMAND_LINE_SIZE, option);
}
