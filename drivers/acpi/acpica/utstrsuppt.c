/*******************************************************************************
 *
 * Module Name: utstrsuppt - Support functions for string-to-integer conversion
 *
 ******************************************************************************/

/*
 * Copyright (C) 2000 - 2018, Intel Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    substantially similar to the "NO WARRANTY" disclaimer below
 *    ("Disclaimer") and any redistribution must be conditioned upon
 *    including a substantially similar Disclaimer requirement for further
 *    binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 */

#include <acpi/acpi.h>
#include "accommon.h"

#define _COMPONENT          ACPI_UTILITIES
ACPI_MODULE_NAME("utstrsuppt")

/* Local prototypes */
static acpi_status
acpi_ut_insert_digit(u64 *accumulated_value, u32 base, int ascii_digit);

static acpi_status
acpi_ut_strtoul_multiply64(u64 multiplicand, u32 base, u64 *out_product);

static acpi_status acpi_ut_strtoul_add64(u64 addend1, u32 digit, u64 *out_sum);

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_convert_octal_string
 *
 * PARAMETERS:  string                  - Null terminated input string
 *              return_value_ptr        - Where the converted value is returned
 *
 * RETURN:      Status and 64-bit converted integer
 *
 * DESCRIPTION: Performs a base 8 conversion of the input string to an
 *              integer value, either 32 or 64 bits.
 *
 * NOTE:        Maximum 64-bit unsigned octal value is 01777777777777777777777
 *              Maximum 32-bit unsigned octal value is 037777777777
 *
 ******************************************************************************/

acpi_status acpi_ut_convert_octal_string(char *string, u64 *return_value_ptr)
{
	u64 accumulated_value = 0;
	acpi_status status = AE_OK;

	/* Convert each ASCII byte in the input string */

	while (*string) {

		/* Character must be ASCII 0-7, otherwise terminate with no error */

		if (!(ACPI_IS_OCTAL_DIGIT(*string))) {
			break;
		}

		/* Convert and insert this octal digit into the accumulator */

		status = acpi_ut_insert_digit(&accumulated_value, 8, *string);
		if (ACPI_FAILURE(status)) {
			status = AE_OCTAL_OVERFLOW;
			break;
		}

		string++;
	}

	/* Always return the value that has been accumulated */

	*return_value_ptr = accumulated_value;
	return (status);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_convert_decimal_string
 *
 * PARAMETERS:  string                  - Null terminated input string
 *              return_value_ptr        - Where the converted value is returned
 *
 * RETURN:      Status and 64-bit converted integer
 *
 * DESCRIPTION: Performs a base 10 conversion of the input string to an
 *              integer value, either 32 or 64 bits.
 *
 * NOTE:        Maximum 64-bit unsigned decimal value is 18446744073709551615
 *              Maximum 32-bit unsigned decimal value is 4294967295
 *
 ******************************************************************************/

acpi_status acpi_ut_convert_decimal_string(char *string, u64 *return_value_ptr)
{
	u64 accumulated_value = 0;
	acpi_status status = AE_OK;

	/* Convert each ASCII byte in the input string */

	while (*string) {

		/* Character must be ASCII 0-9, otherwise terminate with no error */

		if (!isdigit(*string)) {
			break;
		}

		/* Convert and insert this decimal digit into the accumulator */

		status = acpi_ut_insert_digit(&accumulated_value, 10, *string);
		if (ACPI_FAILURE(status)) {
			status = AE_DECIMAL_OVERFLOW;
			break;
		}

		string++;
	}

	/* Always return the value that has been accumulated */

	*return_value_ptr = accumulated_value;
	return (status);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_convert_hex_string
 *
 * PARAMETERS:  string                  - Null terminated input string
 *              return_value_ptr        - Where the converted value is returned
 *
 * RETURN:      Status and 64-bit converted integer
 *
 * DESCRIPTION: Performs a base 16 conversion of the input string to an
 *              integer value, either 32 or 64 bits.
 *
 * NOTE:        Maximum 64-bit unsigned hex value is 0xFFFFFFFFFFFFFFFF
 *              Maximum 32-bit unsigned hex value is 0xFFFFFFFF
 *
 ******************************************************************************/

acpi_status acpi_ut_convert_hex_string(char *string, u64 *return_value_ptr)
{
	u64 accumulated_value = 0;
	acpi_status status = AE_OK;

	/* Convert each ASCII byte in the input string */

	while (*string) {

		/* Must be ASCII A-F, a-f, or 0-9, otherwise terminate with no error */

		if (!isxdigit(*string)) {
			break;
		}

		/* Convert and insert this hex digit into the accumulator */

		status = acpi_ut_insert_digit(&accumulated_value, 16, *string);
		if (ACPI_FAILURE(status)) {
			status = AE_HEX_OVERFLOW;
			break;
		}

		string++;
	}

	/* Always return the value that has been accumulated */

	*return_value_ptr = accumulated_value;
	return (status);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_remove_leading_zeros
 *
 * PARAMETERS:  string                  - Pointer to input ASCII string
 *
 * RETURN:      Next character after any leading zeros. This character may be
 *              used by the caller to detect end-of-string.
 *
 * DESCRIPTION: Remove any leading zeros in the input string. Return the
 *              next character after the final ASCII zero to enable the caller
 *              to check for the end of the string (NULL terminator).
 *
 ******************************************************************************/

char acpi_ut_remove_leading_zeros(char **string)
{

	while (**string == ACPI_ASCII_ZERO) {
		*string += 1;
	}

	return (**string);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_remove_whitespace
 *
 * PARAMETERS:  string                  - Pointer to input ASCII string
 *
 * RETURN:      Next character after any whitespace. This character may be
 *              used by the caller to detect end-of-string.
 *
 * DESCRIPTION: Remove any leading whitespace in the input string. Return the
 *              next character after the final ASCII zero to enable the caller
 *              to check for the end of the string (NULL terminator).
 *
 ******************************************************************************/

char acpi_ut_remove_whitespace(char **string)
{

	while (isspace((u8)**string)) {
		*string += 1;
	}

	return (**string);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_detect_hex_prefix
 *
 * PARAMETERS:  string                  - Pointer to input ASCII string
 *
 * RETURN:      TRUE if a "0x" prefix was found at the start of the string
 *
 * DESCRIPTION: Detect and remove a hex "0x" prefix
 *
 ******************************************************************************/

u8 acpi_ut_detect_hex_prefix(char **string)
{

	if ((**string == ACPI_ASCII_ZERO) &&
	    (tolower((int)*(*string + 1)) == 'x')) {
		*string += 2;	/* Go past the leading 0x */
		return (TRUE);
	}

	return (FALSE);		/* Not a hex string */
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_detect_octal_prefix
 *
 * PARAMETERS:  string                  - Pointer to input ASCII string
 *
 * RETURN:      True if an octal "0" prefix was found at the start of the
 *              string
 *
 * DESCRIPTION: Detect and remove an octal prefix (zero)
 *
 ******************************************************************************/

u8 acpi_ut_detect_octal_prefix(char **string)
{

	if (**string == ACPI_ASCII_ZERO) {
		*string += 1;	/* Go past the leading 0 */
		return (TRUE);
	}

	return (FALSE);		/* Not an octal string */
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_insert_digit
 *
 * PARAMETERS:  accumulated_value       - Current value of the integer value
 *                                        accumulator. The new value is
 *                                        returned here.
 *              base                    - Radix, either 8/10/16
 *              ascii_digit             - ASCII single digit to be inserted
 *
 * RETURN:      Status and result of the convert/insert operation. The only
 *              possible returned exception code is numeric overflow of
 *              either the multiply or add conversion operations.
 *
 * DESCRIPTION: Generic conversion and insertion function for all bases:
 *
 *              1) Multiply the current accumulated/converted value by the
 *              base in order to make room for the new character.
 *
 *              2) Convert the new character to binary and add it to the
 *              current accumulated value.
 *
 *              Note: The only possible exception indicates an integer
 *              overflow (AE_NUMERIC_OVERFLOW)
 *
 ******************************************************************************/

static acpi_status
acpi_ut_insert_digit(u64 *accumulated_value, u32 base, int ascii_digit)
{
	acpi_status status;
	u64 product;

	/* Make room in the accumulated value for the incoming digit */

	status = acpi_ut_strtoul_multiply64(*accumulated_value, base, &product);
	if (ACPI_FAILURE(status)) {
		return (status);
	}

	/* Add in the new digit, and store the sum to the accumulated value */

	status =
	    acpi_ut_strtoul_add64(product,
				  acpi_ut_ascii_char_to_hex(ascii_digit),
				  accumulated_value);

	return (status);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_strtoul_multiply64
 *
 * PARAMETERS:  multiplicand            - Current accumulated converted integer
 *              base                    - Base/Radix
 *              out_product             - Where the product is returned
 *
 * RETURN:      Status and 64-bit product
 *
 * DESCRIPTION: Multiply two 64-bit values, with checking for 64-bit overflow as
 *              well as 32-bit overflow if necessary (if the current global
 *              integer width is 32).
 *
 ******************************************************************************/

static acpi_status
acpi_ut_strtoul_multiply64(u64 multiplicand, u32 base, u64 *out_product)
{
	u64 product;
	u64 quotient;

	/* Exit if either operand is zero */

	*out_product = 0;
	if (!multiplicand || !base) {
		return (AE_OK);
	}

	/*
	 * Check for 64-bit overflow before the actual multiplication.
	 *
	 * Notes: 64-bit division is often not supported on 32-bit platforms
	 * (it requires a library function), Therefore ACPICA has a local
	 * 64-bit divide function. Also, Multiplier is currently only used
	 * as the radix (8/10/16), to the 64/32 divide will always work.
	 */
	acpi_ut_short_divide(ACPI_UINT64_MAX, base, &quotient, NULL);
	if (multiplicand > quotient) {
		return (AE_NUMERIC_OVERFLOW);
	}

	product = multiplicand * base;

	/* Check for 32-bit overflow if necessary */

	if ((acpi_gbl_integer_bit_width == 32) && (product > ACPI_UINT32_MAX)) {
		return (AE_NUMERIC_OVERFLOW);
	}

	*out_product = product;
	return (AE_OK);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_strtoul_add64
 *
 * PARAMETERS:  addend1                 - Current accumulated converted integer
 *              digit                   - New hex value/char
 *              out_sum                 - Where sum is returned (Accumulator)
 *
 * RETURN:      Status and 64-bit sum
 *
 * DESCRIPTION: Add two 64-bit values, with checking for 64-bit overflow as
 *              well as 32-bit overflow if necessary (if the current global
 *              integer width is 32).
 *
 ******************************************************************************/

static acpi_status acpi_ut_strtoul_add64(u64 addend1, u32 digit, u64 *out_sum)
{
	u64 sum;

	/* Check for 64-bit overflow before the actual addition */

	if ((addend1 > 0) && (digit > (ACPI_UINT64_MAX - addend1))) {
		return (AE_NUMERIC_OVERFLOW);
	}

	sum = addend1 + digit;

	/* Check for 32-bit overflow if necessary */

	if ((acpi_gbl_integer_bit_width == 32) && (sum > ACPI_UINT32_MAX)) {
		return (AE_NUMERIC_OVERFLOW);
	}

	*out_sum = sum;
	return (AE_OK);
}
