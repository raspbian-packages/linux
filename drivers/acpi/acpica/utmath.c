/*******************************************************************************
 *
 * Module Name: utmath - Integer math support routines
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
ACPI_MODULE_NAME("utmath")

/* Structures used only for 64-bit divide */
typedef struct uint64_struct {
	u32 lo;
	u32 hi;

} uint64_struct;

typedef union uint64_overlay {
	u64 full;
	struct uint64_struct part;

} uint64_overlay;

/*
 * Optional support for 64-bit double-precision integer multiply and shift.
 * This code is configurable and is implemented in order to support 32-bit
 * kernel environments where a 64-bit double-precision math library is not
 * available.
 */
#ifndef ACPI_USE_NATIVE_MATH64

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_short_multiply
 *
 * PARAMETERS:  multiplicand        - 64-bit multiplicand
 *              multiplier          - 32-bit multiplier
 *              out_product         - Pointer to where the product is returned
 *
 * DESCRIPTION: Perform a short multiply.
 *
 ******************************************************************************/

acpi_status
acpi_ut_short_multiply(u64 multiplicand, u32 multiplier, u64 *out_product)
{
	union uint64_overlay multiplicand_ovl;
	union uint64_overlay product;
	u32 carry32;

	ACPI_FUNCTION_TRACE(ut_short_multiply);

	multiplicand_ovl.full = multiplicand;

	/*
	 * The Product is 64 bits, the carry is always 32 bits,
	 * and is generated by the second multiply.
	 */
	ACPI_MUL_64_BY_32(0, multiplicand_ovl.part.hi, multiplier,
			  product.part.hi, carry32);

	ACPI_MUL_64_BY_32(0, multiplicand_ovl.part.lo, multiplier,
			  product.part.lo, carry32);

	product.part.hi += carry32;

	/* Return only what was requested */

	if (out_product) {
		*out_product = product.full;
	}

	return_ACPI_STATUS(AE_OK);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_short_shift_left
 *
 * PARAMETERS:  operand             - 64-bit shift operand
 *              count               - 32-bit shift count
 *              out_result          - Pointer to where the result is returned
 *
 * DESCRIPTION: Perform a short left shift.
 *
 ******************************************************************************/

acpi_status acpi_ut_short_shift_left(u64 operand, u32 count, u64 *out_result)
{
	union uint64_overlay operand_ovl;

	ACPI_FUNCTION_TRACE(ut_short_shift_left);

	operand_ovl.full = operand;

	if ((count & 63) >= 32) {
		operand_ovl.part.hi = operand_ovl.part.lo;
		operand_ovl.part.lo = 0;
		count = (count & 63) - 32;
	}
	ACPI_SHIFT_LEFT_64_BY_32(operand_ovl.part.hi,
				 operand_ovl.part.lo, count);

	/* Return only what was requested */

	if (out_result) {
		*out_result = operand_ovl.full;
	}

	return_ACPI_STATUS(AE_OK);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_short_shift_right
 *
 * PARAMETERS:  operand             - 64-bit shift operand
 *              count               - 32-bit shift count
 *              out_result          - Pointer to where the result is returned
 *
 * DESCRIPTION: Perform a short right shift.
 *
 ******************************************************************************/

acpi_status acpi_ut_short_shift_right(u64 operand, u32 count, u64 *out_result)
{
	union uint64_overlay operand_ovl;

	ACPI_FUNCTION_TRACE(ut_short_shift_right);

	operand_ovl.full = operand;

	if ((count & 63) >= 32) {
		operand_ovl.part.lo = operand_ovl.part.hi;
		operand_ovl.part.hi = 0;
		count = (count & 63) - 32;
	}
	ACPI_SHIFT_RIGHT_64_BY_32(operand_ovl.part.hi,
				  operand_ovl.part.lo, count);

	/* Return only what was requested */

	if (out_result) {
		*out_result = operand_ovl.full;
	}

	return_ACPI_STATUS(AE_OK);
}
#else

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_short_multiply
 *
 * PARAMETERS:  See function headers above
 *
 * DESCRIPTION: Native version of the ut_short_multiply function.
 *
 ******************************************************************************/

acpi_status
acpi_ut_short_multiply(u64 multiplicand, u32 multiplier, u64 *out_product)
{

	ACPI_FUNCTION_TRACE(ut_short_multiply);

	/* Return only what was requested */

	if (out_product) {
		*out_product = multiplicand * multiplier;
	}

	return_ACPI_STATUS(AE_OK);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_short_shift_left
 *
 * PARAMETERS:  See function headers above
 *
 * DESCRIPTION: Native version of the ut_short_shift_left function.
 *
 ******************************************************************************/

acpi_status acpi_ut_short_shift_left(u64 operand, u32 count, u64 *out_result)
{

	ACPI_FUNCTION_TRACE(ut_short_shift_left);

	/* Return only what was requested */

	if (out_result) {
		*out_result = operand << count;
	}

	return_ACPI_STATUS(AE_OK);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_short_shift_right
 *
 * PARAMETERS:  See function headers above
 *
 * DESCRIPTION: Native version of the ut_short_shift_right function.
 *
 ******************************************************************************/

acpi_status acpi_ut_short_shift_right(u64 operand, u32 count, u64 *out_result)
{

	ACPI_FUNCTION_TRACE(ut_short_shift_right);

	/* Return only what was requested */

	if (out_result) {
		*out_result = operand >> count;
	}

	return_ACPI_STATUS(AE_OK);
}
#endif

/*
 * Optional support for 64-bit double-precision integer divide. This code
 * is configurable and is implemented in order to support 32-bit kernel
 * environments where a 64-bit double-precision math library is not available.
 *
 * Support for a more normal 64-bit divide/modulo (with check for a divide-
 * by-zero) appears after this optional section of code.
 */
#ifndef ACPI_USE_NATIVE_DIVIDE

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_short_divide
 *
 * PARAMETERS:  dividend            - 64-bit dividend
 *              divisor             - 32-bit divisor
 *              out_quotient        - Pointer to where the quotient is returned
 *              out_remainder       - Pointer to where the remainder is returned
 *
 * RETURN:      Status (Checks for divide-by-zero)
 *
 * DESCRIPTION: Perform a short (maximum 64 bits divided by 32 bits)
 *              divide and modulo. The result is a 64-bit quotient and a
 *              32-bit remainder.
 *
 ******************************************************************************/

acpi_status
acpi_ut_short_divide(u64 dividend,
		     u32 divisor, u64 *out_quotient, u32 *out_remainder)
{
	union uint64_overlay dividend_ovl;
	union uint64_overlay quotient;
	u32 remainder32;

	ACPI_FUNCTION_TRACE(ut_short_divide);

	/* Always check for a zero divisor */

	if (divisor == 0) {
		ACPI_ERROR((AE_INFO, "Divide by zero"));
		return_ACPI_STATUS(AE_AML_DIVIDE_BY_ZERO);
	}

	dividend_ovl.full = dividend;

	/*
	 * The quotient is 64 bits, the remainder is always 32 bits,
	 * and is generated by the second divide.
	 */
	ACPI_DIV_64_BY_32(0, dividend_ovl.part.hi, divisor,
			  quotient.part.hi, remainder32);

	ACPI_DIV_64_BY_32(remainder32, dividend_ovl.part.lo, divisor,
			  quotient.part.lo, remainder32);

	/* Return only what was requested */

	if (out_quotient) {
		*out_quotient = quotient.full;
	}
	if (out_remainder) {
		*out_remainder = remainder32;
	}

	return_ACPI_STATUS(AE_OK);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_divide
 *
 * PARAMETERS:  in_dividend         - Dividend
 *              in_divisor          - Divisor
 *              out_quotient        - Pointer to where the quotient is returned
 *              out_remainder       - Pointer to where the remainder is returned
 *
 * RETURN:      Status (Checks for divide-by-zero)
 *
 * DESCRIPTION: Perform a divide and modulo.
 *
 ******************************************************************************/

acpi_status
acpi_ut_divide(u64 in_dividend,
	       u64 in_divisor, u64 *out_quotient, u64 *out_remainder)
{
	union uint64_overlay dividend;
	union uint64_overlay divisor;
	union uint64_overlay quotient;
	union uint64_overlay remainder;
	union uint64_overlay normalized_dividend;
	union uint64_overlay normalized_divisor;
	u32 partial1;
	union uint64_overlay partial2;
	union uint64_overlay partial3;

	ACPI_FUNCTION_TRACE(ut_divide);

	/* Always check for a zero divisor */

	if (in_divisor == 0) {
		ACPI_ERROR((AE_INFO, "Divide by zero"));
		return_ACPI_STATUS(AE_AML_DIVIDE_BY_ZERO);
	}

	divisor.full = in_divisor;
	dividend.full = in_dividend;
	if (divisor.part.hi == 0) {
		/*
		 * 1) Simplest case is where the divisor is 32 bits, we can
		 * just do two divides
		 */
		remainder.part.hi = 0;

		/*
		 * The quotient is 64 bits, the remainder is always 32 bits,
		 * and is generated by the second divide.
		 */
		ACPI_DIV_64_BY_32(0, dividend.part.hi, divisor.part.lo,
				  quotient.part.hi, partial1);

		ACPI_DIV_64_BY_32(partial1, dividend.part.lo, divisor.part.lo,
				  quotient.part.lo, remainder.part.lo);
	}

	else {
		/*
		 * 2) The general case where the divisor is a full 64 bits
		 * is more difficult
		 */
		quotient.part.hi = 0;
		normalized_dividend = dividend;
		normalized_divisor = divisor;

		/* Normalize the operands (shift until the divisor is < 32 bits) */

		do {
			ACPI_SHIFT_RIGHT_64(normalized_divisor.part.hi,
					    normalized_divisor.part.lo);
			ACPI_SHIFT_RIGHT_64(normalized_dividend.part.hi,
					    normalized_dividend.part.lo);

		} while (normalized_divisor.part.hi != 0);

		/* Partial divide */

		ACPI_DIV_64_BY_32(normalized_dividend.part.hi,
				  normalized_dividend.part.lo,
				  normalized_divisor.part.lo, quotient.part.lo,
				  partial1);

		/*
		 * The quotient is always 32 bits, and simply requires
		 * adjustment. The 64-bit remainder must be generated.
		 */
		partial1 = quotient.part.lo * divisor.part.hi;
		partial2.full = (u64) quotient.part.lo * divisor.part.lo;
		partial3.full = (u64) partial2.part.hi + partial1;

		remainder.part.hi = partial3.part.lo;
		remainder.part.lo = partial2.part.lo;

		if (partial3.part.hi == 0) {
			if (partial3.part.lo >= dividend.part.hi) {
				if (partial3.part.lo == dividend.part.hi) {
					if (partial2.part.lo > dividend.part.lo) {
						quotient.part.lo--;
						remainder.full -= divisor.full;
					}
				} else {
					quotient.part.lo--;
					remainder.full -= divisor.full;
				}
			}

			remainder.full = remainder.full - dividend.full;
			remainder.part.hi = (u32)-((s32)remainder.part.hi);
			remainder.part.lo = (u32)-((s32)remainder.part.lo);

			if (remainder.part.lo) {
				remainder.part.hi--;
			}
		}
	}

	/* Return only what was requested */

	if (out_quotient) {
		*out_quotient = quotient.full;
	}
	if (out_remainder) {
		*out_remainder = remainder.full;
	}

	return_ACPI_STATUS(AE_OK);
}

#else

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_short_divide, acpi_ut_divide
 *
 * PARAMETERS:  See function headers above
 *
 * DESCRIPTION: Native versions of the ut_divide functions. Use these if either
 *              1) The target is a 64-bit platform and therefore 64-bit
 *                 integer math is supported directly by the machine.
 *              2) The target is a 32-bit or 16-bit platform, and the
 *                 double-precision integer math library is available to
 *                 perform the divide.
 *
 ******************************************************************************/

acpi_status
acpi_ut_short_divide(u64 in_dividend,
		     u32 divisor, u64 *out_quotient, u32 *out_remainder)
{

	ACPI_FUNCTION_TRACE(ut_short_divide);

	/* Always check for a zero divisor */

	if (divisor == 0) {
		ACPI_ERROR((AE_INFO, "Divide by zero"));
		return_ACPI_STATUS(AE_AML_DIVIDE_BY_ZERO);
	}

	/* Return only what was requested */

	if (out_quotient) {
		*out_quotient = in_dividend / divisor;
	}
	if (out_remainder) {
		*out_remainder = (u32) (in_dividend % divisor);
	}

	return_ACPI_STATUS(AE_OK);
}

acpi_status
acpi_ut_divide(u64 in_dividend,
	       u64 in_divisor, u64 *out_quotient, u64 *out_remainder)
{
	ACPI_FUNCTION_TRACE(ut_divide);

	/* Always check for a zero divisor */

	if (in_divisor == 0) {
		ACPI_ERROR((AE_INFO, "Divide by zero"));
		return_ACPI_STATUS(AE_AML_DIVIDE_BY_ZERO);
	}

	/* Return only what was requested */

	if (out_quotient) {
		*out_quotient = in_dividend / in_divisor;
	}
	if (out_remainder) {
		*out_remainder = in_dividend % in_divisor;
	}

	return_ACPI_STATUS(AE_OK);
}

#endif
