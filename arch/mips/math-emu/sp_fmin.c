/*
 * IEEE754 floating point arithmetic
 * single precision: MIN{,A}.f
 * MIN : Scalar Floating-Point Minimum
 * MINA: Scalar Floating-Point argument with Minimum Absolute Value
 *
 * MIN.S : FPR[fd] = minNum(FPR[fs],FPR[ft])
 * MINA.S: FPR[fd] = maxNumMag(FPR[fs],FPR[ft])
 *
 * MIPS floating point support
 * Copyright (C) 2015 Imagination Technologies, Ltd.
 * Author: Markos Chandras <markos.chandras@imgtec.com>
 *
 *  This program is free software; you can distribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation; version 2 of the License.
 */

#include "ieee754sp.h"

union ieee754sp ieee754sp_fmin(union ieee754sp x, union ieee754sp y)
{
	COMPXSP;
	COMPYSP;

	EXPLODEXSP;
	EXPLODEYSP;

	FLUSHXSP;
	FLUSHYSP;

	ieee754_clearcx();

	switch (CLPAIR(xc, yc)) {
	case CLPAIR(IEEE754_CLASS_QNAN, IEEE754_CLASS_SNAN):
	case CLPAIR(IEEE754_CLASS_ZERO, IEEE754_CLASS_SNAN):
	case CLPAIR(IEEE754_CLASS_NORM, IEEE754_CLASS_SNAN):
	case CLPAIR(IEEE754_CLASS_DNORM, IEEE754_CLASS_SNAN):
	case CLPAIR(IEEE754_CLASS_INF, IEEE754_CLASS_SNAN):
		return ieee754sp_nanxcpt(y);

	case CLPAIR(IEEE754_CLASS_SNAN, IEEE754_CLASS_SNAN):
	case CLPAIR(IEEE754_CLASS_SNAN, IEEE754_CLASS_QNAN):
	case CLPAIR(IEEE754_CLASS_SNAN, IEEE754_CLASS_ZERO):
	case CLPAIR(IEEE754_CLASS_SNAN, IEEE754_CLASS_NORM):
	case CLPAIR(IEEE754_CLASS_SNAN, IEEE754_CLASS_DNORM):
	case CLPAIR(IEEE754_CLASS_SNAN, IEEE754_CLASS_INF):
		return ieee754sp_nanxcpt(x);

	/* numbers are preferred to NaNs */
	case CLPAIR(IEEE754_CLASS_ZERO, IEEE754_CLASS_QNAN):
	case CLPAIR(IEEE754_CLASS_NORM, IEEE754_CLASS_QNAN):
	case CLPAIR(IEEE754_CLASS_DNORM, IEEE754_CLASS_QNAN):
	case CLPAIR(IEEE754_CLASS_INF, IEEE754_CLASS_QNAN):
		return x;

	case CLPAIR(IEEE754_CLASS_QNAN, IEEE754_CLASS_QNAN):
	case CLPAIR(IEEE754_CLASS_QNAN, IEEE754_CLASS_ZERO):
	case CLPAIR(IEEE754_CLASS_QNAN, IEEE754_CLASS_NORM):
	case CLPAIR(IEEE754_CLASS_QNAN, IEEE754_CLASS_DNORM):
	case CLPAIR(IEEE754_CLASS_QNAN, IEEE754_CLASS_INF):
		return y;

	/*
	 * Infinity and zero handling
	 */
	case CLPAIR(IEEE754_CLASS_INF, IEEE754_CLASS_ZERO):
	case CLPAIR(IEEE754_CLASS_INF, IEEE754_CLASS_NORM):
	case CLPAIR(IEEE754_CLASS_INF, IEEE754_CLASS_DNORM):
	case CLPAIR(IEEE754_CLASS_NORM, IEEE754_CLASS_ZERO):
	case CLPAIR(IEEE754_CLASS_DNORM, IEEE754_CLASS_ZERO):
		return xs ? x : y;

	case CLPAIR(IEEE754_CLASS_INF, IEEE754_CLASS_INF):
	case CLPAIR(IEEE754_CLASS_NORM, IEEE754_CLASS_INF):
	case CLPAIR(IEEE754_CLASS_DNORM, IEEE754_CLASS_INF):
	case CLPAIR(IEEE754_CLASS_ZERO, IEEE754_CLASS_INF):
	case CLPAIR(IEEE754_CLASS_ZERO, IEEE754_CLASS_NORM):
	case CLPAIR(IEEE754_CLASS_ZERO, IEEE754_CLASS_DNORM):
		return ys ? y : x;

	case CLPAIR(IEEE754_CLASS_ZERO, IEEE754_CLASS_ZERO):
		if (xs == ys)
			return x;
		return ieee754sp_zero(1);

	case CLPAIR(IEEE754_CLASS_DNORM, IEEE754_CLASS_DNORM):
		SPDNORMX;

	case CLPAIR(IEEE754_CLASS_NORM, IEEE754_CLASS_DNORM):
		SPDNORMY;
		break;

	case CLPAIR(IEEE754_CLASS_DNORM, IEEE754_CLASS_NORM):
		SPDNORMX;
	}

	/* Finally get to do some computation */

	assert(xm & SP_HIDDEN_BIT);
	assert(ym & SP_HIDDEN_BIT);

	/* Compare signs */
	if (xs > ys)
		return x;
	else if (xs < ys)
		return y;

	/* Compare exponent */
	if (xe > ye)
		return y;
	else if (xe < ye)
		return x;

	/* Compare mantissa */
	if (xm <= ym)
		return x;
	return y;
}

union ieee754sp ieee754sp_fmina(union ieee754sp x, union ieee754sp y)
{
	COMPXSP;
	COMPYSP;

	EXPLODEXSP;
	EXPLODEYSP;

	FLUSHXSP;
	FLUSHYSP;

	ieee754_clearcx();

	switch (CLPAIR(xc, yc)) {
	case CLPAIR(IEEE754_CLASS_QNAN, IEEE754_CLASS_SNAN):
	case CLPAIR(IEEE754_CLASS_ZERO, IEEE754_CLASS_SNAN):
	case CLPAIR(IEEE754_CLASS_NORM, IEEE754_CLASS_SNAN):
	case CLPAIR(IEEE754_CLASS_DNORM, IEEE754_CLASS_SNAN):
	case CLPAIR(IEEE754_CLASS_INF, IEEE754_CLASS_SNAN):
		return ieee754sp_nanxcpt(y);

	case CLPAIR(IEEE754_CLASS_SNAN, IEEE754_CLASS_SNAN):
	case CLPAIR(IEEE754_CLASS_SNAN, IEEE754_CLASS_QNAN):
	case CLPAIR(IEEE754_CLASS_SNAN, IEEE754_CLASS_ZERO):
	case CLPAIR(IEEE754_CLASS_SNAN, IEEE754_CLASS_NORM):
	case CLPAIR(IEEE754_CLASS_SNAN, IEEE754_CLASS_DNORM):
	case CLPAIR(IEEE754_CLASS_SNAN, IEEE754_CLASS_INF):
		return ieee754sp_nanxcpt(x);

	/* numbers are preferred to NaNs */
	case CLPAIR(IEEE754_CLASS_ZERO, IEEE754_CLASS_QNAN):
	case CLPAIR(IEEE754_CLASS_NORM, IEEE754_CLASS_QNAN):
	case CLPAIR(IEEE754_CLASS_DNORM, IEEE754_CLASS_QNAN):
	case CLPAIR(IEEE754_CLASS_INF, IEEE754_CLASS_QNAN):
		return x;

	case CLPAIR(IEEE754_CLASS_QNAN, IEEE754_CLASS_QNAN):
	case CLPAIR(IEEE754_CLASS_QNAN, IEEE754_CLASS_ZERO):
	case CLPAIR(IEEE754_CLASS_QNAN, IEEE754_CLASS_NORM):
	case CLPAIR(IEEE754_CLASS_QNAN, IEEE754_CLASS_DNORM):
	case CLPAIR(IEEE754_CLASS_QNAN, IEEE754_CLASS_INF):
		return y;

	/*
	 * Infinity and zero handling
	 */
	case CLPAIR(IEEE754_CLASS_INF, IEEE754_CLASS_ZERO):
	case CLPAIR(IEEE754_CLASS_INF, IEEE754_CLASS_NORM):
	case CLPAIR(IEEE754_CLASS_INF, IEEE754_CLASS_DNORM):
	case CLPAIR(IEEE754_CLASS_NORM, IEEE754_CLASS_ZERO):
	case CLPAIR(IEEE754_CLASS_DNORM, IEEE754_CLASS_ZERO):
		return x;

	case CLPAIR(IEEE754_CLASS_INF, IEEE754_CLASS_INF):
	case CLPAIR(IEEE754_CLASS_NORM, IEEE754_CLASS_INF):
	case CLPAIR(IEEE754_CLASS_DNORM, IEEE754_CLASS_INF):
	case CLPAIR(IEEE754_CLASS_ZERO, IEEE754_CLASS_INF):
	case CLPAIR(IEEE754_CLASS_ZERO, IEEE754_CLASS_NORM):
	case CLPAIR(IEEE754_CLASS_ZERO, IEEE754_CLASS_DNORM):
		return y;

	case CLPAIR(IEEE754_CLASS_ZERO, IEEE754_CLASS_ZERO):
		if (xs == ys)
			return x;
		return ieee754sp_zero(1);

	case CLPAIR(IEEE754_CLASS_DNORM, IEEE754_CLASS_DNORM):
		SPDNORMX;

	case CLPAIR(IEEE754_CLASS_NORM, IEEE754_CLASS_DNORM):
		SPDNORMY;
		break;

	case CLPAIR(IEEE754_CLASS_DNORM, IEEE754_CLASS_NORM):
		SPDNORMX;
	}

	/* Finally get to do some computation */

	assert(xm & SP_HIDDEN_BIT);
	assert(ym & SP_HIDDEN_BIT);

	/* Compare exponent */
	if (xe > ye)
		return y;
	else if (xe < ye)
		return x;

	/* Compare mantissa */
	if (xm <= ym)
		return x;
	return y;
}
