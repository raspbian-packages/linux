/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Please do not include this explicitly.
 * This is used by C files generated by modpost.
 */

#ifndef __LINUX_EXPORT_INTERNAL_H__
#define __LINUX_EXPORT_INTERNAL_H__

#include <linux/compiler.h>
#include <linux/types.h>

#if defined(CONFIG_HAVE_ARCH_PREL32_RELOCATIONS)
/*
 * relative reference: this reduces the size by half on 64-bit architectures,
 * and eliminates the need for absolute relocations that require runtime
 * processing on relocatable kernels.
 */
#define __KSYM_ALIGN		".balign 4"
#define __KSYM_REF(sym)		".long " #sym "- ."
#elif defined(CONFIG_64BIT)
#define __KSYM_ALIGN		".balign 8"
#define __KSYM_REF(sym)		".quad " #sym
#else
#define __KSYM_ALIGN		".balign 4"
#define __KSYM_REF(sym)		".long " #sym
#endif

/*
 * For every exported symbol, do the following:
 *
 * - Put the name of the symbol and namespace (empty string "" for none) in
 *   __ksymtab_strings.
 * - Place a struct kernel_symbol entry in the __ksymtab section.
 *
 * Note on .section use: we specify progbits since usage of the "M" (SHF_MERGE)
 * section flag requires it. Use '%progbits' instead of '@progbits' since the
 * former apparently works on all arches according to the binutils source.
 */
#define __KSYMTAB(name, sym, sec, ns)						\
	asm("	.section \"__ksymtab_strings\",\"aMS\",%progbits,1"	"\n"	\
	    "__kstrtab_" #name ":"					"\n"	\
	    "	.asciz \"" #name "\""					"\n"	\
	    "__kstrtabns_" #name ":"					"\n"	\
	    "	.asciz \"" ns "\""					"\n"	\
	    "	.previous"						"\n"	\
	    "	.section \"___ksymtab" sec "+" #name "\", \"a\""	"\n"	\
		__KSYM_ALIGN						"\n"	\
	    "__ksymtab_" #name ":"					"\n"	\
		__KSYM_REF(sym)						"\n"	\
		__KSYM_REF(__kstrtab_ ##name)				"\n"	\
		__KSYM_REF(__kstrtabns_ ##name)				"\n"	\
	    "	.previous"						"\n"	\
	)

#if defined(CONFIG_PARISC) && defined(CONFIG_64BIT)
#define KSYM_FUNC(name)		P%name
#else
#define KSYM_FUNC(name)		name
#endif

#define KSYMTAB_FUNC(name, sec, ns)	__KSYMTAB(name, KSYM_FUNC(name), sec, ns)
#define KSYMTAB_DATA(name, sec, ns)	__KSYMTAB(name, name, sec, ns)

#define SYMBOL_CRC(sym, crc, sec)   \
	asm(".section \"___kcrctab" sec "+" #sym "\",\"a\""	"\n" \
	    ".balign 4"						"\n" \
	    "__crc_" #sym ":"					"\n" \
	    ".long " #crc					"\n" \
	    ".previous"						"\n")

#endif /* __LINUX_EXPORT_INTERNAL_H__ */
