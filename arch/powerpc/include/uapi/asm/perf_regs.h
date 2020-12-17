/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_POWERPC_PERF_REGS_H
#define _UAPI_ASM_POWERPC_PERF_REGS_H

enum perf_event_powerpc_regs {
	PERF_REG_POWERPC_R0,
	PERF_REG_POWERPC_R1,
	PERF_REG_POWERPC_R2,
	PERF_REG_POWERPC_R3,
	PERF_REG_POWERPC_R4,
	PERF_REG_POWERPC_R5,
	PERF_REG_POWERPC_R6,
	PERF_REG_POWERPC_R7,
	PERF_REG_POWERPC_R8,
	PERF_REG_POWERPC_R9,
	PERF_REG_POWERPC_R10,
	PERF_REG_POWERPC_R11,
	PERF_REG_POWERPC_R12,
	PERF_REG_POWERPC_R13,
	PERF_REG_POWERPC_R14,
	PERF_REG_POWERPC_R15,
	PERF_REG_POWERPC_R16,
	PERF_REG_POWERPC_R17,
	PERF_REG_POWERPC_R18,
	PERF_REG_POWERPC_R19,
	PERF_REG_POWERPC_R20,
	PERF_REG_POWERPC_R21,
	PERF_REG_POWERPC_R22,
	PERF_REG_POWERPC_R23,
	PERF_REG_POWERPC_R24,
	PERF_REG_POWERPC_R25,
	PERF_REG_POWERPC_R26,
	PERF_REG_POWERPC_R27,
	PERF_REG_POWERPC_R28,
	PERF_REG_POWERPC_R29,
	PERF_REG_POWERPC_R30,
	PERF_REG_POWERPC_R31,
	PERF_REG_POWERPC_NIP,
	PERF_REG_POWERPC_MSR,
	PERF_REG_POWERPC_ORIG_R3,
	PERF_REG_POWERPC_CTR,
	PERF_REG_POWERPC_LINK,
	PERF_REG_POWERPC_XER,
	PERF_REG_POWERPC_CCR,
	PERF_REG_POWERPC_SOFTE,
	PERF_REG_POWERPC_TRAP,
	PERF_REG_POWERPC_DAR,
	PERF_REG_POWERPC_DSISR,
	PERF_REG_POWERPC_SIER,
	PERF_REG_POWERPC_MMCRA,
	/* Extended registers */
	PERF_REG_POWERPC_MMCR0,
	PERF_REG_POWERPC_MMCR1,
	PERF_REG_POWERPC_MMCR2,
	PERF_REG_POWERPC_MMCR3,
	PERF_REG_POWERPC_SIER2,
	PERF_REG_POWERPC_SIER3,
	/* Max regs without the extended regs */
	PERF_REG_POWERPC_MAX = PERF_REG_POWERPC_MMCRA + 1,
};

#define PERF_REG_PMU_MASK	((1ULL << PERF_REG_POWERPC_MAX) - 1)

/* PERF_REG_EXTENDED_MASK value for CPU_FTR_ARCH_300 */
#define PERF_REG_PMU_MASK_300   (((1ULL << (PERF_REG_POWERPC_MMCR2 + 1)) - 1) - PERF_REG_PMU_MASK)
/* PERF_REG_EXTENDED_MASK value for CPU_FTR_ARCH_31 */
#define PERF_REG_PMU_MASK_31   (((1ULL << (PERF_REG_POWERPC_SIER3 + 1)) - 1) - PERF_REG_PMU_MASK)

#define PERF_REG_MAX_ISA_300   (PERF_REG_POWERPC_MMCR2 + 1)
#define PERF_REG_MAX_ISA_31    (PERF_REG_POWERPC_SIER3 + 1)
#endif /* _UAPI_ASM_POWERPC_PERF_REGS_H */
