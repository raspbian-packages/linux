#ifndef _ASM_S390_SECCOMP_H
#define _ASM_S390_SECCOMP_H

#include <linux/unistd.h>

#define __NR_seccomp_read	__NR_read
#define __NR_seccomp_write	__NR_write
#define __NR_seccomp_exit	__NR_exit
#define __NR_seccomp_sigreturn	__NR_sigreturn

#define __NR_seccomp_read_32	__NR_read
#define __NR_seccomp_write_32	__NR_write
#define __NR_seccomp_exit_32	__NR_exit
#define __NR_seccomp_sigreturn_32 __NR_sigreturn

#include <asm-generic/seccomp.h>

#endif	/* _ASM_S390_SECCOMP_H */
