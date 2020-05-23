// SPDX-License-Identifier: GPL-2.0
/* System call table for x86-64. */

#include <linux/linkage.h>
#include <linux/sys.h>
#include <linux/cache.h>
#include <linux/moduleparam.h>
#undef MODULE_PARAM_PREFIX
#define MODULE_PARAM_PREFIX "syscall."
#include <linux/syscalls.h>
#include <asm/asm-offsets.h>
#include <asm/syscall.h>

extern asmlinkage long sys_ni_syscall(void);

SYSCALL_DEFINE0(ni_syscall)
{
	return sys_ni_syscall();
}

#define __SYSCALL_64(nr, sym, qual) extern asmlinkage long sym(const struct pt_regs *);
#define __SYSCALL_X32(nr, sym, qual) __SYSCALL_64(nr, sym, qual)
#include <asm/syscalls_64.h>
#undef __SYSCALL_64
#undef __SYSCALL_X32

#define __SYSCALL_64(nr, sym, qual) [nr] = sym,
#define __SYSCALL_X32(nr, sym, qual)

asmlinkage const sys_call_ptr_t sys_call_table[__NR_syscall_max+1] = {
	/*
	 * Smells like a compiler bug -- it doesn't work
	 * when the & below is removed.
	 */
	[0 ... __NR_syscall_max] = &__x64_sys_ni_syscall,
#include <asm/syscalls_64.h>
};

#undef __SYSCALL_64
#undef __SYSCALL_X32

#ifdef CONFIG_X86_X32_ABI

#define __SYSCALL_64(nr, sym, qual)
#define __SYSCALL_X32(nr, sym, qual) [nr] = sym,

asmlinkage const sys_call_ptr_t x32_sys_call_table[__NR_syscall_x32_max+1] = {
	/*
	 * Smells like a compiler bug -- it doesn't work
	 * when the & below is removed.
	 */
	[0 ... __NR_syscall_x32_max] = &__x64_sys_ni_syscall,
#include <asm/syscalls_64.h>
};

#undef __SYSCALL_64
#undef __SYSCALL_X32

/* Maybe enable x32 syscalls */

#if defined(CONFIG_X86_X32_DISABLED)
DEFINE_STATIC_KEY_FALSE(x32_enabled_skey);
#else
DEFINE_STATIC_KEY_TRUE(x32_enabled_skey);
#endif

static int __init x32_param_set(const char *val, const struct kernel_param *p)
{
	bool enabled;
	int ret;

	ret = kstrtobool(val, &enabled);
	if (ret)
		return ret;
	if (IS_ENABLED(CONFIG_X86_X32_DISABLED)) {
		if (enabled) {
			static_key_enable(&x32_enabled_skey.key);
			pr_info("Enabled x32 syscalls\n");
		}
	} else {
		if (!enabled) {
			static_key_disable(&x32_enabled_skey.key);
			pr_info("Disabled x32 syscalls\n");
		}
	}
	return 0;
}

static int x32_param_get(char *buffer, const struct kernel_param *p)
{
	return sprintf(buffer, "%c\n",
		       static_key_enabled(&x32_enabled_skey) ? 'Y' : 'N');
}

static const struct kernel_param_ops x32_param_ops = {
	.set = x32_param_set,
	.get = x32_param_get,
};

arch_param_cb(x32, &x32_param_ops, NULL, 0444);

#endif
