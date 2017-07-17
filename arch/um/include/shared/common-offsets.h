/* for use by sys-$SUBARCH/kernel-offsets.c */

DEFINE(KERNEL_MADV_REMOVE, MADV_REMOVE);

DEFINE(UM_KERN_PAGE_SIZE, PAGE_SIZE);
DEFINE(UM_KERN_PAGE_MASK, PAGE_MASK);
DEFINE(UM_KERN_PAGE_SHIFT, PAGE_SHIFT);
DEFINE(UM_NSEC_PER_SEC, NSEC_PER_SEC);

DEFINE(UM_ELF_CLASS, ELF_CLASS);
DEFINE(UM_ELFCLASS32, ELFCLASS32);
DEFINE(UM_ELFCLASS64, ELFCLASS64);

DEFINE(UM_NR_CPUS, NR_CPUS);

DEFINE(UM_GFP_KERNEL, GFP_KERNEL);
DEFINE(UM_GFP_ATOMIC, GFP_ATOMIC);

/* For crypto assembler code. */
DEFINE(crypto_tfm_ctx_offset, offsetof(struct crypto_tfm, __crt_ctx));

DEFINE(UM_THREAD_SIZE, THREAD_SIZE);

DEFINE(UM_HZ, HZ);

DEFINE(UM_USEC_PER_SEC, USEC_PER_SEC);
DEFINE(UM_NSEC_PER_SEC, NSEC_PER_SEC);
DEFINE(UM_NSEC_PER_USEC, NSEC_PER_USEC);

#ifdef CONFIG_PRINTK
DEFINE(UML_CONFIG_PRINTK, CONFIG_PRINTK);
#endif
#ifdef CONFIG_NO_HZ_COMMON
DEFINE(UML_CONFIG_NO_HZ_COMMON, CONFIG_NO_HZ_COMMON);
#endif
#ifdef CONFIG_UML_X86
DEFINE(UML_CONFIG_UML_X86, CONFIG_UML_X86);
#endif
#ifdef CONFIG_64BIT
DEFINE(UML_CONFIG_64BIT, CONFIG_64BIT);
#endif
