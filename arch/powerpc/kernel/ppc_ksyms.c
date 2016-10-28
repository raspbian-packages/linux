#include <linux/ftrace.h>
#include <linux/mm.h>

#include <asm/processor.h>
#include <asm/switch_to.h>
#include <asm/cacheflush.h>
#include <asm/epapr_hcalls.h>

#ifdef CONFIG_PPC64
EXPORT_SYMBOL(flush_dcache_range);
#endif
EXPORT_SYMBOL(flush_icache_range);

EXPORT_SYMBOL(empty_zero_page);

long long __bswapdi2(long long);
EXPORT_SYMBOL(__bswapdi2);

#ifdef CONFIG_FUNCTION_TRACER
EXPORT_SYMBOL(_mcount);
#endif

#ifdef CONFIG_PPC_FPU
EXPORT_SYMBOL(load_fp_state);
EXPORT_SYMBOL(store_fp_state);
#endif

#ifdef CONFIG_ALTIVEC
EXPORT_SYMBOL(load_vr_state);
EXPORT_SYMBOL(store_vr_state);
#endif

#ifdef CONFIG_EPAPR_PARAVIRT
EXPORT_SYMBOL(epapr_hypercall_start);
#endif

EXPORT_SYMBOL(current_stack_pointer);
