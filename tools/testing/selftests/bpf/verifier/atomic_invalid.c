#define __INVALID_ATOMIC_ACCESS_TEST(op)				\
	{								\
		"atomic " #op " access through non-pointer ",		\
		.insns = {						\
			BPF_MOV64_IMM(BPF_REG_0, 1),			\
			BPF_MOV64_IMM(BPF_REG_1, 0),			\
			BPF_ATOMIC_OP(BPF_DW, op, BPF_REG_1, BPF_REG_0, -8), \
			BPF_MOV64_IMM(BPF_REG_0, 0),			\
			BPF_EXIT_INSN(),				\
		},							\
		.result = REJECT,					\
		.errstr = "R1 invalid mem access 'scalar'"		\
	}
__INVALID_ATOMIC_ACCESS_TEST(BPF_ADD),
__INVALID_ATOMIC_ACCESS_TEST(BPF_ADD | BPF_FETCH),
__INVALID_ATOMIC_ACCESS_TEST(BPF_ADD),
__INVALID_ATOMIC_ACCESS_TEST(BPF_ADD | BPF_FETCH),
__INVALID_ATOMIC_ACCESS_TEST(BPF_AND),
__INVALID_ATOMIC_ACCESS_TEST(BPF_AND | BPF_FETCH),
__INVALID_ATOMIC_ACCESS_TEST(BPF_OR),
__INVALID_ATOMIC_ACCESS_TEST(BPF_OR | BPF_FETCH),
__INVALID_ATOMIC_ACCESS_TEST(BPF_XOR),
__INVALID_ATOMIC_ACCESS_TEST(BPF_XOR | BPF_FETCH),
__INVALID_ATOMIC_ACCESS_TEST(BPF_XCHG),
__INVALID_ATOMIC_ACCESS_TEST(BPF_CMPXCHG),
