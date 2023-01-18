{
	"atomic dw/fetch and address leakage of (map ptr & -1) via stack slot",
	.insns = {
		BPF_LD_IMM64(BPF_REG_1, -1),
		BPF_LD_MAP_FD(BPF_REG_8, 0),
		BPF_LD_MAP_FD(BPF_REG_9, 0),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
		BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_9, 0),
		BPF_ATOMIC_OP(BPF_DW, BPF_AND | BPF_FETCH, BPF_REG_2, BPF_REG_1, 0),
		BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_2, 0),
		BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),
		BPF_MOV64_REG(BPF_REG_1, BPF_REG_8),
		BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
		BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_9, 0),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.fixup_map_array_48b = { 2, 4 },
	.result = ACCEPT,
	.result_unpriv = REJECT,
	.errstr_unpriv = "leaking pointer from stack off -8",
},
{
	"atomic dw/fetch and address leakage of (map ptr & -1) via returned value",
	.insns = {
		BPF_LD_IMM64(BPF_REG_1, -1),
		BPF_LD_MAP_FD(BPF_REG_8, 0),
		BPF_LD_MAP_FD(BPF_REG_9, 0),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
		BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_9, 0),
		BPF_ATOMIC_OP(BPF_DW, BPF_AND | BPF_FETCH, BPF_REG_2, BPF_REG_1, 0),
		BPF_MOV64_REG(BPF_REG_9, BPF_REG_1),
		BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),
		BPF_MOV64_REG(BPF_REG_1, BPF_REG_8),
		BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
		BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_9, 0),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.fixup_map_array_48b = { 2, 4 },
	.result = ACCEPT,
	.result_unpriv = REJECT,
	.errstr_unpriv = "leaking pointer from stack off -8",
},
{
	"atomic w/fetch and address leakage of (map ptr & -1) via stack slot",
	.insns = {
		BPF_LD_IMM64(BPF_REG_1, -1),
		BPF_LD_MAP_FD(BPF_REG_8, 0),
		BPF_LD_MAP_FD(BPF_REG_9, 0),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
		BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_9, 0),
		BPF_ATOMIC_OP(BPF_W, BPF_AND | BPF_FETCH, BPF_REG_2, BPF_REG_1, 0),
		BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_2, 0),
		BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),
		BPF_MOV64_REG(BPF_REG_1, BPF_REG_8),
		BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
		BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_9, 0),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.fixup_map_array_48b = { 2, 4 },
	.result = REJECT,
	.errstr = "invalid size of register fill",
},
{
	"atomic w/fetch and address leakage of (map ptr & -1) via returned value",
	.insns = {
		BPF_LD_IMM64(BPF_REG_1, -1),
		BPF_LD_MAP_FD(BPF_REG_8, 0),
		BPF_LD_MAP_FD(BPF_REG_9, 0),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
		BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_9, 0),
		BPF_ATOMIC_OP(BPF_W, BPF_AND | BPF_FETCH, BPF_REG_2, BPF_REG_1, 0),
		BPF_MOV64_REG(BPF_REG_9, BPF_REG_1),
		BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),
		BPF_MOV64_REG(BPF_REG_1, BPF_REG_8),
		BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
		BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_9, 0),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.fixup_map_array_48b = { 2, 4 },
	.result = REJECT,
	.errstr = "invalid size of register fill",
},
#define __ATOMIC_FETCH_OP_TEST(src_reg, dst_reg, operand1, op, operand2, expect) \
	{								\
		"atomic fetch " #op ", src=" #dst_reg " dst=" #dst_reg,	\
		.insns = {						\
			/* u64 val = operan1; */			\
			BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, operand1),	\
			/* u64 old = atomic_fetch_add(&val, operand2); */ \
			BPF_MOV64_REG(dst_reg, BPF_REG_10),		\
			BPF_MOV64_IMM(src_reg, operand2),		\
			BPF_ATOMIC_OP(BPF_DW, op,			\
				      dst_reg, src_reg, -8),		\
			/* if (old != operand1) exit(1); */		\
			BPF_JMP_IMM(BPF_JEQ, src_reg, operand1, 2),	\
			BPF_MOV64_IMM(BPF_REG_0, 1),			\
			BPF_EXIT_INSN(),				\
			/* if (val != result) exit (2); */		\
			BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, -8),	\
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, expect, 2),	\
			BPF_MOV64_IMM(BPF_REG_0, 2),			\
			BPF_EXIT_INSN(),				\
			/* exit(0); */					\
			BPF_MOV64_IMM(BPF_REG_0, 0),			\
			BPF_EXIT_INSN(),				\
		},							\
		.result = ACCEPT,					\
	}
__ATOMIC_FETCH_OP_TEST(BPF_REG_1, BPF_REG_2, 1, BPF_ADD | BPF_FETCH, 2, 3),
__ATOMIC_FETCH_OP_TEST(BPF_REG_0, BPF_REG_1, 1, BPF_ADD | BPF_FETCH, 2, 3),
__ATOMIC_FETCH_OP_TEST(BPF_REG_1, BPF_REG_0, 1, BPF_ADD | BPF_FETCH, 2, 3),
__ATOMIC_FETCH_OP_TEST(BPF_REG_2, BPF_REG_3, 1, BPF_ADD | BPF_FETCH, 2, 3),
__ATOMIC_FETCH_OP_TEST(BPF_REG_4, BPF_REG_5, 1, BPF_ADD | BPF_FETCH, 2, 3),
__ATOMIC_FETCH_OP_TEST(BPF_REG_9, BPF_REG_8, 1, BPF_ADD | BPF_FETCH, 2, 3),
__ATOMIC_FETCH_OP_TEST(BPF_REG_1, BPF_REG_2, 0x010, BPF_AND | BPF_FETCH, 0x011, 0x010),
__ATOMIC_FETCH_OP_TEST(BPF_REG_0, BPF_REG_1, 0x010, BPF_AND | BPF_FETCH, 0x011, 0x010),
__ATOMIC_FETCH_OP_TEST(BPF_REG_1, BPF_REG_0, 0x010, BPF_AND | BPF_FETCH, 0x011, 0x010),
__ATOMIC_FETCH_OP_TEST(BPF_REG_2, BPF_REG_3, 0x010, BPF_AND | BPF_FETCH, 0x011, 0x010),
__ATOMIC_FETCH_OP_TEST(BPF_REG_4, BPF_REG_5, 0x010, BPF_AND | BPF_FETCH, 0x011, 0x010),
__ATOMIC_FETCH_OP_TEST(BPF_REG_9, BPF_REG_8, 0x010, BPF_AND | BPF_FETCH, 0x011, 0x010),
__ATOMIC_FETCH_OP_TEST(BPF_REG_1, BPF_REG_2, 0x010, BPF_OR | BPF_FETCH, 0x011, 0x011),
__ATOMIC_FETCH_OP_TEST(BPF_REG_0, BPF_REG_1, 0x010, BPF_OR | BPF_FETCH, 0x011, 0x011),
__ATOMIC_FETCH_OP_TEST(BPF_REG_1, BPF_REG_0, 0x010, BPF_OR | BPF_FETCH, 0x011, 0x011),
__ATOMIC_FETCH_OP_TEST(BPF_REG_2, BPF_REG_3, 0x010, BPF_OR | BPF_FETCH, 0x011, 0x011),
__ATOMIC_FETCH_OP_TEST(BPF_REG_4, BPF_REG_5, 0x010, BPF_OR | BPF_FETCH, 0x011, 0x011),
__ATOMIC_FETCH_OP_TEST(BPF_REG_9, BPF_REG_8, 0x010, BPF_OR | BPF_FETCH, 0x011, 0x011),
__ATOMIC_FETCH_OP_TEST(BPF_REG_1, BPF_REG_2, 0x010, BPF_XOR | BPF_FETCH, 0x011, 0x001),
__ATOMIC_FETCH_OP_TEST(BPF_REG_0, BPF_REG_1, 0x010, BPF_XOR | BPF_FETCH, 0x011, 0x001),
__ATOMIC_FETCH_OP_TEST(BPF_REG_1, BPF_REG_0, 0x010, BPF_XOR | BPF_FETCH, 0x011, 0x001),
__ATOMIC_FETCH_OP_TEST(BPF_REG_2, BPF_REG_3, 0x010, BPF_XOR | BPF_FETCH, 0x011, 0x001),
__ATOMIC_FETCH_OP_TEST(BPF_REG_4, BPF_REG_5, 0x010, BPF_XOR | BPF_FETCH, 0x011, 0x001),
__ATOMIC_FETCH_OP_TEST(BPF_REG_9, BPF_REG_8, 0x010, BPF_XOR | BPF_FETCH, 0x011, 0x001),
__ATOMIC_FETCH_OP_TEST(BPF_REG_1, BPF_REG_2, 0x010, BPF_XCHG, 0x011, 0x011),
__ATOMIC_FETCH_OP_TEST(BPF_REG_0, BPF_REG_1, 0x010, BPF_XCHG, 0x011, 0x011),
__ATOMIC_FETCH_OP_TEST(BPF_REG_1, BPF_REG_0, 0x010, BPF_XCHG, 0x011, 0x011),
__ATOMIC_FETCH_OP_TEST(BPF_REG_2, BPF_REG_3, 0x010, BPF_XCHG, 0x011, 0x011),
__ATOMIC_FETCH_OP_TEST(BPF_REG_4, BPF_REG_5, 0x010, BPF_XCHG, 0x011, 0x011),
__ATOMIC_FETCH_OP_TEST(BPF_REG_9, BPF_REG_8, 0x010, BPF_XCHG, 0x011, 0x011),
#undef __ATOMIC_FETCH_OP_TEST
