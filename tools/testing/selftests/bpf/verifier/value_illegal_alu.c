{
	"map element value illegal alu op, 1",
	.insns = {
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 8),
	BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, 22),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 3 },
	.errstr = "R0 bitwise operator &= on pointer",
	.result = REJECT,
},
{
	"map element value illegal alu op, 2",
	.insns = {
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
	BPF_ALU32_IMM(BPF_ADD, BPF_REG_0, 0),
	BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, 22),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 3 },
	.errstr = "R0 32-bit pointer arithmetic prohibited",
	.result = REJECT,
},
{
	"map element value illegal alu op, 3",
	.insns = {
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
	BPF_ALU64_IMM(BPF_DIV, BPF_REG_0, 42),
	BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, 22),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 3 },
	.errstr = "R0 pointer arithmetic with /= operator",
	.result = REJECT,
},
{
	"map element value illegal alu op, 4",
	.insns = {
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
	BPF_ENDIAN(BPF_FROM_BE, BPF_REG_0, 64),
	BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, 22),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 3 },
	.errstr_unpriv = "R0 pointer arithmetic prohibited",
	.errstr = "invalid mem access 'inv'",
	.result = REJECT,
	.result_unpriv = REJECT,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"map element value illegal alu op, 5",
	.insns = {
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 7),
	BPF_MOV64_IMM(BPF_REG_3, 4096),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_0, 0),
	BPF_ATOMIC_OP(BPF_DW, BPF_ADD, BPF_REG_2, BPF_REG_3, 0),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_2, 0),
	BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, 22),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 3 },
	.errstr_unpriv = "leaking pointer from stack off -8",
	.errstr = "R0 invalid mem access 'inv'",
	.result = REJECT,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
