{
	"helper access to variable memory: stack, bitwise AND + JMP, correct bounds",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -64),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -64),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -56),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -48),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -40),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -32),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -24),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -16),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
	BPF_MOV64_IMM(BPF_REG_2, 16),
	BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_2, -128),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, -128),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 64),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_JMP_REG(BPF_JGE, BPF_REG_4, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
{
	"helper access to variable memory: stack, bitwise AND, zero included",
	.insns = {
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, 8),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -64),
	BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_2, -128),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, -128),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 64),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_EXIT_INSN(),
	},
	.errstr = "invalid indirect read from stack off -64+0 size 64",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
{
	"helper access to variable memory: stack, bitwise AND + JMP, wrong max",
	.insns = {
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, 8),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -64),
	BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_2, -128),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, -128),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 65),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_JMP_REG(BPF_JGE, BPF_REG_4, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.errstr = "invalid stack type R1 off=-64 access_size=65",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
{
	"helper access to variable memory: stack, JMP, correct bounds",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -64),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -64),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -56),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -48),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -40),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -32),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -24),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -16),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
	BPF_MOV64_IMM(BPF_REG_2, 16),
	BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_2, -128),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, -128),
	BPF_JMP_IMM(BPF_JGT, BPF_REG_2, 64, 4),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_JMP_REG(BPF_JGE, BPF_REG_4, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
{
	"helper access to variable memory: stack, JMP (signed), correct bounds",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -64),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -64),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -56),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -48),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -40),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -32),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -24),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -16),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
	BPF_MOV64_IMM(BPF_REG_2, 16),
	BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_2, -128),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, -128),
	BPF_JMP_IMM(BPF_JSGT, BPF_REG_2, 64, 4),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_JMP_REG(BPF_JSGE, BPF_REG_4, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
{
	"helper access to variable memory: stack, JMP, bounds + offset",
	.insns = {
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, 8),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -64),
	BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_2, -128),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, -128),
	BPF_JMP_IMM(BPF_JGT, BPF_REG_2, 64, 5),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_JMP_REG(BPF_JGE, BPF_REG_4, BPF_REG_2, 3),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 1),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.errstr = "invalid stack type R1 off=-64 access_size=65",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
{
	"helper access to variable memory: stack, JMP, wrong max",
	.insns = {
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, 8),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -64),
	BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_2, -128),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, -128),
	BPF_JMP_IMM(BPF_JGT, BPF_REG_2, 65, 4),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_JMP_REG(BPF_JGE, BPF_REG_4, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.errstr = "invalid stack type R1 off=-64 access_size=65",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
{
	"helper access to variable memory: stack, JMP, no max check",
	.insns = {
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, 8),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -64),
	BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_2, -128),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, -128),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_JMP_REG(BPF_JGE, BPF_REG_4, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	/* because max wasn't checked, signed min is negative */
	.errstr = "R2 min value is negative, either use unsigned or 'var &= const'",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
{
	"helper access to variable memory: stack, JMP, no min check",
	.insns = {
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, 8),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -64),
	BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_2, -128),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, -128),
	BPF_JMP_IMM(BPF_JGT, BPF_REG_2, 64, 3),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.errstr = "invalid indirect read from stack off -64+0 size 64",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
{
	"helper access to variable memory: stack, JMP (signed), no min check",
	.insns = {
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, 8),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -64),
	BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_2, -128),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, -128),
	BPF_JMP_IMM(BPF_JSGT, BPF_REG_2, 64, 3),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.errstr = "R2 min value is negative",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
{
	"helper access to variable memory: map, JMP, correct bounds",
	.insns = {
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 10),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_MOV64_IMM(BPF_REG_2, sizeof(struct test_val)),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, -128),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, -128),
	BPF_JMP_IMM(BPF_JSGT, BPF_REG_2, sizeof(struct test_val), 4),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_JMP_REG(BPF_JSGE, BPF_REG_4, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 3 },
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
{
	"helper access to variable memory: map, JMP, wrong max",
	.insns = {
	BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, 8),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 10),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_6),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, -128),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, -128),
	BPF_JMP_IMM(BPF_JSGT, BPF_REG_2, sizeof(struct test_val) + 1, 4),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_JMP_REG(BPF_JSGE, BPF_REG_4, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 4 },
	.errstr = "invalid access to map value, value_size=48 off=0 size=49",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
{
	"helper access to variable memory: map adjusted, JMP, correct bounds",
	.insns = {
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 11),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 20),
	BPF_MOV64_IMM(BPF_REG_2, sizeof(struct test_val)),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, -128),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, -128),
	BPF_JMP_IMM(BPF_JSGT, BPF_REG_2, sizeof(struct test_val) - 20, 4),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_JMP_REG(BPF_JSGE, BPF_REG_4, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 3 },
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
{
	"helper access to variable memory: map adjusted, JMP, wrong max",
	.insns = {
	BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, 8),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 11),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 20),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_6),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, -128),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, -128),
	BPF_JMP_IMM(BPF_JSGT, BPF_REG_2, sizeof(struct test_val) - 19, 4),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_JMP_REG(BPF_JSGE, BPF_REG_4, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 4 },
	.errstr = "R1 min value is outside of the allowed memory range",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
{
	"helper access to variable memory: size = 0 allowed on NULL (ARG_PTR_TO_MEM_OR_NULL)",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_1, 0),
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_MOV64_IMM(BPF_REG_5, 0),
	BPF_EMIT_CALL(BPF_FUNC_csum_diff),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
},
{
	"helper access to variable memory: size > 0 not allowed on NULL (ARG_PTR_TO_MEM_OR_NULL)",
	.insns = {
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, 0),
	BPF_MOV64_IMM(BPF_REG_1, 0),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, -128),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, -128),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 64),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_MOV64_IMM(BPF_REG_5, 0),
	BPF_EMIT_CALL(BPF_FUNC_csum_diff),
	BPF_EXIT_INSN(),
	},
	.errstr = "R1 type=inv expected=fp",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
},
{
	"helper access to variable memory: size = 0 allowed on != NULL stack pointer (ARG_PTR_TO_MEM_OR_NULL)",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_2, 0),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 8),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_MOV64_IMM(BPF_REG_5, 0),
	BPF_EMIT_CALL(BPF_FUNC_csum_diff),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
},
{
	"helper access to variable memory: size = 0 allowed on != NULL map pointer (ARG_PTR_TO_MEM_OR_NULL)",
	.insns = {
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 6),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_MOV64_IMM(BPF_REG_5, 0),
	BPF_EMIT_CALL(BPF_FUNC_csum_diff),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_8b = { 3 },
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
},
{
	"helper access to variable memory: size possible = 0 allowed on != NULL stack pointer (ARG_PTR_TO_MEM_OR_NULL)",
	.insns = {
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 9),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_0, 0),
	BPF_JMP_IMM(BPF_JGT, BPF_REG_2, 8, 7),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),
	BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_2, 0),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_MOV64_IMM(BPF_REG_5, 0),
	BPF_EMIT_CALL(BPF_FUNC_csum_diff),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_8b = { 3 },
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
},
{
	"helper access to variable memory: size possible = 0 allowed on != NULL map pointer (ARG_PTR_TO_MEM_OR_NULL)",
	.insns = {
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 7),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_0, 0),
	BPF_JMP_IMM(BPF_JGT, BPF_REG_2, 8, 4),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_MOV64_IMM(BPF_REG_5, 0),
	BPF_EMIT_CALL(BPF_FUNC_csum_diff),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_8b = { 3 },
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
},
{
	"helper access to variable memory: size possible = 0 allowed on != NULL packet pointer (ARG_PTR_TO_MEM_OR_NULL)",
	.insns = {
	BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_1,
		    offsetof(struct __sk_buff, data)),
	BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
		    offsetof(struct __sk_buff, data_end)),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_6),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 8),
	BPF_JMP_REG(BPF_JGT, BPF_REG_0, BPF_REG_3, 7),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, 0),
	BPF_JMP_IMM(BPF_JGT, BPF_REG_2, 8, 4),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_MOV64_IMM(BPF_REG_5, 0),
	BPF_EMIT_CALL(BPF_FUNC_csum_diff),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.retval = 0 /* csum_diff of 64-byte packet */,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"helper access to variable memory: size = 0 not allowed on NULL (!ARG_PTR_TO_MEM_OR_NULL)",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_1, 0),
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_EXIT_INSN(),
	},
	.errstr = "R1 type=inv expected=fp",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
{
	"helper access to variable memory: size > 0 not allowed on NULL (!ARG_PTR_TO_MEM_OR_NULL)",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_1, 0),
	BPF_MOV64_IMM(BPF_REG_2, 1),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_EXIT_INSN(),
	},
	.errstr = "R1 type=inv expected=fp",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
{
	"helper access to variable memory: size = 0 allowed on != NULL stack pointer (!ARG_PTR_TO_MEM_OR_NULL)",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
{
	"helper access to variable memory: size = 0 allowed on != NULL map pointer (!ARG_PTR_TO_MEM_OR_NULL)",
	.insns = {
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 4),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_8b = { 3 },
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
{
	"helper access to variable memory: size possible = 0 allowed on != NULL stack pointer (!ARG_PTR_TO_MEM_OR_NULL)",
	.insns = {
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 6),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_0, 0),
	BPF_JMP_IMM(BPF_JGT, BPF_REG_2, 8, 4),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_8b = { 3 },
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
{
	"helper access to variable memory: size possible = 0 allowed on != NULL map pointer (!ARG_PTR_TO_MEM_OR_NULL)",
	.insns = {
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 5),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_0, 0),
	BPF_JMP_IMM(BPF_JGT, BPF_REG_2, 8, 2),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_8b = { 3 },
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
{
	"helper access to variable memory: 8 bytes leak",
	.insns = {
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, 8),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -64),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -64),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -56),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -48),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -40),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -24),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -16),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, -128),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, -128),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 63),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 1),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, -16),
	BPF_EXIT_INSN(),
	},
	.errstr = "invalid indirect read from stack off -64+32 size 64",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
{
	"helper access to variable memory: 8 bytes no leak (init memory)",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -64),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -56),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -48),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -40),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -32),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -24),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -16),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -64),
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 32),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 32),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, -16),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,
},
