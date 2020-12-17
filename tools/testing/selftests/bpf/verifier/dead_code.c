{
	"dead code: start",
	.insns = {
	BPF_JMP_IMM(BPF_JA, 0, 0, 2),
	BPF_LDX_MEM(BPF_B, BPF_REG_8, BPF_REG_9, 0),
	BPF_JMP_IMM(BPF_JA, 0, 0, 2),
	BPF_MOV64_IMM(BPF_REG_0, 7),
	BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 10, -4),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 7,
},
{
	"dead code: mid 1",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 7),
	BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 0, 1),
	BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 10, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 7,
},
{
	"dead code: mid 2",
	.insns = {
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_prandom_u32),
	BPF_JMP_IMM(BPF_JSET, BPF_REG_0, 1, 4),
	BPF_JMP_IMM(BPF_JSET, BPF_REG_0, 1, 1),
	BPF_JMP_IMM(BPF_JA, 0, 0, 2),
	BPF_MOV64_IMM(BPF_REG_0, 7),
	BPF_EXIT_INSN(),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 1,
},
{
	"dead code: end 1",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 7),
	BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 10, 1),
	BPF_EXIT_INSN(),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 7,
},
{
	"dead code: end 2",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 7),
	BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 10, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_IMM(BPF_REG_0, 12),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 7,
},
{
	"dead code: end 3",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 7),
	BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 8, 1),
	BPF_EXIT_INSN(),
	BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 10, 1),
	BPF_JMP_IMM(BPF_JA, 0, 0, 1),
	BPF_MOV64_IMM(BPF_REG_0, 12),
	BPF_JMP_IMM(BPF_JA, 0, 0, -5),
	},
	.result = ACCEPT,
	.retval = 7,
},
{
	"dead code: tail of main + func",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 7),
	BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 8, 1),
	BPF_EXIT_INSN(),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 1, 0, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_IMM(BPF_REG_0, 12),
	BPF_EXIT_INSN(),
	},
	.errstr_unpriv = "function calls to other bpf functions are allowed for",
	.result_unpriv = REJECT,
	.result = ACCEPT,
	.retval = 7,
},
{
	"dead code: tail of main + two functions",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 7),
	BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 8, 1),
	BPF_EXIT_INSN(),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 1, 0, 1),
	BPF_EXIT_INSN(),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 1, 0, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_IMM(BPF_REG_0, 12),
	BPF_EXIT_INSN(),
	},
	.errstr_unpriv = "function calls to other bpf functions are allowed for",
	.result_unpriv = REJECT,
	.result = ACCEPT,
	.retval = 7,
},
{
	"dead code: function in the middle and mid of another func",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_1, 7),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 1, 0, 3),
	BPF_EXIT_INSN(),
	BPF_MOV64_IMM(BPF_REG_0, 12),
	BPF_EXIT_INSN(),
	BPF_MOV64_IMM(BPF_REG_0, 7),
	BPF_JMP_IMM(BPF_JGE, BPF_REG_1, 7, 1),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 1, 0, -5),
	BPF_EXIT_INSN(),
	},
	.errstr_unpriv = "function calls to other bpf functions are allowed for",
	.result_unpriv = REJECT,
	.result = ACCEPT,
	.retval = 7,
},
{
	"dead code: middle of main before call",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_1, 2),
	BPF_JMP_IMM(BPF_JGE, BPF_REG_1, 2, 1),
	BPF_MOV64_IMM(BPF_REG_1, 5),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 1, 0, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
	BPF_EXIT_INSN(),
	},
	.errstr_unpriv = "function calls to other bpf functions are allowed for",
	.result_unpriv = REJECT,
	.result = ACCEPT,
	.retval = 2,
},
{
	"dead code: start of a function",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_1, 2),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 1, 0, 1),
	BPF_EXIT_INSN(),
	BPF_JMP_IMM(BPF_JA, 0, 0, 0),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
	BPF_EXIT_INSN(),
	},
	.errstr_unpriv = "function calls to other bpf functions are allowed for",
	.result_unpriv = REJECT,
	.result = ACCEPT,
	.retval = 2,
},
