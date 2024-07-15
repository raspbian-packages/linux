{
	"jit: lsh, rsh, arsh by 1",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_MOV64_IMM(BPF_REG_1, 0xff),
	BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 1),
	BPF_ALU32_IMM(BPF_LSH, BPF_REG_1, 1),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0x3fc, 1),
	BPF_EXIT_INSN(),
	BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 1),
	BPF_ALU32_IMM(BPF_RSH, BPF_REG_1, 1),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0xff, 1),
	BPF_EXIT_INSN(),
	BPF_ALU64_IMM(BPF_ARSH, BPF_REG_1, 1),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0x7f, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 2,
},
{
	"jit: mov32 for ldimm64, 1",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_LD_IMM64(BPF_REG_1, 0xfeffffffffffffffULL),
	BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 32),
	BPF_LD_IMM64(BPF_REG_2, 0xfeffffffULL),
	BPF_JMP_REG(BPF_JEQ, BPF_REG_1, BPF_REG_2, 1),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 2,
},
{
	"jit: mov32 for ldimm64, 2",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_LD_IMM64(BPF_REG_1, 0x1ffffffffULL),
	BPF_LD_IMM64(BPF_REG_2, 0xffffffffULL),
	BPF_JMP_REG(BPF_JEQ, BPF_REG_1, BPF_REG_2, 1),
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 2,
},
{
	"jit: various mul tests",
	.insns = {
	BPF_LD_IMM64(BPF_REG_2, 0xeeff0d413122ULL),
	BPF_LD_IMM64(BPF_REG_0, 0xfefefeULL),
	BPF_LD_IMM64(BPF_REG_1, 0xefefefULL),
	BPF_ALU64_REG(BPF_MUL, BPF_REG_0, BPF_REG_1),
	BPF_JMP_REG(BPF_JEQ, BPF_REG_0, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	BPF_LD_IMM64(BPF_REG_3, 0xfefefeULL),
	BPF_ALU64_REG(BPF_MUL, BPF_REG_3, BPF_REG_1),
	BPF_JMP_REG(BPF_JEQ, BPF_REG_3, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	BPF_LD_IMM64(BPF_REG_3, 0xfefefeULL),
	BPF_ALU64_IMM(BPF_MUL, BPF_REG_3, 0xefefef),
	BPF_JMP_REG(BPF_JEQ, BPF_REG_3, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	BPF_MOV32_REG(BPF_REG_2, BPF_REG_2),
	BPF_LD_IMM64(BPF_REG_0, 0xfefefeULL),
	BPF_ALU32_REG(BPF_MUL, BPF_REG_0, BPF_REG_1),
	BPF_JMP_REG(BPF_JEQ, BPF_REG_0, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	BPF_LD_IMM64(BPF_REG_3, 0xfefefeULL),
	BPF_ALU32_REG(BPF_MUL, BPF_REG_3, BPF_REG_1),
	BPF_JMP_REG(BPF_JEQ, BPF_REG_3, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	BPF_LD_IMM64(BPF_REG_3, 0xfefefeULL),
	BPF_ALU32_IMM(BPF_MUL, BPF_REG_3, 0xefefef),
	BPF_JMP_REG(BPF_JEQ, BPF_REG_3, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	BPF_LD_IMM64(BPF_REG_0, 0xfefefeULL),
	BPF_LD_IMM64(BPF_REG_2, 0x2ad4d4aaULL),
	BPF_ALU32_IMM(BPF_MUL, BPF_REG_0, 0x2b),
	BPF_JMP_REG(BPF_JEQ, BPF_REG_0, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	BPF_LD_IMM64(BPF_REG_0, 0x952a7bbcULL),
	BPF_LD_IMM64(BPF_REG_1, 0xfefefeULL),
	BPF_LD_IMM64(BPF_REG_5, 0xeeff0d413122ULL),
	BPF_ALU32_REG(BPF_MUL, BPF_REG_5, BPF_REG_1),
	BPF_JMP_REG(BPF_JEQ, BPF_REG_5, BPF_REG_0, 2),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 2,
},
{
	"jit: various div tests",
	.insns = {
	BPF_LD_IMM64(BPF_REG_2, 0xefeffeULL),
	BPF_LD_IMM64(BPF_REG_0, 0xeeff0d413122ULL),
	BPF_LD_IMM64(BPF_REG_1, 0xfefeeeULL),
	BPF_ALU64_REG(BPF_DIV, BPF_REG_0, BPF_REG_1),
	BPF_JMP_REG(BPF_JEQ, BPF_REG_0, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	BPF_LD_IMM64(BPF_REG_3, 0xeeff0d413122ULL),
	BPF_ALU64_IMM(BPF_DIV, BPF_REG_3, 0xfefeeeULL),
	BPF_JMP_REG(BPF_JEQ, BPF_REG_3, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	BPF_LD_IMM64(BPF_REG_2, 0xaa93ULL),
	BPF_ALU64_IMM(BPF_MOD, BPF_REG_1, 0xbeefULL),
	BPF_JMP_REG(BPF_JEQ, BPF_REG_1, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	BPF_LD_IMM64(BPF_REG_1, 0xfefeeeULL),
	BPF_LD_IMM64(BPF_REG_3, 0xbeefULL),
	BPF_ALU64_REG(BPF_MOD, BPF_REG_1, BPF_REG_3),
	BPF_JMP_REG(BPF_JEQ, BPF_REG_1, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	BPF_LD_IMM64(BPF_REG_2, 0x5ee1dULL),
	BPF_LD_IMM64(BPF_REG_1, 0xfefeeeULL),
	BPF_LD_IMM64(BPF_REG_3, 0x2bULL),
	BPF_ALU32_REG(BPF_DIV, BPF_REG_1, BPF_REG_3),
	BPF_JMP_REG(BPF_JEQ, BPF_REG_1, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	BPF_ALU32_REG(BPF_DIV, BPF_REG_1, BPF_REG_1),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 1, 2),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	BPF_ALU64_REG(BPF_MOD, BPF_REG_2, BPF_REG_2),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_2, 0, 2),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 2,
},
{
	"jit: jsgt, jslt",
	.insns = {
	BPF_LD_IMM64(BPF_REG_1, 0x80000000ULL),
	BPF_LD_IMM64(BPF_REG_2, 0x0ULL),
	BPF_JMP_REG(BPF_JSGT, BPF_REG_1, BPF_REG_2, 2),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),

	BPF_JMP_REG(BPF_JSLT, BPF_REG_2, BPF_REG_1, 2),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),

	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 2,
},
{
	"jit: torturous jumps, imm8 nop jmp and pure jump padding",
	.insns = { },
	.fill_helper = bpf_fill_torturous_jumps,
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.retval = 1,
},
{
	"jit: torturous jumps, imm32 nop jmp and jmp_cond padding",
	.insns = { },
	.fill_helper = bpf_fill_torturous_jumps,
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.retval = 2,
},
{
	"jit: torturous jumps in subprog",
	.insns = { },
	.fill_helper = bpf_fill_torturous_jumps,
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.retval = 3,
},
