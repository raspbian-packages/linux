{
	"add+sub+mul",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_1, 1),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 2),
	BPF_MOV64_IMM(BPF_REG_2, 3),
	BPF_ALU64_REG(BPF_SUB, BPF_REG_1, BPF_REG_2),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -1),
	BPF_ALU64_IMM(BPF_MUL, BPF_REG_1, 3),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = -3,
},
{
	"xor32 zero extend check",
	.insns = {
	BPF_MOV32_IMM(BPF_REG_2, -1),
	BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 32),
	BPF_ALU64_IMM(BPF_OR, BPF_REG_2, 0xffff),
	BPF_ALU32_REG(BPF_XOR, BPF_REG_2, BPF_REG_2),
	BPF_MOV32_IMM(BPF_REG_0, 2),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_2, 0, 1),
	BPF_MOV32_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.retval = 1,
},
{
	"arsh32 on imm",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_ALU32_IMM(BPF_ARSH, BPF_REG_0, 5),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 0,
},
{
	"arsh32 on imm 2",
	.insns = {
	BPF_LD_IMM64(BPF_REG_0, 0x1122334485667788),
	BPF_ALU32_IMM(BPF_ARSH, BPF_REG_0, 7),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = -16069393,
},
{
	"arsh32 on reg",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_MOV64_IMM(BPF_REG_1, 5),
	BPF_ALU32_REG(BPF_ARSH, BPF_REG_0, BPF_REG_1),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 0,
},
{
	"arsh32 on reg 2",
	.insns = {
	BPF_LD_IMM64(BPF_REG_0, 0xffff55667788),
	BPF_MOV64_IMM(BPF_REG_1, 15),
	BPF_ALU32_REG(BPF_ARSH, BPF_REG_0, BPF_REG_1),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 43724,
},
{
	"arsh64 on imm",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_ALU64_IMM(BPF_ARSH, BPF_REG_0, 5),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"arsh64 on reg",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_MOV64_IMM(BPF_REG_1, 5),
	BPF_ALU64_REG(BPF_ARSH, BPF_REG_0, BPF_REG_1),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"lsh64 by 0 imm",
	.insns = {
	BPF_LD_IMM64(BPF_REG_0, 1),
	BPF_LD_IMM64(BPF_REG_1, 1),
	BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 0),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 1, 1),
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 1,
},
{
	"rsh64 by 0 imm",
	.insns = {
	BPF_LD_IMM64(BPF_REG_0, 1),
	BPF_LD_IMM64(BPF_REG_1, 0x100000000LL),
	BPF_ALU64_REG(BPF_MOV, BPF_REG_2, BPF_REG_1),
	BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 0),
	BPF_JMP_REG(BPF_JEQ, BPF_REG_1, BPF_REG_2, 1),
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 1,
},
{
	"arsh64 by 0 imm",
	.insns = {
	BPF_LD_IMM64(BPF_REG_0, 1),
	BPF_LD_IMM64(BPF_REG_1, 0x100000000LL),
	BPF_ALU64_REG(BPF_MOV, BPF_REG_2, BPF_REG_1),
	BPF_ALU64_IMM(BPF_ARSH, BPF_REG_1, 0),
	BPF_JMP_REG(BPF_JEQ, BPF_REG_1, BPF_REG_2, 1),
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 1,
},
{
	"lsh64 by 0 reg",
	.insns = {
	BPF_LD_IMM64(BPF_REG_0, 1),
	BPF_LD_IMM64(BPF_REG_1, 1),
	BPF_LD_IMM64(BPF_REG_2, 0),
	BPF_ALU64_REG(BPF_LSH, BPF_REG_1, BPF_REG_2),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 1, 1),
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 1,
},
{
	"rsh64 by 0 reg",
	.insns = {
	BPF_LD_IMM64(BPF_REG_0, 1),
	BPF_LD_IMM64(BPF_REG_1, 0x100000000LL),
	BPF_ALU64_REG(BPF_MOV, BPF_REG_2, BPF_REG_1),
	BPF_LD_IMM64(BPF_REG_3, 0),
	BPF_ALU64_REG(BPF_RSH, BPF_REG_1, BPF_REG_3),
	BPF_JMP_REG(BPF_JEQ, BPF_REG_1, BPF_REG_2, 1),
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 1,
},
{
	"arsh64 by 0 reg",
	.insns = {
	BPF_LD_IMM64(BPF_REG_0, 1),
	BPF_LD_IMM64(BPF_REG_1, 0x100000000LL),
	BPF_ALU64_REG(BPF_MOV, BPF_REG_2, BPF_REG_1),
	BPF_LD_IMM64(BPF_REG_3, 0),
	BPF_ALU64_REG(BPF_ARSH, BPF_REG_1, BPF_REG_3),
	BPF_JMP_REG(BPF_JEQ, BPF_REG_1, BPF_REG_2, 1),
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 1,
},
{
	"invalid 64-bit BPF_END",
	.insns = {
	BPF_MOV32_IMM(BPF_REG_0, 0),
	{
		.code  = BPF_ALU64 | BPF_END | BPF_TO_LE,
		.dst_reg = BPF_REG_0,
		.src_reg = 0,
		.off   = 0,
		.imm   = 32,
	},
	BPF_EXIT_INSN(),
	},
	.errstr = "unknown opcode d7",
	.result = REJECT,
},
{
	"mov64 src == dst",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_2),
	// Check bounds are OK
	BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
},
{
	"mov64 src != dst",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_3),
	// Check bounds are OK
	BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
},
