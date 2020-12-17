{
	"invalid direct packet write for LWT_IN",
	.insns = {
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
		    offsetof(struct __sk_buff, data)),
	BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
		    offsetof(struct __sk_buff, data_end)),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 8),
	BPF_JMP_REG(BPF_JGT, BPF_REG_0, BPF_REG_3, 1),
	BPF_STX_MEM(BPF_B, BPF_REG_2, BPF_REG_2, 0),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.errstr = "cannot write into packet",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_LWT_IN,
},
{
	"invalid direct packet write for LWT_OUT",
	.insns = {
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
		    offsetof(struct __sk_buff, data)),
	BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
		    offsetof(struct __sk_buff, data_end)),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 8),
	BPF_JMP_REG(BPF_JGT, BPF_REG_0, BPF_REG_3, 1),
	BPF_STX_MEM(BPF_B, BPF_REG_2, BPF_REG_2, 0),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.errstr = "cannot write into packet",
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_LWT_OUT,
},
{
	"direct packet write for LWT_XMIT",
	.insns = {
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
		    offsetof(struct __sk_buff, data)),
	BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
		    offsetof(struct __sk_buff, data_end)),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 8),
	BPF_JMP_REG(BPF_JGT, BPF_REG_0, BPF_REG_3, 1),
	BPF_STX_MEM(BPF_B, BPF_REG_2, BPF_REG_2, 0),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_LWT_XMIT,
},
{
	"direct packet read for LWT_IN",
	.insns = {
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
		    offsetof(struct __sk_buff, data)),
	BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
		    offsetof(struct __sk_buff, data_end)),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 8),
	BPF_JMP_REG(BPF_JGT, BPF_REG_0, BPF_REG_3, 1),
	BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_2, 0),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_LWT_IN,
},
{
	"direct packet read for LWT_OUT",
	.insns = {
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
		    offsetof(struct __sk_buff, data)),
	BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
		    offsetof(struct __sk_buff, data_end)),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 8),
	BPF_JMP_REG(BPF_JGT, BPF_REG_0, BPF_REG_3, 1),
	BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_2, 0),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_LWT_OUT,
},
{
	"direct packet read for LWT_XMIT",
	.insns = {
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
		    offsetof(struct __sk_buff, data)),
	BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
		    offsetof(struct __sk_buff, data_end)),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 8),
	BPF_JMP_REG(BPF_JGT, BPF_REG_0, BPF_REG_3, 1),
	BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_2, 0),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_LWT_XMIT,
},
{
	"overlapping checks for direct packet access",
	.insns = {
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
		    offsetof(struct __sk_buff, data)),
	BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
		    offsetof(struct __sk_buff, data_end)),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 8),
	BPF_JMP_REG(BPF_JGT, BPF_REG_0, BPF_REG_3, 4),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_2),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 6),
	BPF_JMP_REG(BPF_JGT, BPF_REG_1, BPF_REG_3, 1),
	BPF_LDX_MEM(BPF_H, BPF_REG_0, BPF_REG_2, 6),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_LWT_XMIT,
},
{
	"make headroom for LWT_XMIT",
	.insns = {
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
	BPF_MOV64_IMM(BPF_REG_2, 34),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_skb_change_head),
	/* split for s390 to succeed */
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_MOV64_IMM(BPF_REG_2, 42),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_skb_change_head),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_LWT_XMIT,
},
{
	"invalid access of tc_classid for LWT_IN",
	.insns = {
	BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
		    offsetof(struct __sk_buff, tc_classid)),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "invalid bpf_context access",
},
{
	"invalid access of tc_classid for LWT_OUT",
	.insns = {
	BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
		    offsetof(struct __sk_buff, tc_classid)),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "invalid bpf_context access",
},
{
	"invalid access of tc_classid for LWT_XMIT",
	.insns = {
	BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
		    offsetof(struct __sk_buff, tc_classid)),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "invalid bpf_context access",
},
{
	"check skb->tc_classid half load not permitted for lwt prog",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 0),
#if __BYTE_ORDER == __LITTLE_ENDIAN
	BPF_LDX_MEM(BPF_H, BPF_REG_0, BPF_REG_1,
		    offsetof(struct __sk_buff, tc_classid)),
#else
	BPF_LDX_MEM(BPF_H, BPF_REG_0, BPF_REG_1,
		    offsetof(struct __sk_buff, tc_classid) + 2),
#endif
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "invalid bpf_context access",
	.prog_type = BPF_PROG_TYPE_LWT_IN,
},
