{
	"reference tracking: leak potential reference",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0), /* leak reference */
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "Unreleased reference",
	.result = REJECT,
},
{
	"reference tracking: leak potential reference to sock_common",
	.insns = {
	BPF_SK_LOOKUP(skc_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0), /* leak reference */
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "Unreleased reference",
	.result = REJECT,
},
{
	"reference tracking: leak potential reference on stack",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_4, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, -8),
	BPF_STX_MEM(BPF_DW, BPF_REG_4, BPF_REG_0, 0),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "Unreleased reference",
	.result = REJECT,
},
{
	"reference tracking: leak potential reference on stack 2",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_4, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, -8),
	BPF_STX_MEM(BPF_DW, BPF_REG_4, BPF_REG_0, 0),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_ST_MEM(BPF_DW, BPF_REG_4, 0, 0),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "Unreleased reference",
	.result = REJECT,
},
{
	"reference tracking: zero potential reference",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_IMM(BPF_REG_0, 0), /* leak reference */
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "Unreleased reference",
	.result = REJECT,
},
{
	"reference tracking: zero potential reference to sock_common",
	.insns = {
	BPF_SK_LOOKUP(skc_lookup_tcp),
	BPF_MOV64_IMM(BPF_REG_0, 0), /* leak reference */
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "Unreleased reference",
	.result = REJECT,
},
{
	"reference tracking: copy and zero potential references",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_MOV64_IMM(BPF_REG_7, 0), /* leak reference */
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "Unreleased reference",
	.result = REJECT,
},
{
	"reference tracking: release reference without check",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	/* reference in r0 may be NULL */
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "type=sock_or_null expected=sock",
	.result = REJECT,
},
{
	"reference tracking: release reference to sock_common without check",
	.insns = {
	BPF_SK_LOOKUP(skc_lookup_tcp),
	/* reference in r0 may be NULL */
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "type=sock_common_or_null expected=sock",
	.result = REJECT,
},
{
	"reference tracking: release reference",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
},
{
	"reference tracking: release reference to sock_common",
	.insns = {
	BPF_SK_LOOKUP(skc_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
},
{
	"reference tracking: release reference 2",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
	BPF_EXIT_INSN(),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
},
{
	"reference tracking: release reference twice",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "type=inv expected=sock",
	.result = REJECT,
},
{
	"reference tracking: release reference twice inside branch",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 3), /* goto end */
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "type=inv expected=sock",
	.result = REJECT,
},
{
	"reference tracking: alloc, check, free in one subbranch",
	.insns = {
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
		    offsetof(struct __sk_buff, data)),
	BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
		    offsetof(struct __sk_buff, data_end)),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 16),
	/* if (offsetof(skb, mark) > data_len) exit; */
	BPF_JMP_REG(BPF_JLE, BPF_REG_0, BPF_REG_3, 1),
	BPF_EXIT_INSN(),
	BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_2,
		    offsetof(struct __sk_buff, mark)),
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, 0, 1), /* mark == 0? */
	/* Leak reference in R0 */
	BPF_EXIT_INSN(),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2), /* sk NULL? */
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "Unreleased reference",
	.result = REJECT,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"reference tracking: alloc, check, free in both subbranches",
	.insns = {
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
		    offsetof(struct __sk_buff, data)),
	BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
		    offsetof(struct __sk_buff, data_end)),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 16),
	/* if (offsetof(skb, mark) > data_len) exit; */
	BPF_JMP_REG(BPF_JLE, BPF_REG_0, BPF_REG_3, 1),
	BPF_EXIT_INSN(),
	BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_2,
		    offsetof(struct __sk_buff, mark)),
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, 0, 4), /* mark == 0? */
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2), /* sk NULL? */
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2), /* sk NULL? */
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"reference tracking in call: free reference in subprog",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0), /* unchecked reference */
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 1, 0, 2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),

	/* subprog 1 */
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_1),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_2, 0, 1),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
},
{
	"reference tracking in call: free reference in subprog and outside",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0), /* unchecked reference */
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 1, 0, 3),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),

	/* subprog 1 */
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_1),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_2, 0, 1),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "type=inv expected=sock",
	.result = REJECT,
},
{
	"reference tracking in call: alloc & leak reference in subprog",
	.insns = {
	BPF_MOV64_REG(BPF_REG_4, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, -8),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 1, 0, 3),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),

	/* subprog 1 */
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_4),
	BPF_SK_LOOKUP(sk_lookup_tcp),
	/* spill unchecked sk_ptr into stack of caller */
	BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "Unreleased reference",
	.result = REJECT,
},
{
	"reference tracking in call: alloc in subprog, release outside",
	.insns = {
	BPF_MOV64_REG(BPF_REG_4, BPF_REG_10),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 1, 0, 4),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),

	/* subprog 1 */
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_EXIT_INSN(), /* return sk */
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.retval = POINTER_VALUE,
	.result = ACCEPT,
},
{
	"reference tracking in call: sk_ptr leak into caller stack",
	.insns = {
	BPF_MOV64_REG(BPF_REG_4, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, -8),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 1, 0, 2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),

	/* subprog 1 */
	BPF_MOV64_REG(BPF_REG_5, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_5, -8),
	BPF_STX_MEM(BPF_DW, BPF_REG_5, BPF_REG_4, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 1, 0, 5),
	/* spill unchecked sk_ptr into stack of caller */
	BPF_MOV64_REG(BPF_REG_5, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_5, -8),
	BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_5, 0),
	BPF_STX_MEM(BPF_DW, BPF_REG_4, BPF_REG_0, 0),
	BPF_EXIT_INSN(),

	/* subprog 2 */
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "Unreleased reference",
	.result = REJECT,
},
{
	"reference tracking in call: sk_ptr spill into caller stack",
	.insns = {
	BPF_MOV64_REG(BPF_REG_4, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, -8),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 1, 0, 2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),

	/* subprog 1 */
	BPF_MOV64_REG(BPF_REG_5, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_5, -8),
	BPF_STX_MEM(BPF_DW, BPF_REG_5, BPF_REG_4, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 1, 0, 8),
	/* spill unchecked sk_ptr into stack of caller */
	BPF_MOV64_REG(BPF_REG_5, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_5, -8),
	BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_5, 0),
	BPF_STX_MEM(BPF_DW, BPF_REG_4, BPF_REG_0, 0),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
	/* now the sk_ptr is verified, free the reference */
	BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_4, 0),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),

	/* subprog 2 */
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
},
{
	"reference tracking: allow LD_ABS",
	.insns = {
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_LD_ABS(BPF_B, 0),
	BPF_LD_ABS(BPF_H, 0),
	BPF_LD_ABS(BPF_W, 0),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
},
{
	"reference tracking: forbid LD_ABS while holding reference",
	.insns = {
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_LD_ABS(BPF_B, 0),
	BPF_LD_ABS(BPF_H, 0),
	BPF_LD_ABS(BPF_W, 0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "BPF_LD_[ABS|IND] cannot be mixed with socket references",
	.result = REJECT,
},
{
	"reference tracking: allow LD_IND",
	.insns = {
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_MOV64_IMM(BPF_REG_7, 1),
	BPF_LD_IND(BPF_W, BPF_REG_7, -0x200000),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_7),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.retval = 1,
},
{
	"reference tracking: forbid LD_IND while holding reference",
	.insns = {
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_4, BPF_REG_0),
	BPF_MOV64_IMM(BPF_REG_7, 1),
	BPF_LD_IND(BPF_W, BPF_REG_7, -0x200000),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_7),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_4),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 1),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "BPF_LD_[ABS|IND] cannot be mixed with socket references",
	.result = REJECT,
},
{
	"reference tracking: check reference or tail call",
	.insns = {
	BPF_MOV64_REG(BPF_REG_7, BPF_REG_1),
	BPF_SK_LOOKUP(sk_lookup_tcp),
	/* if (sk) bpf_sk_release() */
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_1, 0, 7),
	/* bpf_tail_call() */
	BPF_MOV64_IMM(BPF_REG_3, 3),
	BPF_LD_MAP_FD(BPF_REG_2, 0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_7),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_tail_call),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.fixup_prog1 = { 17 },
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
},
{
	"reference tracking: release reference then tail call",
	.insns = {
	BPF_MOV64_REG(BPF_REG_7, BPF_REG_1),
	BPF_SK_LOOKUP(sk_lookup_tcp),
	/* if (sk) bpf_sk_release() */
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 1),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	/* bpf_tail_call() */
	BPF_MOV64_IMM(BPF_REG_3, 3),
	BPF_LD_MAP_FD(BPF_REG_2, 0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_7),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_tail_call),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_prog1 = { 18 },
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
},
{
	"reference tracking: leak possible reference over tail call",
	.insns = {
	BPF_MOV64_REG(BPF_REG_7, BPF_REG_1),
	/* Look up socket and store in REG_6 */
	BPF_SK_LOOKUP(sk_lookup_tcp),
	/* bpf_tail_call() */
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_MOV64_IMM(BPF_REG_3, 3),
	BPF_LD_MAP_FD(BPF_REG_2, 0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_7),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_tail_call),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	/* if (sk) bpf_sk_release() */
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 1),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.fixup_prog1 = { 16 },
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "tail_call would lead to reference leak",
	.result = REJECT,
},
{
	"reference tracking: leak checked reference over tail call",
	.insns = {
	BPF_MOV64_REG(BPF_REG_7, BPF_REG_1),
	/* Look up socket and store in REG_6 */
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	/* if (!sk) goto end */
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 7),
	/* bpf_tail_call() */
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_LD_MAP_FD(BPF_REG_2, 0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_7),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_tail_call),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.fixup_prog1 = { 17 },
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "tail_call would lead to reference leak",
	.result = REJECT,
},
{
	"reference tracking: mangle and release sock_or_null",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 5),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "R1 pointer arithmetic on sock_or_null prohibited",
	.result = REJECT,
},
{
	"reference tracking: mangle and release sock",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 5),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "R1 pointer arithmetic on sock prohibited",
	.result = REJECT,
},
{
	"reference tracking: access member",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 3),
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_0, 4),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
},
{
	"reference tracking: write to member",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 5),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_LD_IMM64(BPF_REG_2, 42),
	BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_2,
		    offsetof(struct bpf_sock, mark)),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_LD_IMM64(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "cannot write into sock",
	.result = REJECT,
},
{
	"reference tracking: invalid 64-bit access of member",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 3),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_0, 0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "invalid sock access off=0 size=8",
	.result = REJECT,
},
{
	"reference tracking: access after release",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, 0),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "!read_ok",
	.result = REJECT,
},
{
	"reference tracking: direct access for lookup",
	.insns = {
	/* Check that the packet is at least 64B long */
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
		    offsetof(struct __sk_buff, data)),
	BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
		    offsetof(struct __sk_buff, data_end)),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 64),
	BPF_JMP_REG(BPF_JGT, BPF_REG_0, BPF_REG_3, 9),
	/* sk = sk_lookup_tcp(ctx, skb->data, ...) */
	BPF_MOV64_IMM(BPF_REG_3, sizeof(struct bpf_sock_tuple)),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_MOV64_IMM(BPF_REG_5, 0),
	BPF_EMIT_CALL(BPF_FUNC_sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 3),
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_0, 4),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
},
{
	"reference tracking: use ptr from bpf_tcp_sock() after release",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_tcp_sock),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 3),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_7, offsetof(struct bpf_tcp_sock, snd_cwnd)),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = REJECT,
	.errstr = "invalid mem access",
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"reference tracking: use ptr from bpf_sk_fullsock() after release",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_sk_fullsock),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 3),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_7, offsetof(struct bpf_sock, type)),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = REJECT,
	.errstr = "invalid mem access",
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"reference tracking: use ptr from bpf_sk_fullsock(tp) after release",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_tcp_sock),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 3),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_sk_fullsock),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_6, 0, 1),
	BPF_EXIT_INSN(),
	BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_6, offsetof(struct bpf_sock, type)),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = REJECT,
	.errstr = "invalid mem access",
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"reference tracking: use sk after bpf_sk_release(tp)",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_tcp_sock),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 3),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_6, offsetof(struct bpf_sock, type)),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = REJECT,
	.errstr = "invalid mem access",
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"reference tracking: use ptr from bpf_get_listener_sock() after bpf_sk_release(sk)",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_get_listener_sock),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 3),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_6, offsetof(struct bpf_sock, src_port)),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
},
{
	"reference tracking: bpf_sk_release(listen_sk)",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_get_listener_sock),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 3),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_6, offsetof(struct bpf_sock, type)),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = REJECT,
	.errstr = "reference has not been acquired before",
},
{
	/* !bpf_sk_fullsock(sk) is checked but !bpf_tcp_sock(sk) is not checked */
	"reference tracking: tp->snd_cwnd after bpf_sk_fullsock(sk) and bpf_tcp_sock(sk)",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_sk_fullsock),
	BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_tcp_sock),
	BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_7, 0, 3),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_8, offsetof(struct bpf_tcp_sock, snd_cwnd)),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = REJECT,
	.errstr = "invalid mem access",
},
{
	"reference tracking: branch tracking valid pointer null comparison",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_MOV64_IMM(BPF_REG_3, 1),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_6, 0, 1),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, 0, 2),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
},
{
	"reference tracking: branch tracking valid pointer value comparison",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_MOV64_IMM(BPF_REG_3, 1),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, 0, 4),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, 1234, 2),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.errstr = "Unreleased reference",
	.result = REJECT,
},
{
	"reference tracking: bpf_sk_release(btf_tcp_sock)",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_skc_to_tcp_sock),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 3),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.result_unpriv = REJECT,
	.errstr_unpriv = "unknown func",
},
{
	"reference tracking: use ptr from bpf_skc_to_tcp_sock() after release",
	.insns = {
	BPF_SK_LOOKUP(sk_lookup_tcp),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_skc_to_tcp_sock),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 3),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_sk_release),
	BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_7, 0),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = REJECT,
	.errstr = "invalid mem access",
	.result_unpriv = REJECT,
	.errstr_unpriv = "unknown func",
},
