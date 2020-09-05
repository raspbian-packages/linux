{
	"valid cgroup storage access",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_local_storage),
	BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	},
	.fixup_cgroup_storage = { 1 },
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_CGROUP_SKB,
},
{
	"invalid cgroup storage access 1",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_local_storage),
	BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_8b = { 1 },
	.result = REJECT,
	.errstr = "cannot pass map_type 1 into func bpf_get_local_storage",
	.prog_type = BPF_PROG_TYPE_CGROUP_SKB,
},
{
	"invalid cgroup storage access 2",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 1),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_local_storage),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "fd 1 is not pointing to valid bpf_map",
	.prog_type = BPF_PROG_TYPE_CGROUP_SKB,
},
{
	"invalid cgroup storage access 3",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_local_storage),
	BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 256),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 1),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_cgroup_storage = { 1 },
	.result = REJECT,
	.errstr = "invalid access to map value, value_size=64 off=256 size=4",
	.prog_type = BPF_PROG_TYPE_CGROUP_SKB,
},
{
	"invalid cgroup storage access 4",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_local_storage),
	BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, -2),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 1),
	BPF_EXIT_INSN(),
	},
	.fixup_cgroup_storage = { 1 },
	.result = REJECT,
	.errstr = "invalid access to map value, value_size=64 off=-2 size=4",
	.prog_type = BPF_PROG_TYPE_CGROUP_SKB,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"invalid cgroup storage access 5",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 7),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_local_storage),
	BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	},
	.fixup_cgroup_storage = { 1 },
	.result = REJECT,
	.errstr = "get_local_storage() doesn't support non-zero flags",
	.prog_type = BPF_PROG_TYPE_CGROUP_SKB,
},
{
	"invalid cgroup storage access 6",
	.insns = {
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_1),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_local_storage),
	BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	},
	.fixup_cgroup_storage = { 1 },
	.result = REJECT,
	.errstr = "get_local_storage() doesn't support non-zero flags",
	.errstr_unpriv = "R2 leaks addr into helper function",
	.prog_type = BPF_PROG_TYPE_CGROUP_SKB,
},
{
	"valid per-cpu cgroup storage access",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_local_storage),
	BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	},
	.fixup_percpu_cgroup_storage = { 1 },
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_CGROUP_SKB,
},
{
	"invalid per-cpu cgroup storage access 1",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_local_storage),
	BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_8b = { 1 },
	.result = REJECT,
	.errstr = "cannot pass map_type 1 into func bpf_get_local_storage",
	.prog_type = BPF_PROG_TYPE_CGROUP_SKB,
},
{
	"invalid per-cpu cgroup storage access 2",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 1),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_local_storage),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "fd 1 is not pointing to valid bpf_map",
	.prog_type = BPF_PROG_TYPE_CGROUP_SKB,
},
{
	"invalid per-cpu cgroup storage access 3",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_local_storage),
	BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 256),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 1),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_percpu_cgroup_storage = { 1 },
	.result = REJECT,
	.errstr = "invalid access to map value, value_size=64 off=256 size=4",
	.prog_type = BPF_PROG_TYPE_CGROUP_SKB,
},
{
	"invalid per-cpu cgroup storage access 4",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_local_storage),
	BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, -2),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 1),
	BPF_EXIT_INSN(),
	},
	.fixup_cgroup_storage = { 1 },
	.result = REJECT,
	.errstr = "invalid access to map value, value_size=64 off=-2 size=4",
	.prog_type = BPF_PROG_TYPE_CGROUP_SKB,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"invalid per-cpu cgroup storage access 5",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 7),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_local_storage),
	BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	},
	.fixup_percpu_cgroup_storage = { 1 },
	.result = REJECT,
	.errstr = "get_local_storage() doesn't support non-zero flags",
	.prog_type = BPF_PROG_TYPE_CGROUP_SKB,
},
{
	"invalid per-cpu cgroup storage access 6",
	.insns = {
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_1),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_local_storage),
	BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	},
	.fixup_percpu_cgroup_storage = { 1 },
	.result = REJECT,
	.errstr = "get_local_storage() doesn't support non-zero flags",
	.errstr_unpriv = "R2 leaks addr into helper function",
	.prog_type = BPF_PROG_TYPE_CGROUP_SKB,
},
