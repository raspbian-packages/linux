/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Traceprobe fetch helper inlines
 */

static nokprobe_inline void
fetch_store_raw(unsigned long val, struct fetch_insn *code, void *buf)
{
	switch (code->size) {
	case 1:
		*(u8 *)buf = (u8)val;
		break;
	case 2:
		*(u16 *)buf = (u16)val;
		break;
	case 4:
		*(u32 *)buf = (u32)val;
		break;
	case 8:
		//TBD: 32bit signed
		*(u64 *)buf = (u64)val;
		break;
	default:
		*(unsigned long *)buf = val;
	}
}

static nokprobe_inline void
fetch_apply_bitfield(struct fetch_insn *code, void *buf)
{
	switch (code->basesize) {
	case 1:
		*(u8 *)buf <<= code->lshift;
		*(u8 *)buf >>= code->rshift;
		break;
	case 2:
		*(u16 *)buf <<= code->lshift;
		*(u16 *)buf >>= code->rshift;
		break;
	case 4:
		*(u32 *)buf <<= code->lshift;
		*(u32 *)buf >>= code->rshift;
		break;
	case 8:
		*(u64 *)buf <<= code->lshift;
		*(u64 *)buf >>= code->rshift;
		break;
	}
}

/*
 * These functions must be defined for each callsite.
 * Return consumed dynamic data size (>= 0), or error (< 0).
 * If dest is NULL, don't store result and return required dynamic data size.
 */
static int
process_fetch_insn(struct fetch_insn *code, void *rec,
		   void *dest, void *base);
static nokprobe_inline int fetch_store_strlen(unsigned long addr);
static nokprobe_inline int
fetch_store_string(unsigned long addr, void *dest, void *base);
static nokprobe_inline int fetch_store_strlen_user(unsigned long addr);
static nokprobe_inline int
fetch_store_string_user(unsigned long addr, void *dest, void *base);
static nokprobe_inline int
probe_mem_read(void *dest, void *src, size_t size);
static nokprobe_inline int
probe_mem_read_user(void *dest, void *src, size_t size);

static nokprobe_inline int
fetch_store_symstrlen(unsigned long addr)
{
	char namebuf[KSYM_SYMBOL_LEN];
	int ret;

	ret = sprint_symbol(namebuf, addr);
	if (ret < 0)
		return 0;

	return ret + 1;
}

/*
 * Fetch a null-terminated symbol string + offset. Caller MUST set *(u32 *)buf
 * with max length and relative data location.
 */
static nokprobe_inline int
fetch_store_symstring(unsigned long addr, void *dest, void *base)
{
	int maxlen = get_loc_len(*(u32 *)dest);
	void *__dest;

	if (unlikely(!maxlen))
		return -ENOMEM;

	__dest = get_loc_data(dest, base);

	return sprint_symbol(__dest, addr);
}

/* common part of process_fetch_insn*/
static nokprobe_inline int
process_common_fetch_insn(struct fetch_insn *code, unsigned long *val)
{
	switch (code->op) {
	case FETCH_OP_IMM:
		*val = code->immediate;
		break;
	case FETCH_OP_COMM:
		*val = (unsigned long)current->comm;
		break;
	case FETCH_OP_DATA:
		*val = (unsigned long)code->data;
		break;
	default:
		return -EILSEQ;
	}
	return 0;
}

/* From the 2nd stage, routine is same */
static nokprobe_inline int
process_fetch_insn_bottom(struct fetch_insn *code, unsigned long val,
			   void *dest, void *base)
{
	struct fetch_insn *s3 = NULL;
	int total = 0, ret = 0, i = 0;
	u32 loc = 0;
	unsigned long lval = val;

stage2:
	/* 2nd stage: dereference memory if needed */
	do {
		if (code->op == FETCH_OP_DEREF) {
			lval = val;
			ret = probe_mem_read(&val, (void *)val + code->offset,
					     sizeof(val));
		} else if (code->op == FETCH_OP_UDEREF) {
			lval = val;
			ret = probe_mem_read_user(&val,
				 (void *)val + code->offset, sizeof(val));
		} else
			break;
		if (ret)
			return ret;
		code++;
	} while (1);

	s3 = code;
stage3:
	/* 3rd stage: store value to buffer */
	if (unlikely(!dest)) {
		switch (code->op) {
		case FETCH_OP_ST_STRING:
			ret = fetch_store_strlen(val + code->offset);
			code++;
			goto array;
		case FETCH_OP_ST_USTRING:
			ret = fetch_store_strlen_user(val + code->offset);
			code++;
			goto array;
		case FETCH_OP_ST_SYMSTR:
			ret = fetch_store_symstrlen(val + code->offset);
			code++;
			goto array;
		default:
			return -EILSEQ;
		}
	}

	switch (code->op) {
	case FETCH_OP_ST_RAW:
		fetch_store_raw(val, code, dest);
		break;
	case FETCH_OP_ST_MEM:
		probe_mem_read(dest, (void *)val + code->offset, code->size);
		break;
	case FETCH_OP_ST_UMEM:
		probe_mem_read_user(dest, (void *)val + code->offset, code->size);
		break;
	case FETCH_OP_ST_STRING:
		loc = *(u32 *)dest;
		ret = fetch_store_string(val + code->offset, dest, base);
		break;
	case FETCH_OP_ST_USTRING:
		loc = *(u32 *)dest;
		ret = fetch_store_string_user(val + code->offset, dest, base);
		break;
	case FETCH_OP_ST_SYMSTR:
		loc = *(u32 *)dest;
		ret = fetch_store_symstring(val + code->offset, dest, base);
		break;
	default:
		return -EILSEQ;
	}
	code++;

	/* 4th stage: modify stored value if needed */
	if (code->op == FETCH_OP_MOD_BF) {
		fetch_apply_bitfield(code, dest);
		code++;
	}

array:
	/* the last stage: Loop on array */
	if (code->op == FETCH_OP_LP_ARRAY) {
		if (ret < 0)
			ret = 0;
		total += ret;
		if (++i < code->param) {
			code = s3;
			if (s3->op != FETCH_OP_ST_STRING &&
			    s3->op != FETCH_OP_ST_USTRING) {
				dest += s3->size;
				val += s3->size;
				goto stage3;
			}
			code--;
			val = lval + sizeof(char *);
			if (dest) {
				dest += sizeof(u32);
				*(u32 *)dest = update_data_loc(loc, ret);
			}
			goto stage2;
		}
		code++;
		ret = total;
	}

	return code->op == FETCH_OP_END ? ret : -EILSEQ;
}

/* Sum up total data length for dynamic arrays (strings) */
static nokprobe_inline int
__get_data_size(struct trace_probe *tp, struct pt_regs *regs)
{
	struct probe_arg *arg;
	int i, len, ret = 0;

	for (i = 0; i < tp->nr_args; i++) {
		arg = tp->args + i;
		if (unlikely(arg->dynamic)) {
			len = process_fetch_insn(arg->code, regs, NULL, NULL);
			if (len > 0)
				ret += len;
		}
	}

	return ret;
}

/* Store the value of each argument */
static nokprobe_inline void
store_trace_args(void *data, struct trace_probe *tp, void *rec,
		 int header_size, int maxlen)
{
	struct probe_arg *arg;
	void *base = data - header_size;
	void *dyndata = data + tp->size;
	u32 *dl;	/* Data location */
	int ret, i;

	for (i = 0; i < tp->nr_args; i++) {
		arg = tp->args + i;
		dl = data + arg->offset;
		/* Point the dynamic data area if needed */
		if (unlikely(arg->dynamic))
			*dl = make_data_loc(maxlen, dyndata - base);
		ret = process_fetch_insn(arg->code, rec, dl, base);
		if (arg->dynamic && likely(ret > 0)) {
			dyndata += ret;
			maxlen -= ret;
		}
	}
}
