uint32_t g98_sec_data[] = {
/* 0x0000: ctx_dma */
/* 0x0000: ctx_dma_query */
	0x00000000,
/* 0x0004: ctx_dma_src */
	0x00000000,
/* 0x0008: ctx_dma_dst */
	0x00000000,
/* 0x000c: ctx_query_address_high */
	0x00000000,
/* 0x0010: ctx_query_address_low */
	0x00000000,
/* 0x0014: ctx_query_counter */
	0x00000000,
/* 0x0018: ctx_cond_address_high */
	0x00000000,
/* 0x001c: ctx_cond_address_low */
	0x00000000,
/* 0x0020: ctx_cond_off */
	0x00000000,
/* 0x0024: ctx_src_address_high */
	0x00000000,
/* 0x0028: ctx_src_address_low */
	0x00000000,
/* 0x002c: ctx_dst_address_high */
	0x00000000,
/* 0x0030: ctx_dst_address_low */
	0x00000000,
/* 0x0034: ctx_mode */
	0x00000000,
	0x00000000,
	0x00000000,
/* 0x0040: ctx_key */
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
/* 0x0050: ctx_iv */
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
/* 0x0080: swap */
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
/* 0x00a0: common_cmd_dtable */
	0x0002000c,
	0xffffff00,
	0x00020010,
	0x0000000f,
	0x00020014,
	0x00000000,
	0x00000192,
	0xfffffffe,
	0x00020018,
	0xffffff00,
	0x0002001c,
	0x0000000f,
	0x000001d7,
	0xfffffff8,
	0x00000260,
	0xffffffff,
/* 0x00e0: engine_cmd_dtable */
	0x00020040,
	0x00000000,
	0x00020044,
	0x00000000,
	0x00020048,
	0x00000000,
	0x0002004c,
	0x00000000,
	0x00020050,
	0x00000000,
	0x00020054,
	0x00000000,
	0x00020058,
	0x00000000,
	0x0002005c,
	0x00000000,
	0x00020024,
	0xffffff00,
	0x00020028,
	0x0000000f,
	0x0002002c,
	0xffffff00,
	0x00020030,
	0x0000000f,
	0x00000271,
	0xfffffff0,
	0x00010285,
	0xf000000f,
/* 0x0150: sec_dtable */
	0x04db0321,
	0x04b1032f,
	0x04db0339,
	0x04db034b,
	0x04db0361,
	0x04db0377,
	0x04db0395,
	0x04db03af,
	0x04db03cd,
	0x04db03e3,
	0x04db03f9,
	0x04db040f,
	0x04830429,
	0x0483043b,
	0x0483045d,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
};

uint32_t g98_sec_code[] = {
	0x17f004bd,
	0x0010fe35,
	0xf10004fe,
	0xf0fff017,
	0x27f10013,
	0x21d00400,
	0x0c15f0c0,
	0xf00021d0,
	0x27f10317,
	0x21d01200,
	0x1031f400,
/* 0x002f: spin */
	0xf40031f4,
	0x0ef40028,
/* 0x0035: ih */
	0x8001cffd,
	0xb00812c4,
	0x0bf40024,
	0x0027f167,
	0x002bfe77,
	0xf00007fe,
	0x23f00027,
	0x0037f105,
	0x0034cf14,
	0xb0014594,
	0x18f40055,
	0x0602fa17,
	0x4af003f8,
	0x0034d01e,
	0xd00147f0,
	0x0ef48034,
/* 0x0075: ctxload */
	0x4034cf33,
	0xb0014f94,
	0x18f400f5,
	0x0502fa21,
	0x57f003f8,
	0x0267f000,
/* 0x008c: ctxload_dma_loop */
	0xa07856bc,
	0xb6018068,
	0x87d00884,
	0x0162b600,
/* 0x009f: dummyload */
	0xf0f018f4,
	0x35d00257,
/* 0x00a5: noctx */
	0x0412c480,
	0xf50024b0,
	0xf100df0b,
	0xcf190037,
	0x33cf4032,
	0xff24e400,
	0x1024b607,
	0x07bf45e4,
	0xf50054b0,
	0xf100b90b,
	0xf1fae057,
	0xb000ce67,
	0x18f4c044,
	0xa057f14d,
	0x8867f1fc,
	0x8044b000,
	0xb03f18f4,
	0x18f46044,
	0x5044b019,
	0xf1741bf4,
	0xbd220027,
	0x0233f034,
	0xf50023d0,
/* 0x0103: dma_cmd */
	0xb000810e,
	0x18f46344,
	0x0245945e,
	0xfe8050b7,
	0x801e39f0,
	0x40b70053,
	0x44b60120,
	0x0043d008,
/* 0x0123: dtable_cmd */
	0xb8600ef4,
	0x18f40446,
	0x0344b63e,
	0x980045bb,
	0x53fd0145,
	0x0054b004,
	0x58291bf4,
	0x46580045,
	0x0264b001,
	0x98170bf4,
	0x67fd0807,
	0x0164b004,
	0xf9300bf4,
	0x0f01f455,
/* 0x015b: cmd_setctx */
	0x80280ef4,
	0x0ef40053,
/* 0x0161: invalid_bitfield */
	0x0125f022,
/* 0x0164: dispatch_error */
/* 0x0164: illegal_mthd */
	0x100047f1,
	0xd00042d0,
	0x47f04043,
	0x0004d040,
/* 0x0174: im_loop */
	0xf08004cf,
	0x44b04044,
	0xf71bf400,
/* 0x0180: cmddone */
	0x1d0037f1,
	0xd00147f0,
/* 0x018a: nocmd */
	0x11c40034,
	0x4001d00c,
/* 0x0192: cmd_query_get */
	0x38f201f8,
	0x0325f001,
	0x0b0047f1,
/* 0x019c: ptimer_retry */
	0xcf4046cf,
	0x47cf0045,
	0x0467b840,
	0x98f41bf4,
	0x04800504,
	0x21008020,
	0x80220580,
	0x0bfe2306,
	0x03049800,
	0xfe1844b6,
	0x04980047,
	0x8057f104,
	0x0253f000,
	0xf80645fa,
/* 0x01d7: cmd_cond_mode */
	0xf400f803,
	0x25f00131,
	0x0534b002,
	0xf41218f4,
	0x34b00132,
	0x0b18f402,
	0x800136f0,
/* 0x01f2: return */
	0x00f80803,
/* 0x01f4: cmd_cond_mode_queryful */
	0x98060498,
	0x56c40705,
	0x0855b6ff,
	0xfd1844b6,
	0x47fe0545,
	0x000bfe00,
	0x008057f1,
	0xfa0253f0,
	0x34b00565,
	0x131bf402,
	0x049803f8,
	0x0044b021,
	0x800b4cf0,
	0x00f80804,
/* 0x022c: cmd_cond_mode_double */
	0xb61060b6,
	0x65fa1050,
	0x9803f805,
	0x06982005,
	0x0456b824,
	0x980b4cf0,
	0x06982105,
	0x0456b825,
	0xfd0b5cf0,
	0x34b00445,
	0x0b5cf003,
	0x800645fd,
	0x00f80804,
/* 0x0260: cmd_wrcache_flush */
	0xf10132f4,
	0xbd220027,
	0x0133f034,
	0xf80023d0,
/* 0x0271: sec_cmd_mode */
	0x0131f400,
	0xb00225f0,
	0x18f40f34,
	0x0132f409,
/* 0x0283: sec_cmd_mode_return */
	0xf80d0380,
/* 0x0285: sec_cmd_length */
	0x0034b000,
	0xf4fb0bf4,
	0x47f0033c,
	0x0743f040,
	0xf00604fa,
	0x43f05047,
	0x0604fa06,
	0x3cf503f8,
	0x47f1c407,
	0x4bfe2100,
	0x09049800,
	0x950a0598,
	0x44b60858,
	0x0548fd18,
	0x98ff55c4,
	0x07980b06,
	0x0878950c,
	0xfd1864b6,
	0x77c40568,
	0x0d0898ff,
	0x580284b6,
	0x95f9a889,
	0xf9a98958,
	0x013cf495,
	0x3cf403f8,
	0xf803f861,
	0x18489503,
	0xbb084994,
	0x81b60095,
	0x09088000,
	0x950a0980,
	0x69941868,
	0x0097bb08,
	0x800081b6,
	0x09800b08,
	0x023cf40c,
	0xf05047f0,
	0x04fa0643,
	0xf803f805,
/* 0x0321: sec_copy_prep */
	0x203cf500,
	0x003cf594,
	0x003cf588,
/* 0x032f: sec_store_prep */
	0xf500f88c,
	0xf594103c,
	0xf88c063c,
/* 0x0339: sec_ecb_e_prep */
	0x303cf500,
	0x003cf594,
	0x003cf588,
	0x003cf5d0,
/* 0x034b: sec_ecb_d_prep */
	0xf500f88c,
	0xf5c8773c,
	0xf594303c,
	0xf588003c,
	0xf5d4003c,
	0xf88c003c,
/* 0x0361: sec_cbc_e_prep */
	0x403cf500,
	0x003cf594,
	0x063cf588,
	0x663cf5ac,
	0x063cf5d0,
/* 0x0377: sec_cbc_d_prep */
	0xf500f88c,
	0xf5c8773c,
	0xf594503c,
	0xf584623c,
	0xf588063c,
	0xf5d4603c,
	0xf5ac203c,
	0xf88c003c,
/* 0x0395: sec_pcbc_e_prep */
	0x503cf500,
	0x003cf594,
	0x063cf588,
	0x663cf5ac,
	0x063cf5d0,
	0x063cf58c,
/* 0x03af: sec_pcbc_d_prep */
	0xf500f8ac,
	0xf5c8773c,
	0xf594503c,
	0xf588003c,
	0xf5d4013c,
	0xf5ac163c,
	0xf58c063c,
	0xf8ac063c,
/* 0x03cd: sec_cfb_e_prep */
	0x403cf500,
	0x663cf594,
	0x003cf5d0,
	0x063cf588,
	0x063cf5ac,
/* 0x03e3: sec_cfb_d_prep */
	0xf500f88c,
	0xf594403c,
	0xf5d0603c,
	0xf588063c,
	0xf5ac603c,
	0xf88c003c,
/* 0x03f9: sec_ofb_prep */
	0x403cf500,
	0x663cf594,
	0x003cf5d0,
	0x603cf588,
	0x003cf5ac,
/* 0x040f: sec_ctr_prep */
	0xf500f88c,
	0xf594503c,
	0xf5d0613c,
	0xf5b0163c,
	0xf588003c,
	0xf5ac103c,
	0xf88c003c,
/* 0x0429: sec_cbc_mac_prep */
	0x303cf500,
	0x003cf594,
	0x063cf588,
	0x663cf5ac,
/* 0x043b: sec_cmac_finish_complete_prep */
	0xf500f8d0,
	0xf594703c,
	0xf588003c,
	0xf5ac063c,
	0xf5ac003c,
	0xf5d0003c,
	0xf5bc003c,
	0xf5ac063c,
	0xf8d0663c,
/* 0x045d: sec_cmac_finish_partial_prep */
	0x803cf500,
	0x003cf594,
	0x063cf588,
	0x003cf5ac,
	0x003cf5ac,
	0x003cf5d0,
	0x003cf5bc,
	0x063cf5bc,
	0x663cf5ac,
/* 0x0483: sec_do_in */
	0xbb00f8d0,
	0x47fe0035,
	0x8097f100,
	0x0293f000,
/* 0x0490: sec_do_in_loop */
	0xf80559fa,
	0x223cf403,
	0xf50609fa,
	0xf898103c,
	0x1050b603,
	0xf40453b8,
	0x3cf4e91b,
	0xf803f801,
/* 0x04b1: sec_do_out */
	0x0037bb00,
	0xf10067fe,
	0xf0008097,
/* 0x04be: sec_do_out_loop */
	0x3cf50293,
	0x3cf49810,
	0x0579fa61,
	0xf40679fa,
	0x03f8013c,
	0xb81070b6,
	0x1bf40473,
/* 0x04db: sec_do_inout */
	0xbb00f8e8,
	0x97f10035,
	0x93f00080,
/* 0x04e5: sec_do_inout_loop */
	0x0047fe02,
	0xf80559fa,
	0x213cf403,
	0xf50609fa,
	0xf498103c,
	0x67fe613c,
	0x0579fa00,
	0xf40679fa,
	0x03f8013c,
	0xb61050b6,
	0x53b81070,
	0xd41bf404,
	0x000000f8,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
};
