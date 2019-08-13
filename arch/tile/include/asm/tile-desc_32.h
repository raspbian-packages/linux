/* TILEPro opcode information.
 *
 * Copyright 2011 Tilera Corporation. All Rights Reserved.
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation, version 2.
 *
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 *   NON INFRINGEMENT.  See the GNU General Public License for
 *   more details.
 *
 *
 *
 *
 *
 */

#ifndef opcode_tilepro_h
#define opcode_tilepro_h

#include <arch/opcode.h>


enum
{
  TILEPRO_MAX_OPERANDS = 5 /* mm */
};

typedef enum
{
  TILEPRO_OPC_BPT,
  TILEPRO_OPC_INFO,
  TILEPRO_OPC_INFOL,
  TILEPRO_OPC_J,
  TILEPRO_OPC_JAL,
  TILEPRO_OPC_MOVE,
  TILEPRO_OPC_MOVE_SN,
  TILEPRO_OPC_MOVEI,
  TILEPRO_OPC_MOVEI_SN,
  TILEPRO_OPC_MOVELI,
  TILEPRO_OPC_MOVELI_SN,
  TILEPRO_OPC_MOVELIS,
  TILEPRO_OPC_PREFETCH,
  TILEPRO_OPC_RAISE,
  TILEPRO_OPC_ADD,
  TILEPRO_OPC_ADD_SN,
  TILEPRO_OPC_ADDB,
  TILEPRO_OPC_ADDB_SN,
  TILEPRO_OPC_ADDBS_U,
  TILEPRO_OPC_ADDBS_U_SN,
  TILEPRO_OPC_ADDH,
  TILEPRO_OPC_ADDH_SN,
  TILEPRO_OPC_ADDHS,
  TILEPRO_OPC_ADDHS_SN,
  TILEPRO_OPC_ADDI,
  TILEPRO_OPC_ADDI_SN,
  TILEPRO_OPC_ADDIB,
  TILEPRO_OPC_ADDIB_SN,
  TILEPRO_OPC_ADDIH,
  TILEPRO_OPC_ADDIH_SN,
  TILEPRO_OPC_ADDLI,
  TILEPRO_OPC_ADDLI_SN,
  TILEPRO_OPC_ADDLIS,
  TILEPRO_OPC_ADDS,
  TILEPRO_OPC_ADDS_SN,
  TILEPRO_OPC_ADIFFB_U,
  TILEPRO_OPC_ADIFFB_U_SN,
  TILEPRO_OPC_ADIFFH,
  TILEPRO_OPC_ADIFFH_SN,
  TILEPRO_OPC_AND,
  TILEPRO_OPC_AND_SN,
  TILEPRO_OPC_ANDI,
  TILEPRO_OPC_ANDI_SN,
  TILEPRO_OPC_AULI,
  TILEPRO_OPC_AVGB_U,
  TILEPRO_OPC_AVGB_U_SN,
  TILEPRO_OPC_AVGH,
  TILEPRO_OPC_AVGH_SN,
  TILEPRO_OPC_BBNS,
  TILEPRO_OPC_BBNS_SN,
  TILEPRO_OPC_BBNST,
  TILEPRO_OPC_BBNST_SN,
  TILEPRO_OPC_BBS,
  TILEPRO_OPC_BBS_SN,
  TILEPRO_OPC_BBST,
  TILEPRO_OPC_BBST_SN,
  TILEPRO_OPC_BGEZ,
  TILEPRO_OPC_BGEZ_SN,
  TILEPRO_OPC_BGEZT,
  TILEPRO_OPC_BGEZT_SN,
  TILEPRO_OPC_BGZ,
  TILEPRO_OPC_BGZ_SN,
  TILEPRO_OPC_BGZT,
  TILEPRO_OPC_BGZT_SN,
  TILEPRO_OPC_BITX,
  TILEPRO_OPC_BITX_SN,
  TILEPRO_OPC_BLEZ,
  TILEPRO_OPC_BLEZ_SN,
  TILEPRO_OPC_BLEZT,
  TILEPRO_OPC_BLEZT_SN,
  TILEPRO_OPC_BLZ,
  TILEPRO_OPC_BLZ_SN,
  TILEPRO_OPC_BLZT,
  TILEPRO_OPC_BLZT_SN,
  TILEPRO_OPC_BNZ,
  TILEPRO_OPC_BNZ_SN,
  TILEPRO_OPC_BNZT,
  TILEPRO_OPC_BNZT_SN,
  TILEPRO_OPC_BYTEX,
  TILEPRO_OPC_BYTEX_SN,
  TILEPRO_OPC_BZ,
  TILEPRO_OPC_BZ_SN,
  TILEPRO_OPC_BZT,
  TILEPRO_OPC_BZT_SN,
  TILEPRO_OPC_CLZ,
  TILEPRO_OPC_CLZ_SN,
  TILEPRO_OPC_CRC32_32,
  TILEPRO_OPC_CRC32_32_SN,
  TILEPRO_OPC_CRC32_8,
  TILEPRO_OPC_CRC32_8_SN,
  TILEPRO_OPC_CTZ,
  TILEPRO_OPC_CTZ_SN,
  TILEPRO_OPC_DRAIN,
  TILEPRO_OPC_DTLBPR,
  TILEPRO_OPC_DWORD_ALIGN,
  TILEPRO_OPC_DWORD_ALIGN_SN,
  TILEPRO_OPC_FINV,
  TILEPRO_OPC_FLUSH,
  TILEPRO_OPC_FNOP,
  TILEPRO_OPC_ICOH,
  TILEPRO_OPC_ILL,
  TILEPRO_OPC_INTHB,
  TILEPRO_OPC_INTHB_SN,
  TILEPRO_OPC_INTHH,
  TILEPRO_OPC_INTHH_SN,
  TILEPRO_OPC_INTLB,
  TILEPRO_OPC_INTLB_SN,
  TILEPRO_OPC_INTLH,
  TILEPRO_OPC_INTLH_SN,
  TILEPRO_OPC_INV,
  TILEPRO_OPC_IRET,
  TILEPRO_OPC_JALB,
  TILEPRO_OPC_JALF,
  TILEPRO_OPC_JALR,
  TILEPRO_OPC_JALRP,
  TILEPRO_OPC_JB,
  TILEPRO_OPC_JF,
  TILEPRO_OPC_JR,
  TILEPRO_OPC_JRP,
  TILEPRO_OPC_LB,
  TILEPRO_OPC_LB_SN,
  TILEPRO_OPC_LB_U,
  TILEPRO_OPC_LB_U_SN,
  TILEPRO_OPC_LBADD,
  TILEPRO_OPC_LBADD_SN,
  TILEPRO_OPC_LBADD_U,
  TILEPRO_OPC_LBADD_U_SN,
  TILEPRO_OPC_LH,
  TILEPRO_OPC_LH_SN,
  TILEPRO_OPC_LH_U,
  TILEPRO_OPC_LH_U_SN,
  TILEPRO_OPC_LHADD,
  TILEPRO_OPC_LHADD_SN,
  TILEPRO_OPC_LHADD_U,
  TILEPRO_OPC_LHADD_U_SN,
  TILEPRO_OPC_LNK,
  TILEPRO_OPC_LNK_SN,
  TILEPRO_OPC_LW,
  TILEPRO_OPC_LW_SN,
  TILEPRO_OPC_LW_NA,
  TILEPRO_OPC_LW_NA_SN,
  TILEPRO_OPC_LWADD,
  TILEPRO_OPC_LWADD_SN,
  TILEPRO_OPC_LWADD_NA,
  TILEPRO_OPC_LWADD_NA_SN,
  TILEPRO_OPC_MAXB_U,
  TILEPRO_OPC_MAXB_U_SN,
  TILEPRO_OPC_MAXH,
  TILEPRO_OPC_MAXH_SN,
  TILEPRO_OPC_MAXIB_U,
  TILEPRO_OPC_MAXIB_U_SN,
  TILEPRO_OPC_MAXIH,
  TILEPRO_OPC_MAXIH_SN,
  TILEPRO_OPC_MF,
  TILEPRO_OPC_MFSPR,
  TILEPRO_OPC_MINB_U,
  TILEPRO_OPC_MINB_U_SN,
  TILEPRO_OPC_MINH,
  TILEPRO_OPC_MINH_SN,
  TILEPRO_OPC_MINIB_U,
  TILEPRO_OPC_MINIB_U_SN,
  TILEPRO_OPC_MINIH,
  TILEPRO_OPC_MINIH_SN,
  TILEPRO_OPC_MM,
  TILEPRO_OPC_MNZ,
  TILEPRO_OPC_MNZ_SN,
  TILEPRO_OPC_MNZB,
  TILEPRO_OPC_MNZB_SN,
  TILEPRO_OPC_MNZH,
  TILEPRO_OPC_MNZH_SN,
  TILEPRO_OPC_MTSPR,
  TILEPRO_OPC_MULHH_SS,
  TILEPRO_OPC_MULHH_SS_SN,
  TILEPRO_OPC_MULHH_SU,
  TILEPRO_OPC_MULHH_SU_SN,
  TILEPRO_OPC_MULHH_UU,
  TILEPRO_OPC_MULHH_UU_SN,
  TILEPRO_OPC_MULHHA_SS,
  TILEPRO_OPC_MULHHA_SS_SN,
  TILEPRO_OPC_MULHHA_SU,
  TILEPRO_OPC_MULHHA_SU_SN,
  TILEPRO_OPC_MULHHA_UU,
  TILEPRO_OPC_MULHHA_UU_SN,
  TILEPRO_OPC_MULHHSA_UU,
  TILEPRO_OPC_MULHHSA_UU_SN,
  TILEPRO_OPC_MULHL_SS,
  TILEPRO_OPC_MULHL_SS_SN,
  TILEPRO_OPC_MULHL_SU,
  TILEPRO_OPC_MULHL_SU_SN,
  TILEPRO_OPC_MULHL_US,
  TILEPRO_OPC_MULHL_US_SN,
  TILEPRO_OPC_MULHL_UU,
  TILEPRO_OPC_MULHL_UU_SN,
  TILEPRO_OPC_MULHLA_SS,
  TILEPRO_OPC_MULHLA_SS_SN,
  TILEPRO_OPC_MULHLA_SU,
  TILEPRO_OPC_MULHLA_SU_SN,
  TILEPRO_OPC_MULHLA_US,
  TILEPRO_OPC_MULHLA_US_SN,
  TILEPRO_OPC_MULHLA_UU,
  TILEPRO_OPC_MULHLA_UU_SN,
  TILEPRO_OPC_MULHLSA_UU,
  TILEPRO_OPC_MULHLSA_UU_SN,
  TILEPRO_OPC_MULLL_SS,
  TILEPRO_OPC_MULLL_SS_SN,
  TILEPRO_OPC_MULLL_SU,
  TILEPRO_OPC_MULLL_SU_SN,
  TILEPRO_OPC_MULLL_UU,
  TILEPRO_OPC_MULLL_UU_SN,
  TILEPRO_OPC_MULLLA_SS,
  TILEPRO_OPC_MULLLA_SS_SN,
  TILEPRO_OPC_MULLLA_SU,
  TILEPRO_OPC_MULLLA_SU_SN,
  TILEPRO_OPC_MULLLA_UU,
  TILEPRO_OPC_MULLLA_UU_SN,
  TILEPRO_OPC_MULLLSA_UU,
  TILEPRO_OPC_MULLLSA_UU_SN,
  TILEPRO_OPC_MVNZ,
  TILEPRO_OPC_MVNZ_SN,
  TILEPRO_OPC_MVZ,
  TILEPRO_OPC_MVZ_SN,
  TILEPRO_OPC_MZ,
  TILEPRO_OPC_MZ_SN,
  TILEPRO_OPC_MZB,
  TILEPRO_OPC_MZB_SN,
  TILEPRO_OPC_MZH,
  TILEPRO_OPC_MZH_SN,
  TILEPRO_OPC_NAP,
  TILEPRO_OPC_NOP,
  TILEPRO_OPC_NOR,
  TILEPRO_OPC_NOR_SN,
  TILEPRO_OPC_OR,
  TILEPRO_OPC_OR_SN,
  TILEPRO_OPC_ORI,
  TILEPRO_OPC_ORI_SN,
  TILEPRO_OPC_PACKBS_U,
  TILEPRO_OPC_PACKBS_U_SN,
  TILEPRO_OPC_PACKHB,
  TILEPRO_OPC_PACKHB_SN,
  TILEPRO_OPC_PACKHS,
  TILEPRO_OPC_PACKHS_SN,
  TILEPRO_OPC_PACKLB,
  TILEPRO_OPC_PACKLB_SN,
  TILEPRO_OPC_PCNT,
  TILEPRO_OPC_PCNT_SN,
  TILEPRO_OPC_RL,
  TILEPRO_OPC_RL_SN,
  TILEPRO_OPC_RLI,
  TILEPRO_OPC_RLI_SN,
  TILEPRO_OPC_S1A,
  TILEPRO_OPC_S1A_SN,
  TILEPRO_OPC_S2A,
  TILEPRO_OPC_S2A_SN,
  TILEPRO_OPC_S3A,
  TILEPRO_OPC_S3A_SN,
  TILEPRO_OPC_SADAB_U,
  TILEPRO_OPC_SADAB_U_SN,
  TILEPRO_OPC_SADAH,
  TILEPRO_OPC_SADAH_SN,
  TILEPRO_OPC_SADAH_U,
  TILEPRO_OPC_SADAH_U_SN,
  TILEPRO_OPC_SADB_U,
  TILEPRO_OPC_SADB_U_SN,
  TILEPRO_OPC_SADH,
  TILEPRO_OPC_SADH_SN,
  TILEPRO_OPC_SADH_U,
  TILEPRO_OPC_SADH_U_SN,
  TILEPRO_OPC_SB,
  TILEPRO_OPC_SBADD,
  TILEPRO_OPC_SEQ,
  TILEPRO_OPC_SEQ_SN,
  TILEPRO_OPC_SEQB,
  TILEPRO_OPC_SEQB_SN,
  TILEPRO_OPC_SEQH,
  TILEPRO_OPC_SEQH_SN,
  TILEPRO_OPC_SEQI,
  TILEPRO_OPC_SEQI_SN,
  TILEPRO_OPC_SEQIB,
  TILEPRO_OPC_SEQIB_SN,
  TILEPRO_OPC_SEQIH,
  TILEPRO_OPC_SEQIH_SN,
  TILEPRO_OPC_SH,
  TILEPRO_OPC_SHADD,
  TILEPRO_OPC_SHL,
  TILEPRO_OPC_SHL_SN,
  TILEPRO_OPC_SHLB,
  TILEPRO_OPC_SHLB_SN,
  TILEPRO_OPC_SHLH,
  TILEPRO_OPC_SHLH_SN,
  TILEPRO_OPC_SHLI,
  TILEPRO_OPC_SHLI_SN,
  TILEPRO_OPC_SHLIB,
  TILEPRO_OPC_SHLIB_SN,
  TILEPRO_OPC_SHLIH,
  TILEPRO_OPC_SHLIH_SN,
  TILEPRO_OPC_SHR,
  TILEPRO_OPC_SHR_SN,
  TILEPRO_OPC_SHRB,
  TILEPRO_OPC_SHRB_SN,
  TILEPRO_OPC_SHRH,
  TILEPRO_OPC_SHRH_SN,
  TILEPRO_OPC_SHRI,
  TILEPRO_OPC_SHRI_SN,
  TILEPRO_OPC_SHRIB,
  TILEPRO_OPC_SHRIB_SN,
  TILEPRO_OPC_SHRIH,
  TILEPRO_OPC_SHRIH_SN,
  TILEPRO_OPC_SLT,
  TILEPRO_OPC_SLT_SN,
  TILEPRO_OPC_SLT_U,
  TILEPRO_OPC_SLT_U_SN,
  TILEPRO_OPC_SLTB,
  TILEPRO_OPC_SLTB_SN,
  TILEPRO_OPC_SLTB_U,
  TILEPRO_OPC_SLTB_U_SN,
  TILEPRO_OPC_SLTE,
  TILEPRO_OPC_SLTE_SN,
  TILEPRO_OPC_SLTE_U,
  TILEPRO_OPC_SLTE_U_SN,
  TILEPRO_OPC_SLTEB,
  TILEPRO_OPC_SLTEB_SN,
  TILEPRO_OPC_SLTEB_U,
  TILEPRO_OPC_SLTEB_U_SN,
  TILEPRO_OPC_SLTEH,
  TILEPRO_OPC_SLTEH_SN,
  TILEPRO_OPC_SLTEH_U,
  TILEPRO_OPC_SLTEH_U_SN,
  TILEPRO_OPC_SLTH,
  TILEPRO_OPC_SLTH_SN,
  TILEPRO_OPC_SLTH_U,
  TILEPRO_OPC_SLTH_U_SN,
  TILEPRO_OPC_SLTI,
  TILEPRO_OPC_SLTI_SN,
  TILEPRO_OPC_SLTI_U,
  TILEPRO_OPC_SLTI_U_SN,
  TILEPRO_OPC_SLTIB,
  TILEPRO_OPC_SLTIB_SN,
  TILEPRO_OPC_SLTIB_U,
  TILEPRO_OPC_SLTIB_U_SN,
  TILEPRO_OPC_SLTIH,
  TILEPRO_OPC_SLTIH_SN,
  TILEPRO_OPC_SLTIH_U,
  TILEPRO_OPC_SLTIH_U_SN,
  TILEPRO_OPC_SNE,
  TILEPRO_OPC_SNE_SN,
  TILEPRO_OPC_SNEB,
  TILEPRO_OPC_SNEB_SN,
  TILEPRO_OPC_SNEH,
  TILEPRO_OPC_SNEH_SN,
  TILEPRO_OPC_SRA,
  TILEPRO_OPC_SRA_SN,
  TILEPRO_OPC_SRAB,
  TILEPRO_OPC_SRAB_SN,
  TILEPRO_OPC_SRAH,
  TILEPRO_OPC_SRAH_SN,
  TILEPRO_OPC_SRAI,
  TILEPRO_OPC_SRAI_SN,
  TILEPRO_OPC_SRAIB,
  TILEPRO_OPC_SRAIB_SN,
  TILEPRO_OPC_SRAIH,
  TILEPRO_OPC_SRAIH_SN,
  TILEPRO_OPC_SUB,
  TILEPRO_OPC_SUB_SN,
  TILEPRO_OPC_SUBB,
  TILEPRO_OPC_SUBB_SN,
  TILEPRO_OPC_SUBBS_U,
  TILEPRO_OPC_SUBBS_U_SN,
  TILEPRO_OPC_SUBH,
  TILEPRO_OPC_SUBH_SN,
  TILEPRO_OPC_SUBHS,
  TILEPRO_OPC_SUBHS_SN,
  TILEPRO_OPC_SUBS,
  TILEPRO_OPC_SUBS_SN,
  TILEPRO_OPC_SW,
  TILEPRO_OPC_SWADD,
  TILEPRO_OPC_SWINT0,
  TILEPRO_OPC_SWINT1,
  TILEPRO_OPC_SWINT2,
  TILEPRO_OPC_SWINT3,
  TILEPRO_OPC_TBLIDXB0,
  TILEPRO_OPC_TBLIDXB0_SN,
  TILEPRO_OPC_TBLIDXB1,
  TILEPRO_OPC_TBLIDXB1_SN,
  TILEPRO_OPC_TBLIDXB2,
  TILEPRO_OPC_TBLIDXB2_SN,
  TILEPRO_OPC_TBLIDXB3,
  TILEPRO_OPC_TBLIDXB3_SN,
  TILEPRO_OPC_TNS,
  TILEPRO_OPC_TNS_SN,
  TILEPRO_OPC_WH64,
  TILEPRO_OPC_XOR,
  TILEPRO_OPC_XOR_SN,
  TILEPRO_OPC_XORI,
  TILEPRO_OPC_XORI_SN,
  TILEPRO_OPC_NONE
} tilepro_mnemonic;




typedef enum
{
  TILEPRO_PIPELINE_X0,
  TILEPRO_PIPELINE_X1,
  TILEPRO_PIPELINE_Y0,
  TILEPRO_PIPELINE_Y1,
  TILEPRO_PIPELINE_Y2,
} tilepro_pipeline;

#define tilepro_is_x_pipeline(p) ((int)(p) <= (int)TILEPRO_PIPELINE_X1)

typedef enum
{
  TILEPRO_OP_TYPE_REGISTER,
  TILEPRO_OP_TYPE_IMMEDIATE,
  TILEPRO_OP_TYPE_ADDRESS,
  TILEPRO_OP_TYPE_SPR
} tilepro_operand_type;

struct tilepro_operand
{
  /* Is this operand a register, immediate or address? */
  tilepro_operand_type type;

  /* The default relocation type for this operand.  */
  signed int default_reloc : 16;

  /* How many bits is this value? (used for range checking) */
  unsigned int num_bits : 5;

  /* Is the value signed? (used for range checking) */
  unsigned int is_signed : 1;

  /* Is this operand a source register? */
  unsigned int is_src_reg : 1;

  /* Is this operand written? (i.e. is it a destination register) */
  unsigned int is_dest_reg : 1;

  /* Is this operand PC-relative? */
  unsigned int is_pc_relative : 1;

  /* By how many bits do we right shift the value before inserting? */
  unsigned int rightshift : 2;

  /* Return the bits for this operand to be ORed into an existing bundle. */
  tilepro_bundle_bits (*insert) (int op);

  /* Extract this operand and return it. */
  unsigned int (*extract) (tilepro_bundle_bits bundle);
};


extern const struct tilepro_operand tilepro_operands[];

/* One finite-state machine per pipe for rapid instruction decoding. */
extern const unsigned short * const
tilepro_bundle_decoder_fsms[TILEPRO_NUM_PIPELINE_ENCODINGS];


struct tilepro_opcode
{
  /* The opcode mnemonic, e.g. "add" */
  const char *name;

  /* The enum value for this mnemonic. */
  tilepro_mnemonic mnemonic;

  /* A bit mask of which of the five pipes this instruction
     is compatible with:
     X0  0x01
     X1  0x02
     Y0  0x04
     Y1  0x08
     Y2  0x10 */
  unsigned char pipes;

  /* How many operands are there? */
  unsigned char num_operands;

  /* Which register does this write implicitly, or TREG_ZERO if none? */
  unsigned char implicitly_written_register;

  /* Can this be bundled with other instructions (almost always true). */
  unsigned char can_bundle;

  /* The description of the operands. Each of these is an
   * index into the tilepro_operands[] table. */
  unsigned char operands[TILEPRO_NUM_PIPELINE_ENCODINGS][TILEPRO_MAX_OPERANDS];

};

extern const struct tilepro_opcode tilepro_opcodes[];


/* Used for non-textual disassembly into structs. */
struct tilepro_decoded_instruction
{
  const struct tilepro_opcode *opcode;
  const struct tilepro_operand *operands[TILEPRO_MAX_OPERANDS];
  int operand_values[TILEPRO_MAX_OPERANDS];
};


/* Disassemble a bundle into a struct for machine processing. */
extern int parse_insn_tilepro(tilepro_bundle_bits bits,
                              unsigned int pc,
                              struct tilepro_decoded_instruction
                              decoded[TILEPRO_MAX_INSTRUCTIONS_PER_BUNDLE]);


/* Given a set of bundle bits and a specific pipe, returns which
 * instruction the bundle contains in that pipe.
 */
extern const struct tilepro_opcode *
find_opcode(tilepro_bundle_bits bits, tilepro_pipeline pipe);



#endif /* opcode_tilepro_h */
