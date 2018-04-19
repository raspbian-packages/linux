/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __irq_nmi_defs_asm_h
#define __irq_nmi_defs_asm_h

/*
 * This file is autogenerated from
 *   file:           ../../mod/irq_nmi.r
 *     id:           <not found>
 *     last modfied: Thu Jan 22 09:22:43 2004
 *
 *   by /n/asic/design/tools/rdesc/src/rdes2c -asm --outfile asm/irq_nmi_defs_asm.h ../../mod/irq_nmi.r
 *      id: $Id: irq_nmi_defs_asm.h,v 1.1 2005/04/24 18:31:04 starvik Exp $
 * Any changes here will be lost.
 *
 * -*- buffer-read-only: t -*-
 */

#ifndef REG_FIELD
#define REG_FIELD( scope, reg, field, value ) \
  REG_FIELD_X_( value, reg_##scope##_##reg##___##field##___lsb )
#define REG_FIELD_X_( value, shift ) ((value) << shift)
#endif

#ifndef REG_STATE
#define REG_STATE( scope, reg, field, symbolic_value ) \
  REG_STATE_X_( regk_##scope##_##symbolic_value, reg_##scope##_##reg##___##field##___lsb )
#define REG_STATE_X_( k, shift ) (k << shift)
#endif

#ifndef REG_MASK
#define REG_MASK( scope, reg, field ) \
  REG_MASK_X_( reg_##scope##_##reg##___##field##___width, reg_##scope##_##reg##___##field##___lsb )
#define REG_MASK_X_( width, lsb ) (((1 << width)-1) << lsb)
#endif

#ifndef REG_LSB
#define REG_LSB( scope, reg, field ) reg_##scope##_##reg##___##field##___lsb
#endif

#ifndef REG_BIT
#define REG_BIT( scope, reg, field ) reg_##scope##_##reg##___##field##___bit
#endif

#ifndef REG_ADDR
#define REG_ADDR( scope, inst, reg ) REG_ADDR_X_(inst, reg_##scope##_##reg##_offset)
#define REG_ADDR_X_( inst, offs ) ((inst) + offs)
#endif

#ifndef REG_ADDR_VECT
#define REG_ADDR_VECT( scope, inst, reg, index ) \
         REG_ADDR_VECT_X_(inst, reg_##scope##_##reg##_offset, index, \
			 STRIDE_##scope##_##reg )
#define REG_ADDR_VECT_X_( inst, offs, index, stride ) \
                          ((inst) + offs + (index) * stride)
#endif

/* Register rw_cmd, scope irq_nmi, type rw */
#define reg_irq_nmi_rw_cmd___delay___lsb 0
#define reg_irq_nmi_rw_cmd___delay___width 16
#define reg_irq_nmi_rw_cmd___op___lsb 16
#define reg_irq_nmi_rw_cmd___op___width 2
#define reg_irq_nmi_rw_cmd_offset 0


/* Constants */
#define regk_irq_nmi_ack_irq                      0x00000002
#define regk_irq_nmi_ack_nmi                      0x00000003
#define regk_irq_nmi_irq                          0x00000000
#define regk_irq_nmi_nmi                          0x00000001
#endif /* __irq_nmi_defs_asm_h */
