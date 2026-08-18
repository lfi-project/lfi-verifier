#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// A decoder for the subset of RV64GC it is deliberately not a general
// disassembler.

enum {
  RV_ZERO = 0,
  RV_RA = 1,
  RV_SP = 2,
  // The sandbox address register. Only add.uw may write it.
  RV_ADDR = 18,
  // The sandbox base register. Nothing may write it.
  RV_BASE = 21,
  // No register in this slot.
  RV_NOREG = 32,
};

enum RvKind {
  // Not recognized. Always rejected.
  RV_UNKNOWN = 0,
  // Computation with no memory operand and no control flow.
  RV_COMPUTE,
  // Reads memory at rs1 + imm.
  RV_LOAD,
  // Writes memory at rs1 + imm.
  RV_STORE,
  // Atomic RMW at rs1, with no displacement.
  RV_AMO,
  // Conditional branch to pc + imm.
  RV_BRANCH,
  // Direct jump to pc + imm.
  RV_JAL,
  // Indirect jump to rs1 + imm.
  RV_JALR,
  // Ordering, with no operand this verifier cares about.
  RV_FENCE,
  // Control and status register access.
  RV_CSR,
  // environment calls, instruction-cache maintenance, and anything privileged.
  RV_SYSTEM,
};

enum RvOp {
  RV_OP_UNKNOWN = 0,

  // RV64I
  RV_OP_LUI,
  RV_OP_AUIPC,
  RV_OP_JAL,
  RV_OP_JALR,
  RV_OP_BEQ,
  RV_OP_BNE,
  RV_OP_BLT,
  RV_OP_BGE,
  RV_OP_BLTU,
  RV_OP_BGEU,
  RV_OP_LB,
  RV_OP_LH,
  RV_OP_LW,
  RV_OP_LBU,
  RV_OP_LHU,
  RV_OP_LWU,
  RV_OP_LD,
  RV_OP_SB,
  RV_OP_SH,
  RV_OP_SW,
  RV_OP_SD,
  RV_OP_ADDI,
  RV_OP_SLTI,
  RV_OP_SLTIU,
  RV_OP_XORI,
  RV_OP_ORI,
  RV_OP_ANDI,
  RV_OP_SLLI,
  RV_OP_SRLI,
  RV_OP_SRAI,
  RV_OP_ADD,
  RV_OP_SUB,
  RV_OP_SLL,
  RV_OP_SLT,
  RV_OP_SLTU,
  RV_OP_XOR,
  RV_OP_SRL,
  RV_OP_SRA,
  RV_OP_OR,
  RV_OP_AND,
  RV_OP_ADDIW,
  RV_OP_SLLIW,
  RV_OP_SRLIW,
  RV_OP_SRAIW,
  RV_OP_ADDW,
  RV_OP_SUBW,
  RV_OP_SLLW,
  RV_OP_SRLW,
  RV_OP_SRAW,
  RV_OP_FENCE,
  RV_OP_ECALL,
  RV_OP_EBREAK,

  // Zifencei, Zicsr, and the privileged set: recognized to be refused.
  RV_OP_FENCE_I,
  RV_OP_CSRRW,
  RV_OP_CSRRS,
  RV_OP_CSRRC,
  RV_OP_CSRRWI,
  RV_OP_CSRRSI,
  RV_OP_CSRRCI,
  RV_OP_PRIVILEGED,

  // M
  RV_OP_MUL,
  RV_OP_MULH,
  RV_OP_MULHSU,
  RV_OP_MULHU,
  RV_OP_DIV,
  RV_OP_DIVU,
  RV_OP_REM,
  RV_OP_REMU,
  RV_OP_MULW,
  RV_OP_DIVW,
  RV_OP_DIVUW,
  RV_OP_REMW,
  RV_OP_REMUW,

  // A
  RV_OP_LR,
  RV_OP_SC,
  RV_OP_AMOSWAP,
  RV_OP_AMOADD,
  RV_OP_AMOXOR,
  RV_OP_AMOAND,
  RV_OP_AMOOR,
  RV_OP_AMOMIN,
  RV_OP_AMOMAX,
  RV_OP_AMOMINU,
  RV_OP_AMOMAXU,

  // F and D
  RV_OP_FLW,
  RV_OP_FLD,
  RV_OP_FSW,
  RV_OP_FSD,
  RV_OP_FMADD,
  RV_OP_FMSUB,
  RV_OP_FNMSUB,
  RV_OP_FNMADD,
  RV_OP_FP,
  RV_OP_FCMP,
  RV_OP_FCVT_INT,
  RV_OP_FMV_X,
  RV_OP_FCLASS,

  // Zba
  RV_OP_ADD_UW,
  RV_OP_SH1ADD,
  RV_OP_SH2ADD,
  RV_OP_SH3ADD,
  RV_OP_SH1ADD_UW,
  RV_OP_SH2ADD_UW,
  RV_OP_SH3ADD_UW,
  RV_OP_SLLI_UW,

  // Zbb
  RV_OP_ANDN,
  RV_OP_ORN,
  RV_OP_XNOR,
  RV_OP_CLZ,
  RV_OP_CLZW,
  RV_OP_CTZ,
  RV_OP_CTZW,
  RV_OP_CPOP,
  RV_OP_CPOPW,
  RV_OP_MAX,
  RV_OP_MAXU,
  RV_OP_MIN,
  RV_OP_MINU,
  RV_OP_SEXT_B,
  RV_OP_SEXT_H,
  RV_OP_ZEXT_H,
  RV_OP_ROL,
  RV_OP_ROLW,
  RV_OP_ROR,
  RV_OP_RORI,
  RV_OP_RORIW,
  RV_OP_RORW,
  RV_OP_ORC_B,
  RV_OP_REV8,

  // Zbs
  RV_OP_BCLR,
  RV_OP_BCLRI,
  RV_OP_BEXT,
  RV_OP_BEXTI,
  RV_OP_BINV,
  RV_OP_BINVI,
  RV_OP_BSET,
  RV_OP_BSETI,

  RV_OP_MAXVAL,
};

struct RvInst {
  enum RvOp op;
  enum RvKind kind;

  // 2 compressed, 4 otherwise.
  uint8_t len;

  uint8_t rd;
  uint8_t rs1;
  uint8_t rs2;

  int32_t imm;
  bool compressed;
};

bool rv_decode(const uint8_t *bytes, size_t size, struct RvInst *inst);

// The mnemonic of a decoded instruction, for error messages.
const char *rv_name(enum RvOp op);
