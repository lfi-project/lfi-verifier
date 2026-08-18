#include <string.h>

#include "decode.h"

static inline uint32_t
bits(uint32_t x, unsigned hi, unsigned lo)
{
    return (x >> lo) & ((1u << (hi - lo + 1)) - 1);
}

static inline int32_t
sext(uint32_t x, unsigned width)
{
    uint32_t sign = 1u << (width - 1);
    return (int32_t) ((x ^ sign) - sign);
}

static inline uint32_t opcode(uint32_t x) { return bits(x, 6, 0); }
static inline uint32_t rd(uint32_t x) { return bits(x, 11, 7); }
static inline uint32_t funct3(uint32_t x) { return bits(x, 14, 12); }
static inline uint32_t rs1(uint32_t x) { return bits(x, 19, 15); }
static inline uint32_t rs2(uint32_t x) { return bits(x, 24, 20); }
static inline uint32_t funct7(uint32_t x) { return bits(x, 31, 25); }
static inline uint32_t funct6(uint32_t x) { return bits(x, 31, 26); }

static inline int32_t
imm_i(uint32_t x)
{
    return sext(bits(x, 31, 20), 12);
}

static inline int32_t
imm_s(uint32_t x)
{
    return sext((bits(x, 31, 25) << 5) | bits(x, 11, 7), 12);
}

static inline int32_t
imm_b(uint32_t x)
{
    uint32_t v = (bits(x, 31, 31) << 12) | (bits(x, 7, 7) << 11) |
        (bits(x, 30, 25) << 5) | (bits(x, 11, 8) << 1);
    return sext(v, 13);
}

static inline int32_t
imm_u(uint32_t x)
{
    return (int32_t) (x & 0xfffff000u);
}

static inline int32_t
imm_j(uint32_t x)
{
    uint32_t v = (bits(x, 31, 31) << 20) | (bits(x, 19, 12) << 12) |
        (bits(x, 20, 20) << 11) | (bits(x, 30, 21) << 1);
    return sext(v, 21);
}

static bool
reserved_rounding(uint32_t x)
{
    return funct3(x) == 5 || funct3(x) == 6;
}

static void
set(struct RvInst *inst, enum RvOp op, enum RvKind kind)
{
    inst->op = op;
    inst->kind = kind;
}

static inline uint8_t
creg(uint32_t x)
{
    return (uint8_t) (x + 8);
}

static void
decode32(uint32_t x, struct RvInst *inst)
{
    inst->rd = (uint8_t) rd(x);
    inst->rs1 = (uint8_t) rs1(x);
    inst->rs2 = (uint8_t) rs2(x);

    switch (opcode(x)) {
    case 0x37:
        inst->rs1 = inst->rs2 = RV_NOREG;
        inst->imm = imm_u(x);
        set(inst, RV_OP_LUI, RV_COMPUTE);
        return;
    case 0x17:
        inst->rs1 = inst->rs2 = RV_NOREG;
        inst->imm = imm_u(x);
        set(inst, RV_OP_AUIPC, RV_COMPUTE);
        return;
    case 0x6f:
        inst->rs1 = inst->rs2 = RV_NOREG;
        inst->imm = imm_j(x);
        set(inst, RV_OP_JAL, RV_JAL);
        return;
    case 0x67:
        if (funct3(x) != 0)
            return;
        inst->rs2 = RV_NOREG;
        inst->imm = imm_i(x);
        set(inst, RV_OP_JALR, RV_JALR);
        return;
    case 0x63:
        inst->rd = RV_NOREG;
        inst->imm = imm_b(x);
        switch (funct3(x)) {
        case 0: set(inst, RV_OP_BEQ, RV_BRANCH); return;
        case 1: set(inst, RV_OP_BNE, RV_BRANCH); return;
        case 4: set(inst, RV_OP_BLT, RV_BRANCH); return;
        case 5: set(inst, RV_OP_BGE, RV_BRANCH); return;
        case 6: set(inst, RV_OP_BLTU, RV_BRANCH); return;
        case 7: set(inst, RV_OP_BGEU, RV_BRANCH); return;
        }
        return;
    case 0x03:
        inst->rs2 = RV_NOREG;
        inst->imm = imm_i(x);
        switch (funct3(x)) {
        case 0: set(inst, RV_OP_LB, RV_LOAD); return;
        case 1: set(inst, RV_OP_LH, RV_LOAD); return;
        case 2: set(inst, RV_OP_LW, RV_LOAD); return;
        case 3: set(inst, RV_OP_LD, RV_LOAD); return;
        case 4: set(inst, RV_OP_LBU, RV_LOAD); return;
        case 5: set(inst, RV_OP_LHU, RV_LOAD); return;
        case 6: set(inst, RV_OP_LWU, RV_LOAD); return;
        }
        return;
    case 0x23:
        inst->rd = RV_NOREG;
        inst->imm = imm_s(x);
        switch (funct3(x)) {
        case 0: set(inst, RV_OP_SB, RV_STORE); return;
        case 1: set(inst, RV_OP_SH, RV_STORE); return;
        case 2: set(inst, RV_OP_SW, RV_STORE); return;
        case 3: set(inst, RV_OP_SD, RV_STORE); return;
        }
        return;
    case 0x07:
        inst->rd = RV_NOREG;
        inst->rs2 = RV_NOREG;
        inst->imm = imm_i(x);
        switch (funct3(x)) {
        case 2: set(inst, RV_OP_FLW, RV_LOAD); return;
        case 3: set(inst, RV_OP_FLD, RV_LOAD); return;
        }
        return;
    case 0x27:
        inst->rd = RV_NOREG;
        inst->rs2 = RV_NOREG;
        inst->imm = imm_s(x);
        switch (funct3(x)) {
        case 2: set(inst, RV_OP_FSW, RV_STORE); return;
        case 3: set(inst, RV_OP_FSD, RV_STORE); return;
        }
        return;
    case 0x13:
        inst->rs2 = RV_NOREG;
        inst->imm = imm_i(x);
        switch (funct3(x)) {
        case 0: set(inst, RV_OP_ADDI, RV_COMPUTE); return;
        case 2: set(inst, RV_OP_SLTI, RV_COMPUTE); return;
        case 3: set(inst, RV_OP_SLTIU, RV_COMPUTE); return;
        case 4: set(inst, RV_OP_XORI, RV_COMPUTE); return;
        case 6: set(inst, RV_OP_ORI, RV_COMPUTE); return;
        case 7: set(inst, RV_OP_ANDI, RV_COMPUTE); return;
        case 1:
            switch (funct6(x)) {
            case 0x00: set(inst, RV_OP_SLLI, RV_COMPUTE); return;
            case 0x0a: set(inst, RV_OP_BSETI, RV_COMPUTE); return;
            case 0x12: set(inst, RV_OP_BCLRI, RV_COMPUTE); return;
            case 0x1a: set(inst, RV_OP_BINVI, RV_COMPUTE); return;
            case 0x18:
                switch (rs2(x)) {
                case 0: set(inst, RV_OP_CLZ, RV_COMPUTE); return;
                case 1: set(inst, RV_OP_CTZ, RV_COMPUTE); return;
                case 2: set(inst, RV_OP_CPOP, RV_COMPUTE); return;
                case 4: set(inst, RV_OP_SEXT_B, RV_COMPUTE); return;
                case 5: set(inst, RV_OP_SEXT_H, RV_COMPUTE); return;
                }
                return;
            }
            return;
        case 5:
            switch (funct6(x)) {
            case 0x00: set(inst, RV_OP_SRLI, RV_COMPUTE); return;
            case 0x10: set(inst, RV_OP_SRAI, RV_COMPUTE); return;
            case 0x12: set(inst, RV_OP_BEXTI, RV_COMPUTE); return;
            case 0x18: set(inst, RV_OP_RORI, RV_COMPUTE); return;
            case 0x0a:
                if (rs2(x) == 7)
                    set(inst, RV_OP_ORC_B, RV_COMPUTE);
                return;
            case 0x1a:
                if (rs2(x) == 0x18)
                    set(inst, RV_OP_REV8, RV_COMPUTE);
                return;
            }
            return;
        }
        return;
    case 0x1b:
        inst->rs2 = RV_NOREG;
        inst->imm = imm_i(x);
        switch (funct3(x)) {
        case 0: set(inst, RV_OP_ADDIW, RV_COMPUTE); return;
        case 1:
            switch (funct7(x)) {
            case 0x00: set(inst, RV_OP_SLLIW, RV_COMPUTE); return;
            case 0x04:
            case 0x05: set(inst, RV_OP_SLLI_UW, RV_COMPUTE); return;
            case 0x30:
                switch (rs2(x)) {
                case 0: set(inst, RV_OP_CLZW, RV_COMPUTE); return;
                case 1: set(inst, RV_OP_CTZW, RV_COMPUTE); return;
                case 2: set(inst, RV_OP_CPOPW, RV_COMPUTE); return;
                }
                return;
            }
            return;
        case 5:
            switch (funct7(x)) {
            case 0x00: set(inst, RV_OP_SRLIW, RV_COMPUTE); return;
            case 0x20: set(inst, RV_OP_SRAIW, RV_COMPUTE); return;
            case 0x30: set(inst, RV_OP_RORIW, RV_COMPUTE); return;
            }
            return;
        }
        return;
    case 0x33:
        switch (funct7(x)) {
        case 0x00:
            switch (funct3(x)) {
            case 0: set(inst, RV_OP_ADD, RV_COMPUTE); return;
            case 1: set(inst, RV_OP_SLL, RV_COMPUTE); return;
            case 2: set(inst, RV_OP_SLT, RV_COMPUTE); return;
            case 3: set(inst, RV_OP_SLTU, RV_COMPUTE); return;
            case 4: set(inst, RV_OP_XOR, RV_COMPUTE); return;
            case 5: set(inst, RV_OP_SRL, RV_COMPUTE); return;
            case 6: set(inst, RV_OP_OR, RV_COMPUTE); return;
            case 7: set(inst, RV_OP_AND, RV_COMPUTE); return;
            }
            return;
        case 0x20:
            switch (funct3(x)) {
            case 0: set(inst, RV_OP_SUB, RV_COMPUTE); return;
            case 4: set(inst, RV_OP_XNOR, RV_COMPUTE); return;
            case 5: set(inst, RV_OP_SRA, RV_COMPUTE); return;
            case 6: set(inst, RV_OP_ORN, RV_COMPUTE); return;
            case 7: set(inst, RV_OP_ANDN, RV_COMPUTE); return;
            }
            return;
        case 0x01:
            switch (funct3(x)) {
            case 0: set(inst, RV_OP_MUL, RV_COMPUTE); return;
            case 1: set(inst, RV_OP_MULH, RV_COMPUTE); return;
            case 2: set(inst, RV_OP_MULHSU, RV_COMPUTE); return;
            case 3: set(inst, RV_OP_MULHU, RV_COMPUTE); return;
            case 4: set(inst, RV_OP_DIV, RV_COMPUTE); return;
            case 5: set(inst, RV_OP_DIVU, RV_COMPUTE); return;
            case 6: set(inst, RV_OP_REM, RV_COMPUTE); return;
            case 7: set(inst, RV_OP_REMU, RV_COMPUTE); return;
            }
            return;
        case 0x05:
            switch (funct3(x)) {
            case 4: set(inst, RV_OP_MIN, RV_COMPUTE); return;
            case 5: set(inst, RV_OP_MINU, RV_COMPUTE); return;
            case 6: set(inst, RV_OP_MAX, RV_COMPUTE); return;
            case 7: set(inst, RV_OP_MAXU, RV_COMPUTE); return;
            }
            return;
        case 0x10:
            switch (funct3(x)) {
            case 2: set(inst, RV_OP_SH1ADD, RV_COMPUTE); return;
            case 4: set(inst, RV_OP_SH2ADD, RV_COMPUTE); return;
            case 6: set(inst, RV_OP_SH3ADD, RV_COMPUTE); return;
            }
            return;
        case 0x30:
            switch (funct3(x)) {
            case 1: set(inst, RV_OP_ROL, RV_COMPUTE); return;
            case 5: set(inst, RV_OP_ROR, RV_COMPUTE); return;
            }
            return;
        case 0x14:
            if (funct3(x) == 1)
                set(inst, RV_OP_BSET, RV_COMPUTE);
            return;
        case 0x24:
            switch (funct3(x)) {
            case 1: set(inst, RV_OP_BCLR, RV_COMPUTE); return;
            case 5: set(inst, RV_OP_BEXT, RV_COMPUTE); return;
            }
            return;
        case 0x34:
            if (funct3(x) == 1)
                set(inst, RV_OP_BINV, RV_COMPUTE);
            return;
        }
        return;
    case 0x3b:
        switch (funct7(x)) {
        case 0x00:
            switch (funct3(x)) {
            case 0: set(inst, RV_OP_ADDW, RV_COMPUTE); return;
            case 1: set(inst, RV_OP_SLLW, RV_COMPUTE); return;
            case 5: set(inst, RV_OP_SRLW, RV_COMPUTE); return;
            }
            return;
        case 0x20:
            switch (funct3(x)) {
            case 0: set(inst, RV_OP_SUBW, RV_COMPUTE); return;
            case 5: set(inst, RV_OP_SRAW, RV_COMPUTE); return;
            }
            return;
        case 0x01:
            switch (funct3(x)) {
            case 0: set(inst, RV_OP_MULW, RV_COMPUTE); return;
            case 4: set(inst, RV_OP_DIVW, RV_COMPUTE); return;
            case 5: set(inst, RV_OP_DIVUW, RV_COMPUTE); return;
            case 6: set(inst, RV_OP_REMW, RV_COMPUTE); return;
            case 7: set(inst, RV_OP_REMUW, RV_COMPUTE); return;
            }
            return;
        case 0x04:
            if (funct3(x) == 0) {
                set(inst, RV_OP_ADD_UW, RV_COMPUTE);
                return;
            }
            if (funct3(x) == 4 && rs2(x) == 0)
                set(inst, RV_OP_ZEXT_H, RV_COMPUTE);
            return;
        case 0x10:
            switch (funct3(x)) {
            case 2: set(inst, RV_OP_SH1ADD_UW, RV_COMPUTE); return;
            case 4: set(inst, RV_OP_SH2ADD_UW, RV_COMPUTE); return;
            case 6: set(inst, RV_OP_SH3ADD_UW, RV_COMPUTE); return;
            }
            return;
        case 0x30:
            switch (funct3(x)) {
            case 1: set(inst, RV_OP_ROLW, RV_COMPUTE); return;
            case 5: set(inst, RV_OP_RORW, RV_COMPUTE); return;
            }
            return;
        }
        return;
    case 0x2f: {
        if (funct3(x) != 2 && funct3(x) != 3)
            return;
        inst->imm = 0;
        uint32_t funct5 = bits(x, 31, 27);
        switch (funct5) {
        case 0x02:
            if (rs2(x) != 0)
                return;
            inst->rs2 = RV_NOREG;
            set(inst, RV_OP_LR, RV_AMO);
            return;
        case 0x03: set(inst, RV_OP_SC, RV_AMO); return;
        case 0x01: set(inst, RV_OP_AMOSWAP, RV_AMO); return;
        case 0x00: set(inst, RV_OP_AMOADD, RV_AMO); return;
        case 0x04: set(inst, RV_OP_AMOXOR, RV_AMO); return;
        case 0x0c: set(inst, RV_OP_AMOAND, RV_AMO); return;
        case 0x08: set(inst, RV_OP_AMOOR, RV_AMO); return;
        case 0x10: set(inst, RV_OP_AMOMIN, RV_AMO); return;
        case 0x14: set(inst, RV_OP_AMOMAX, RV_AMO); return;
        case 0x18: set(inst, RV_OP_AMOMINU, RV_AMO); return;
        case 0x1c: set(inst, RV_OP_AMOMAXU, RV_AMO); return;
        }
        return;
    }
    case 0x43:
    case 0x47:
    case 0x4b:
    case 0x4f: {
        uint32_t fmt = bits(x, 26, 25);
        if (fmt != 0 && fmt != 1)
            return;
        if (reserved_rounding(x))
            return;
        inst->rd = inst->rs1 = inst->rs2 = RV_NOREG;
        switch (opcode(x)) {
        case 0x43: set(inst, RV_OP_FMADD, RV_COMPUTE); return;
        case 0x47: set(inst, RV_OP_FMSUB, RV_COMPUTE); return;
        case 0x4b: set(inst, RV_OP_FNMSUB, RV_COMPUTE); return;
        case 0x4f: set(inst, RV_OP_FNMADD, RV_COMPUTE); return;
        }
        return;
    }
    case 0x53: {
        uint32_t fmt = bits(x, 26, 25);
        uint32_t funct5 = bits(x, 31, 27);
        if (fmt != 0 && fmt != 1)
            return;
        switch (funct5) {
        case 0x00:
        case 0x01:
        case 0x02:
        case 0x03:
            if (reserved_rounding(x))
                return;
            inst->rd = inst->rs1 = inst->rs2 = RV_NOREG;
            set(inst, RV_OP_FP, RV_COMPUTE);
            return;
        case 0x0b:
            if (rs2(x) != 0 || reserved_rounding(x))
                return;
            inst->rd = inst->rs1 = inst->rs2 = RV_NOREG;
            set(inst, RV_OP_FP, RV_COMPUTE);
            return;
        case 0x04:
            if (funct3(x) > 2)
                return;
            inst->rd = inst->rs1 = inst->rs2 = RV_NOREG;
            set(inst, RV_OP_FP, RV_COMPUTE);
            return;
        case 0x05:
            if (funct3(x) > 1)
                return;
            inst->rd = inst->rs1 = inst->rs2 = RV_NOREG;
            set(inst, RV_OP_FP, RV_COMPUTE);
            return;
        case 0x08:
            if (rs2(x) != (fmt == 0 ? 1u : 0u) || reserved_rounding(x))
                return;
            inst->rd = inst->rs1 = inst->rs2 = RV_NOREG;
            set(inst, RV_OP_FP, RV_COMPUTE);
            return;
        case 0x14:
            if (funct3(x) > 2)
                return;
            inst->rs1 = inst->rs2 = RV_NOREG;
            set(inst, RV_OP_FCMP, RV_COMPUTE);
            return;
        case 0x18:
            if (rs2(x) > 3 || reserved_rounding(x))
                return;
            inst->rs1 = inst->rs2 = RV_NOREG;
            set(inst, RV_OP_FCVT_INT, RV_COMPUTE);
            return;
        case 0x1a:
            if (rs2(x) > 3 || reserved_rounding(x))
                return;
            inst->rd = inst->rs2 = RV_NOREG;
            set(inst, RV_OP_FP, RV_COMPUTE);
            return;
        case 0x1c:
            if (rs2(x) != 0)
                return;
            inst->rs1 = inst->rs2 = RV_NOREG;
            if (funct3(x) == 0) {
                set(inst, RV_OP_FMV_X, RV_COMPUTE);
                return;
            }
            if (funct3(x) == 1)
                set(inst, RV_OP_FCLASS, RV_COMPUTE);
            return;
        case 0x1e:
            if (rs2(x) != 0 || funct3(x) != 0)
                return;
            inst->rd = inst->rs2 = RV_NOREG;
            set(inst, RV_OP_FP, RV_COMPUTE);
            return;
        }
        return;
    }
    case 0x0f:
        if (funct3(x) == 0 && (rd(x) != 0 || rs1(x) != 0))
            return;
        if (funct3(x) == 0 && bits(x, 31, 28) != 0 && x != 0x8330000f)
            return;
        inst->rd = inst->rs1 = inst->rs2 = RV_NOREG;
        switch (funct3(x)) {
        case 0: set(inst, RV_OP_FENCE, RV_FENCE); return;
        case 1: set(inst, RV_OP_FENCE_I, RV_SYSTEM); return;
        }
        return;
    case 0x73:
        inst->rs2 = RV_NOREG;
        switch (funct3(x)) {
        case 0:
            inst->rd = inst->rs1 = RV_NOREG;
            if (bits(x, 31, 7) == 0) {
                set(inst, RV_OP_ECALL, RV_SYSTEM);
                return;
            }
            if (bits(x, 31, 20) == 1 && rd(x) == 0 && rs1(x) == 0) {
                set(inst, RV_OP_EBREAK, RV_SYSTEM);
                return;
            }
            set(inst, RV_OP_PRIVILEGED, RV_SYSTEM);
            return;
        case 1:
        case 2:
        case 3:
        case 5:
        case 6:
        case 7:
            inst->imm = (int32_t) bits(x, 31, 20);
            if (funct3(x) >= 5)
                inst->rs1 = RV_NOREG;
            switch (funct3(x)) {
            case 1: set(inst, RV_OP_CSRRW, RV_CSR); return;
            case 2: set(inst, RV_OP_CSRRS, RV_CSR); return;
            case 3: set(inst, RV_OP_CSRRC, RV_CSR); return;
            case 5: set(inst, RV_OP_CSRRWI, RV_CSR); return;
            case 6: set(inst, RV_OP_CSRRSI, RV_CSR); return;
            case 7: set(inst, RV_OP_CSRRCI, RV_CSR); return;
            }
            return;
        }
        return;
    }
}

static void
decode16(uint32_t x, struct RvInst *inst)
{
    uint32_t quadrant = bits(x, 1, 0);
    uint32_t f3 = bits(x, 15, 13);

    inst->compressed = true;

    switch (quadrant) {
    case 0:
        switch (f3) {
        case 0:
            if (bits(x, 12, 5) == 0)
                return;
            inst->rd = creg(bits(x, 4, 2));
            inst->rs1 = RV_SP;
            inst->imm = (int32_t) ((bits(x, 10, 7) << 6) | (bits(x, 12, 11) << 4) |
                (bits(x, 6, 6) << 2) | (bits(x, 5, 5) << 3));
            set(inst, RV_OP_ADDI, RV_COMPUTE);
            return;
        case 1:
        case 2:
        case 3:
        case 5:
        case 6:
        case 7: {
            bool store = f3 >= 5;
            bool wide = (f3 & 3) == 3 || f3 == 1 || f3 == 5;
            inst->rs1 = creg(bits(x, 9, 7));
            if (f3 == 2 || f3 == 6)
                inst->imm = (int32_t) ((bits(x, 12, 10) << 3) |
                    (bits(x, 6, 6) << 2) | (bits(x, 5, 5) << 6));
            else
                inst->imm = (int32_t) ((bits(x, 12, 10) << 3) | (bits(x, 6, 5) << 6));
            if (store) {
                inst->rd = RV_NOREG;
                inst->rs2 = f3 == 5 ? RV_NOREG : creg(bits(x, 4, 2));
                set(inst, f3 == 5 ? RV_OP_FSD : (wide ? RV_OP_SD : RV_OP_SW), RV_STORE);
            } else {
                inst->rd = f3 == 1 ? RV_NOREG : creg(bits(x, 4, 2));
                inst->rs2 = RV_NOREG;
                set(inst, f3 == 1 ? RV_OP_FLD : (wide ? RV_OP_LD : RV_OP_LW), RV_LOAD);
            }
            return;
        }
        }
        return;
    case 1:
        switch (f3) {
        case 0:
            inst->rd = (uint8_t) bits(x, 11, 7);
            inst->rs1 = inst->rd;
            inst->imm = sext((bits(x, 12, 12) << 5) | bits(x, 6, 2), 6);
            set(inst, RV_OP_ADDI, RV_COMPUTE);
            return;
        case 1:
            if (bits(x, 11, 7) == 0)
                return;
            inst->rd = (uint8_t) bits(x, 11, 7);
            inst->rs1 = inst->rd;
            inst->imm = sext((bits(x, 12, 12) << 5) | bits(x, 6, 2), 6);
            set(inst, RV_OP_ADDIW, RV_COMPUTE);
            return;
        case 2:
            if (bits(x, 11, 7) == 0)
                return;
            inst->rd = (uint8_t) bits(x, 11, 7);
            inst->rs1 = RV_NOREG;
            inst->imm = sext((bits(x, 12, 12) << 5) | bits(x, 6, 2), 6);
            set(inst, RV_OP_ADDI, RV_COMPUTE);
            return;
        case 3:
            if (bits(x, 11, 7) == 2) {
                if ((bits(x, 12, 12) | bits(x, 6, 2)) == 0)
                    return;
                inst->rd = RV_SP;
                inst->rs1 = RV_SP;
                inst->imm = sext((bits(x, 12, 12) << 9) | (bits(x, 4, 3) << 7) |
                    (bits(x, 5, 5) << 6) | (bits(x, 2, 2) << 5) |
                    (bits(x, 6, 6) << 4), 10);
                set(inst, RV_OP_ADDI, RV_COMPUTE);
                return;
            }
            if (bits(x, 11, 7) == 0 || (bits(x, 12, 12) | bits(x, 6, 2)) == 0)
                return;
            inst->rd = (uint8_t) bits(x, 11, 7);
            inst->rs1 = RV_NOREG;
            inst->imm = sext((bits(x, 12, 12) << 17) | (bits(x, 6, 2) << 12), 18);
            set(inst, RV_OP_LUI, RV_COMPUTE);
            return;
        case 4: {
            uint32_t sel = bits(x, 11, 10);
            inst->rd = creg(bits(x, 9, 7));
            inst->rs1 = inst->rd;
            if (sel == 0 || sel == 1) {
                inst->imm = (int32_t) ((bits(x, 12, 12) << 5) | bits(x, 6, 2));
                set(inst, sel == 0 ? RV_OP_SRLI : RV_OP_SRAI, RV_COMPUTE);
                return;
            }
            if (sel == 2) {
                inst->imm = sext((bits(x, 12, 12) << 5) | bits(x, 6, 2), 6);
                set(inst, RV_OP_ANDI, RV_COMPUTE);
                return;
            }
            inst->rs2 = creg(bits(x, 4, 2));
            if (bits(x, 12, 12) == 0) {
                switch (bits(x, 6, 5)) {
                case 0: set(inst, RV_OP_SUB, RV_COMPUTE); return;
                case 1: set(inst, RV_OP_XOR, RV_COMPUTE); return;
                case 2: set(inst, RV_OP_OR, RV_COMPUTE); return;
                case 3: set(inst, RV_OP_AND, RV_COMPUTE); return;
                }
                return;
            }
            switch (bits(x, 6, 5)) {
            case 0: set(inst, RV_OP_SUBW, RV_COMPUTE); return;
            case 1: set(inst, RV_OP_ADDW, RV_COMPUTE); return;
            }
            return;
        }
        case 5:
            inst->rd = inst->rs1 = inst->rs2 = RV_NOREG;
            inst->imm = sext((bits(x, 12, 12) << 11) | (bits(x, 8, 8) << 10) |
                (bits(x, 10, 9) << 8) | (bits(x, 6, 6) << 7) |
                (bits(x, 7, 7) << 6) | (bits(x, 2, 2) << 5) |
                (bits(x, 11, 11) << 4) | (bits(x, 5, 3) << 1), 12);
            set(inst, RV_OP_JAL, RV_JAL);
            return;
        case 6:
        case 7:
            inst->rd = RV_NOREG;
            inst->rs1 = creg(bits(x, 9, 7));
            inst->rs2 = RV_NOREG;
            inst->imm = sext((bits(x, 12, 12) << 8) | (bits(x, 6, 5) << 6) |
                (bits(x, 2, 2) << 5) | (bits(x, 11, 10) << 3) |
                (bits(x, 4, 3) << 1), 9);
            set(inst, f3 == 6 ? RV_OP_BEQ : RV_OP_BNE, RV_BRANCH);
            return;
        }
        return;
    case 2:
        switch (f3) {
        case 0:
            if (bits(x, 11, 7) == 0)
                return;
            inst->rd = (uint8_t) bits(x, 11, 7);
            inst->rs1 = inst->rd;
            inst->imm = (int32_t) ((bits(x, 12, 12) << 5) | bits(x, 6, 2));
            set(inst, RV_OP_SLLI, RV_COMPUTE);
            return;
        case 1:
        case 2:
        case 3:
            inst->rs1 = RV_SP;
            inst->rs2 = RV_NOREG;
            if (f3 == 2) {
                if (bits(x, 11, 7) == 0)
                    return;
                inst->rd = (uint8_t) bits(x, 11, 7);
                inst->imm = (int32_t) ((bits(x, 12, 12) << 5) |
                    (bits(x, 6, 4) << 2) | (bits(x, 3, 2) << 6));
                set(inst, RV_OP_LW, RV_LOAD);
                return;
            }
            inst->imm = (int32_t) ((bits(x, 12, 12) << 5) |
                (bits(x, 6, 5) << 3) | (bits(x, 4, 2) << 6));
            if (f3 == 1) {
                inst->rd = RV_NOREG;
                set(inst, RV_OP_FLD, RV_LOAD);
                return;
            }
            if (bits(x, 11, 7) == 0)
                return;
            inst->rd = (uint8_t) bits(x, 11, 7);
            set(inst, RV_OP_LD, RV_LOAD);
            return;
        case 4: {
            uint32_t r1 = bits(x, 11, 7);
            uint32_t r2 = bits(x, 6, 2);
            if (bits(x, 12, 12) == 0) {
                if (r2 == 0) {
                    if (r1 == 0)
                        return;
                    inst->rd = RV_ZERO;
                    inst->rs1 = (uint8_t) r1;
                    inst->rs2 = RV_NOREG;
                    inst->imm = 0;
                    set(inst, RV_OP_JALR, RV_JALR);
                    return;
                }
                if (r1 == 0)
                    return;
                inst->rd = (uint8_t) r1;
                inst->rs1 = RV_ZERO;
                inst->rs2 = (uint8_t) r2;
                set(inst, RV_OP_ADD, RV_COMPUTE);
                return;
            }
            if (r1 == 0 && r2 == 0) {
                inst->rd = inst->rs1 = inst->rs2 = RV_NOREG;
                set(inst, RV_OP_EBREAK, RV_SYSTEM);
                return;
            }
            if (r2 == 0) {
                inst->rd = RV_RA;
                inst->rs1 = (uint8_t) r1;
                inst->rs2 = RV_NOREG;
                inst->imm = 0;
                set(inst, RV_OP_JALR, RV_JALR);
                return;
            }
            inst->rd = (uint8_t) r1;
            inst->rs1 = inst->rd;
            inst->rs2 = (uint8_t) r2;
            set(inst, RV_OP_ADD, RV_COMPUTE);
            return;
        }
        case 5:
        case 6:
        case 7:
            inst->rd = RV_NOREG;
            inst->rs1 = RV_SP;
            inst->rs2 = (uint8_t) bits(x, 6, 2);
            if (f3 == 6) {
                inst->imm = (int32_t) ((bits(x, 12, 9) << 2) | (bits(x, 8, 7) << 6));
                set(inst, RV_OP_SW, RV_STORE);
                return;
            }
            inst->imm = (int32_t) ((bits(x, 12, 10) << 3) | (bits(x, 9, 7) << 6));
            if (f3 == 5) {
                inst->rs2 = RV_NOREG;
                set(inst, RV_OP_FSD, RV_STORE);
                return;
            }
            set(inst, RV_OP_SD, RV_STORE);
            return;
        }
        return;
    }
}

bool
rv_decode(const uint8_t *bytes, size_t size, struct RvInst *inst)
{
    memset(inst, 0, sizeof(*inst));
    inst->op = RV_OP_UNKNOWN;
    inst->kind = RV_UNKNOWN;
    inst->rd = inst->rs1 = inst->rs2 = RV_NOREG;

    if (size < 2)
        return false;

    uint16_t low;
    memcpy(&low, bytes, sizeof(low));

    if ((low & 3) != 3) {
        inst->len = 2;
        decode16(low, inst);
        return true;
    }

    inst->len = 4;
    if (size < 4)
        return false;

    uint32_t word;
    memcpy(&word, bytes, sizeof(word));
    if ((word & 0x1f) == 0x1f)
        return true;
    decode32(word, inst);
    return true;
}

static const char *const names[RV_OP_MAXVAL] = {
    [RV_OP_UNKNOWN] = "unknown",
    [RV_OP_LUI] = "lui",
    [RV_OP_AUIPC] = "auipc",
    [RV_OP_JAL] = "jal",
    [RV_OP_JALR] = "jalr",
    [RV_OP_BEQ] = "beq",
    [RV_OP_BNE] = "bne",
    [RV_OP_BLT] = "blt",
    [RV_OP_BGE] = "bge",
    [RV_OP_BLTU] = "bltu",
    [RV_OP_BGEU] = "bgeu",
    [RV_OP_LB] = "lb",
    [RV_OP_LH] = "lh",
    [RV_OP_LW] = "lw",
    [RV_OP_LBU] = "lbu",
    [RV_OP_LHU] = "lhu",
    [RV_OP_LWU] = "lwu",
    [RV_OP_LD] = "ld",
    [RV_OP_SB] = "sb",
    [RV_OP_SH] = "sh",
    [RV_OP_SW] = "sw",
    [RV_OP_SD] = "sd",
    [RV_OP_ADDI] = "addi",
    [RV_OP_SLTI] = "slti",
    [RV_OP_SLTIU] = "sltiu",
    [RV_OP_XORI] = "xori",
    [RV_OP_ORI] = "ori",
    [RV_OP_ANDI] = "andi",
    [RV_OP_SLLI] = "slli",
    [RV_OP_SRLI] = "srli",
    [RV_OP_SRAI] = "srai",
    [RV_OP_ADD] = "add",
    [RV_OP_SUB] = "sub",
    [RV_OP_SLL] = "sll",
    [RV_OP_SLT] = "slt",
    [RV_OP_SLTU] = "sltu",
    [RV_OP_XOR] = "xor",
    [RV_OP_SRL] = "srl",
    [RV_OP_SRA] = "sra",
    [RV_OP_OR] = "or",
    [RV_OP_AND] = "and",
    [RV_OP_ADDIW] = "addiw",
    [RV_OP_SLLIW] = "slliw",
    [RV_OP_SRLIW] = "srliw",
    [RV_OP_SRAIW] = "sraiw",
    [RV_OP_ADDW] = "addw",
    [RV_OP_SUBW] = "subw",
    [RV_OP_SLLW] = "sllw",
    [RV_OP_SRLW] = "srlw",
    [RV_OP_SRAW] = "sraw",
    [RV_OP_FENCE] = "fence",
    [RV_OP_ECALL] = "ecall",
    [RV_OP_EBREAK] = "ebreak",
    [RV_OP_FENCE_I] = "fence.i",
    [RV_OP_CSRRW] = "csrrw",
    [RV_OP_CSRRS] = "csrrs",
    [RV_OP_CSRRC] = "csrrc",
    [RV_OP_CSRRWI] = "csrrwi",
    [RV_OP_CSRRSI] = "csrrsi",
    [RV_OP_CSRRCI] = "csrrci",
    [RV_OP_PRIVILEGED] = "privileged instruction",
    [RV_OP_MUL] = "mul",
    [RV_OP_MULH] = "mulh",
    [RV_OP_MULHSU] = "mulhsu",
    [RV_OP_MULHU] = "mulhu",
    [RV_OP_DIV] = "div",
    [RV_OP_DIVU] = "divu",
    [RV_OP_REM] = "rem",
    [RV_OP_REMU] = "remu",
    [RV_OP_MULW] = "mulw",
    [RV_OP_DIVW] = "divw",
    [RV_OP_DIVUW] = "divuw",
    [RV_OP_REMW] = "remw",
    [RV_OP_REMUW] = "remuw",
    [RV_OP_LR] = "lr",
    [RV_OP_SC] = "sc",
    [RV_OP_AMOSWAP] = "amoswap",
    [RV_OP_AMOADD] = "amoadd",
    [RV_OP_AMOXOR] = "amoxor",
    [RV_OP_AMOAND] = "amoand",
    [RV_OP_AMOOR] = "amoor",
    [RV_OP_AMOMIN] = "amomin",
    [RV_OP_AMOMAX] = "amomax",
    [RV_OP_AMOMINU] = "amominu",
    [RV_OP_AMOMAXU] = "amomaxu",
    [RV_OP_FLW] = "flw",
    [RV_OP_FLD] = "fld",
    [RV_OP_FSW] = "fsw",
    [RV_OP_FSD] = "fsd",
    [RV_OP_FMADD] = "fmadd",
    [RV_OP_FMSUB] = "fmsub",
    [RV_OP_FNMSUB] = "fnmsub",
    [RV_OP_FNMADD] = "fnmadd",
    [RV_OP_FP] = "floating-point operation",
    [RV_OP_FCMP] = "floating-point comparison",
    [RV_OP_FCVT_INT] = "fcvt",
    [RV_OP_FMV_X] = "fmv.x",
    [RV_OP_FCLASS] = "fclass",
    [RV_OP_ADD_UW] = "add.uw",
    [RV_OP_SH1ADD] = "sh1add",
    [RV_OP_SH2ADD] = "sh2add",
    [RV_OP_SH3ADD] = "sh3add",
    [RV_OP_SH1ADD_UW] = "sh1add.uw",
    [RV_OP_SH2ADD_UW] = "sh2add.uw",
    [RV_OP_SH3ADD_UW] = "sh3add.uw",
    [RV_OP_SLLI_UW] = "slli.uw",
    [RV_OP_ANDN] = "andn",
    [RV_OP_ORN] = "orn",
    [RV_OP_XNOR] = "xnor",
    [RV_OP_CLZ] = "clz",
    [RV_OP_CLZW] = "clzw",
    [RV_OP_CTZ] = "ctz",
    [RV_OP_CTZW] = "ctzw",
    [RV_OP_CPOP] = "cpop",
    [RV_OP_CPOPW] = "cpopw",
    [RV_OP_MAX] = "max",
    [RV_OP_MAXU] = "maxu",
    [RV_OP_MIN] = "min",
    [RV_OP_MINU] = "minu",
    [RV_OP_SEXT_B] = "sext.b",
    [RV_OP_SEXT_H] = "sext.h",
    [RV_OP_ZEXT_H] = "zext.h",
    [RV_OP_ROL] = "rol",
    [RV_OP_ROLW] = "rolw",
    [RV_OP_ROR] = "ror",
    [RV_OP_RORI] = "rori",
    [RV_OP_RORIW] = "roriw",
    [RV_OP_RORW] = "rorw",
    [RV_OP_ORC_B] = "orc.b",
    [RV_OP_REV8] = "rev8",
    [RV_OP_BCLR] = "bclr",
    [RV_OP_BCLRI] = "bclri",
    [RV_OP_BEXT] = "bext",
    [RV_OP_BEXTI] = "bexti",
    [RV_OP_BINV] = "binv",
    [RV_OP_BINVI] = "binvi",
    [RV_OP_BSET] = "bset",
    [RV_OP_BSETI] = "bseti",
};

const char *
rv_name(enum RvOp op)
{
    if (op >= RV_OP_MAXVAL || !names[op])
        return "unknown";
    return names[op];
}
