#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "lfiv.h"

#include "decode.h"

enum {
  ERRMAX = 128,

  BUNDLE = 8,
  BUNDLE_MASK = -8,

  // The runtime call table sits at the start of the sandbox, and the
  // displacement that reaches it is bounded by the specification.
  RTCALL_MAX = 256,

  CSR_FFLAGS = 0x001,
  CSR_FRM = 0x002,
  CSR_FCSR = 0x003,
};

struct Verifier {
  bool failed;
  struct LFIVOptions *opts;

  struct RvInst prev;
  uintptr_t prev_addr;
  bool has_prev;

  uintptr_t addr;

  const uint8_t *code;
  uintptr_t base;
  size_t size;
};

static void verr(struct Verifier *v, const char *fmt, ...) {
  v->failed = true;

  if (!v->opts->err)
    return;

  va_list ap;
  char errbuf[ERRMAX];

  va_start(ap, fmt);
  vsnprintf(errbuf, ERRMAX, fmt, ap);
  va_end(ap);

  v->opts->err(errbuf, strlen(errbuf));
}

// add.uw <reg>, xN, x21
static bool is_adduw(const struct RvInst *inst, uint8_t reg) {
  return inst->op == RV_OP_ADD_UW && inst->rd == reg && inst->rs2 == RV_BASE;
}

// andi x18, x18, -8
static bool is_guard(const struct RvInst *inst) {
  return inst->op == RV_OP_ANDI && inst->rd == RV_ADDR &&
         inst->rs1 == RV_ADDR && inst->imm == BUNDLE_MASK && !inst->compressed;
}

// ld ra, N(x21) where N % 8 == 0 and N < 256
static bool is_rtcall_load(const struct RvInst *inst) {
  return inst->op == RV_OP_LD && inst->rd == RV_RA && inst->rs1 == RV_BASE &&
         inst->imm >= 0 && inst->imm < RTCALL_MAX && inst->imm % 8 == 0;
}

static bool same_bundle(uintptr_t a, uintptr_t b) {
  return a / BUNDLE == b / BUNDLE;
}

static bool ok_target(struct Verifier *v, uintptr_t target) {
  if (target < v->base || target >= v->base + v->size)
    return false;

  size_t off = (size_t)(target - v->base);
  if (off % 2 != 0)
    return false;

  size_t at = off & ~(size_t)(BUNDLE - 1);
  while (at < off) {
    struct RvInst inst;
    if (!rv_decode(v->code + at, v->size - at, &inst))
      return false;
    at += inst.len;
  }
  if (at != off)
    return false;

  struct RvInst inst;
  if (!rv_decode(v->code + off, v->size - off, &inst))
    return false;
  return inst.kind != RV_JALR;
}

static bool ok_base(uint8_t reg) { return reg == RV_ADDR || reg == RV_SP; }

static void chkmem(struct Verifier *v, const struct RvInst *inst) {
  if (inst->kind != RV_LOAD && inst->kind != RV_STORE && inst->kind != RV_AMO)
    return;

  if (v->opts->box == LFI_BOX_STORES && inst->kind == RV_LOAD)
    return;

  if (is_rtcall_load(inst))
    return;

  if (!ok_base(inst->rs1))
    verr(v, "%lx: %s: memory operand must be based on x18 or sp", v->addr,
         rv_name(inst->op));
}

static void chkmod(struct Verifier *v, const struct RvInst *inst) {
  uint8_t reg = inst->rd;
  if (reg == RV_NOREG || reg == RV_ZERO)
    return;

  if (reg == RV_BASE) {
    verr(v, "%lx: %s: write to the sandbox base register x21", v->addr,
         rv_name(inst->op));
    return;
  }

  if (reg == RV_ADDR) {
    if (is_adduw(inst, RV_ADDR))
      return;
    if (is_guard(inst))
      return;
    verr(v, "%lx: %s: x18 may only be written by add.uw x18, xN, x21", v->addr,
         rv_name(inst->op));
    return;
  }

  if (reg == RV_RA) {
    if (is_adduw(inst, RV_RA))
      return;
    if (is_rtcall_load(inst))
      return;
    if (inst->kind == RV_JAL || inst->kind == RV_JALR)
      return;
    verr(v,
         "%lx: %s: ra may only be written by add.uw ra, xN, x21, by a "
         "runtime call load, or by a call",
         v->addr, rv_name(inst->op));
    return;
  }

  if (reg == RV_SP) {
    if (is_adduw(inst, RV_SP))
      return;
    verr(v, "%lx: %s: sp may only be written by add.uw sp, xN, x21", v->addr,
         rv_name(inst->op));
    return;
  }
}

static void chkcsr(struct Verifier *v, const struct RvInst *inst) {
  if (inst->kind != RV_CSR)
    return;

  switch (inst->imm) {
  case CSR_FFLAGS:
  case CSR_FRM:
  case CSR_FCSR:
    return;
  }

  verr(v, "%lx: %s: access to csr 0x%x is not permitted", v->addr,
       rv_name(inst->op), (unsigned)inst->imm);
}

static void chkflow(struct Verifier *v, const struct RvInst *inst) {
  if (inst->kind != RV_JALR)
    return;

  if (inst->compressed) {
    verr(v, "%lx: compressed indirect branch", v->addr);
    return;
  }

  if (inst->imm != 0) {
    verr(v, "%lx: jalr with a displacement", v->addr);
    return;
  }

  if (!v->has_prev || !same_bundle(v->prev_addr, v->addr)) {
    verr(v, "%lx: indirect branch is not part of a macroinstruction", v->addr);
    return;
  }

  if (inst->rs1 == RV_ADDR) {
    if (!is_guard(&v->prev)) {
      verr(v,
           "%lx: indirect branch through x18 must follow "
           "andi x18, x18, -8",
           v->addr);
      return;
    }
    if (inst->rd != RV_ZERO && inst->rd != RV_RA)
      verr(v, "%lx: indirect branch links into an illegal register", v->addr);
    return;
  }

  if (inst->rs1 == RV_RA && inst->rd == RV_RA) {
    if (!is_rtcall_load(&v->prev))
      verr(v,
           "%lx: runtime call must follow ld ra, N(x21) with "
           "N %% 8 == 0 and N < %d",
           v->addr, RTCALL_MAX);
    return;
  }

  verr(v, "%lx: indirect branch through an illegal register", v->addr);
}

static void chk(struct Verifier *v, const struct RvInst *inst) {
  if (inst->kind == RV_UNKNOWN) {
    verr(v, "%lx: unknown instruction", v->addr);
    return;
  }

  if (inst->kind == RV_SYSTEM) {
    verr(v, "%lx: %s: system instructions are not permitted", v->addr,
         rv_name(inst->op));
    return;
  }

  if (v->addr % BUNDLE + inst->len > BUNDLE) {
    verr(v, "%lx: %s: instruction crosses a bundle boundary", v->addr,
         rv_name(inst->op));
    return;
  }

  chkmod(v, inst);
  chkmem(v, inst);
  chkcsr(v, inst);
  chkflow(v, inst);

  if (inst->kind == RV_JAL || inst->kind == RV_BRANCH) {
    uintptr_t target = v->addr + (uintptr_t)(intptr_t)inst->imm;
    if (!ok_target(v, target))
      verr(v,
           "%lx: %s: branch to %lx, which is not an entry point in "
           "this segment",
           v->addr, rv_name(inst->op), target);
  }
}

bool lfiv_verify_riscv64(char *code, size_t size, uintptr_t addr,
                         struct LFIVOptions *opts) {
  if (size % 2 != 0)
    return false;
  if (addr % BUNDLE != 0)
    return false;

  struct Verifier v = {
      .opts = opts,
      .code = (const uint8_t *)code,
      .base = addr,
      .size = size,
  };

  size_t off = 0;
  while (off < size) {
    struct RvInst inst;
    v.addr = addr + off;

    if (!rv_decode(v.code + off, size - off, &inst)) {
      verr(&v, "%lx: truncated instruction", v.addr);
      break;
    }

    chk(&v, &inst);

    if (v.failed && v.opts->err == NULL)
      break;

    v.prev = inst;
    v.prev_addr = v.addr;
    v.has_prev = true;
    off += inst.len;
  }

  return !v.failed;
}
