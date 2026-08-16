.option norvc
add.uw x18, x0, x21
---
.option norvc
add.uw sp, a0, x21
---
.option norvc
add.uw ra, a0, x21
---
.option norvc
ld a0, 0(x18)
---
.option norvc
lw a0, -4(x18)
---
.option norvc
lbu a0, 2047(x18)
---
.option norvc
sd a0, 8(sp)
---
.option norvc
sb a0, -2048(sp)
---
// the indirect branch macroinstruction, contiguous in one bundle
.option norvc
andi x18, x18, -8
jr x18
---
// the same macroinstruction, linking into ra
.option norvc
andi x18, x18, -8
jalr x18
---
// a runtime call at index zero
.option norvc
ld ra, 0(x21)
jalr ra
---
// a runtime call at the last index the displacement can reach
.option norvc
ld ra, 248(x21)
jalr ra
---
// a call, and the return sequence that reconstructs an address from ra
.option norvc
jal ra, foo
foo:
add.uw x18, ra, x21
andi x18, x18, -8
jr x18
---
.option norvc
beq a0, a1, foo
foo:
nop
---
.option norvc
bltu a0, a1, foo
nop
foo:
nop
---
.option norvc
amoadd.d a0, a1, (x18)
---
.option norvc
amoswap.w.aq a0, a1, (sp)
---
.option norvc
lr.d a0, (x18)
---
.option norvc
sc.d a0, a1, (sp)
---
.option norvc
fld ft0, 16(x18)
---
.option norvc
fsd ft0, 16(sp)
---
.option norvc
fadd.d ft0, ft1, ft2
---
.option norvc
fcvt.l.d a0, ft0
---
.option norvc
fmv.x.d a0, ft0
---
.option norvc
feq.d a0, ft0, ft1
---
.option norvc
fmadd.d ft0, ft1, ft2, ft3
---
.option norvc
sh3add.uw a0, a1, a2
---
.option norvc
slli.uw a0, a1, 2
---
.option norvc
sext.b a0, a1
---
.option norvc
rev8 a0, a1
---
.option norvc
orc.b a0, a1
---
.option norvc
clzw a0, a1
---
.option norvc
rolw a0, a1, a2
---
.option norvc
max a0, a1, a2
---
.option norvc
xnor a0, a1, a2
---
.option norvc
rori a0, a1, 7
---
.option norvc
bseti a0, a1, 3
---
.option norvc
mul a0, a1, a2
---
.option norvc
divuw a0, a1, a2
---
.option norvc
fence
---
.option norvc
fence iorw, iorw
---
.option norvc
fence.tso
---
// a rounding mode the encoding is allowed to carry
.option norvc
fadd.d ft0, ft1, ft2, rtz
---
.option norvc
fcvt.d.s ft0, ft1
---
.option norvc
fcvt.s.d ft0, ft1
---
// the floating-point control registers, and nothing else
.option norvc
csrr a0, fcsr
---
.option norvc
csrrw a0, frm, a1
---
.option norvc
csrrsi a0, fflags, 1
---
.option norvc
frrm a0
---
.option norvc
auipc a0, 0
---
.option norvc
lui a0, 1
---
.option norvc
addiw a0, a1, 1
---
// compressed instructions are allowed where they do not break a rule
c.nop
---
c.ldsp a0, 8(sp)
---
c.sdsp a0, 8(sp)
---
c.li a0, 3
---
c.add a0, a1
---
// a stores-only sandbox leaves reads alone
// flags: --sandbox=stores
.option norvc
ld a0, 0(a1)
---
// flags: --sandbox=stores
.option norvc
flw ft0, 0(a1)
