// a memory operand based on anything but x18 or sp
.option norvc
ld a0, 0(a1)
---
.option norvc
sd a0, 0(a1)
---
.option norvc
lbu a0, 0(x21)
---
.option norvc
fsd ft0, 0(a1)
---
.option norvc
amoadd.d a0, a1, (a2)
---
.option norvc
lr.d a0, (a1)
---
// writes to the reserved registers
.option norvc
mv x21, a0
---
.option norvc
mv x18, a0
---
.option norvc
mv sp, a0
---
.option norvc
mv ra, a0
---
.option norvc
addi sp, sp, -16
---
.option norvc
add.uw x18, x0, a0
---
.option norvc
add.uw sp, x21, a0
---
// an atomic whose destination is a reserved register
.option norvc
amoadd.d sp, a1, (x18)
---
// the compressed prologue that adjusts sp
c.addi16sp sp, -16
---
c.mv sp, a0
---
// indirect branches outside a macroinstruction
.option norvc
jr x18
---
.option norvc
jalr ra
---
.option norvc
jalr a0
---
.option norvc
ret
---
// an indirect branch whose bundle neighbour is not the mask
.option norvc
nop
jr x18
---
// a runtime call whose bundle neighbour is not the table load
.option norvc
nop
jalr ra
---
// a masked indirect branch that links into a register other than ra
.option norvc
andi x18, x18, -8
jalr a0, 0(x18)
---
// a mask that is not the bundle mask
.option norvc
andi x18, x18, -4
jr x18
---
// the guard and the branch in different bundles
.option norvc
nop
andi x18, x18, -8
jr x18
---
// a runtime call displacement that is not a multiple of eight
.option norvc
ld ra, 4(x21)
jalr ra
---
// a runtime call displacement past the end of the table
.option norvc
ld ra, 256(x21)
jalr ra
---
// a runtime call whose load is not from the base register
.option norvc
ld ra, 0(sp)
jalr ra
---
// an indirect branch with a displacement
.option norvc
andi x18, x18, -8
jalr ra, 8(x18)
---
// compressed indirect branches are refused rather than accepted as a half
c.jr a0
---
c.jalr a0
---
// system instructions
.option norvc
ecall
---
.option norvc
ebreak
---
.option norvc
csrr a0, cycle
---
// a permitted csr still may not be read into a reserved register
.option norvc
csrr sp, fcsr
---
.option norvc
csrr a0, satp
---
.option norvc
csrw sscratch, a0
---
.option norvc
sret
---
.option norvc
wfi
---
.option norvc
sfence.vma
---
.option norvc
fence.i
---
// an instruction that straddles a bundle boundary
.option rvc
c.nop
c.nop
c.nop
.option norvc
addi a0, a0, 1
---
// an encoding this verifier does not name
.word 0x0000007b
---
// a direct branch into the second half of a macroinstruction, which would
// reach the indirect branch without its mask
.option norvc
nop
beq a0, a1, target
andi x18, x18, -8
target:
jr x18
---
// a stores-only sandbox still confines the stores
// flags: --sandbox=stores
.option norvc
sd a0, 0(a1)
---
// flags: --sandbox=stores
.option norvc
amoadd.d a0, a1, (a2)
