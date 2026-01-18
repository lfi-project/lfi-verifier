ldr x0, [x28]
---
add x28, x27, w0, uxtw
---
ldr x0, [x27, w0, uxtw]
---
b foo
foo:
---
br x28
---
ret
---
foo:
bl foo
---
ldr x0, [sp]
---
ldr x0, [sp], #16
---
ldr x0, [sp, 16]!
---
add sp, x27, w0, uxtw
---
nop
---
ldr x0, [x28, #4096]
---
str x0, [x28, #4096]
---
ld4 { v29.2s, v30.2s, v31.2s, v0.2s }, [x28]
---
brk #0x281a
---
str w28, [sp, #0x3a38]
---
movk x1, #0x9ec0, lsl #32
---
uaddl2 v12.4s, v2.8h, v19.8h
---
tbx v19.16b, { v26.16b }, v14.16b
---
extr x1, x8, x15, #0
---
stp s24, s9, [sp], #-0x10
---
ands x16, x30, #0x8f8f8f8f8f8f8f8f
---
str q0, [x28, #55696]
---
stp x29, x30, [sp], #16
---
ldr x30, [x27]
---
ldr x30, [x27, #8]
---
ldr x30, [x27, #16]
---
str w28, [x28]
---
stp xzr, xzr, [sp, #-0x10]!
---
swpal w0, w0, [x28]
---
ldadd w0, w0, [x28]
---
// flags: --sandbox=stores
ldr x0, [x1]
---
// flags: --sandbox=stores
ldr x0, [x1], #16
---
.arch_extension pauth
autiasp
---
.arch_extension pauth
paciasp
---
ldur x30, [x27, #-8]
---
ldur x30, [x27, #-16]
---
ldur x30, [x27, #-24]
---
ldur x30, [x27, #-32]
---
// x30 modification followed by guard and ret
mov x30, x0
add x30, x27, w30, uxtw
ret
---
// x30 load from stack followed by guard and branch
ldr x30, [sp]
add x30, x27, w30, uxtw
br x30
---
// Multiple x30 modifications before guard
mov x30, x1
mov x30, x2
add x30, x27, w30, uxtw
ret
---
// Load from stack, authenticate, guard, then return
.arch_extension pauth
ldr x30, [sp]
autiasp
add x30, x27, w30, uxtw
ret
---
// x30 guarded before direct branch
mov x30, x0
add x30, x27, w30, uxtw
b foo
foo:
---
// x30 guarded before conditional branch
mov x30, x0
add x30, x27, w30, uxtw
cbz x0, foo
foo:
---
add x30, x27, w26, uxtw
ret
---
ldr xzr, [x30]
---
// flags: --ctxreg
ldr x0, [x25, #32]
---
// flags: --ctxreg
str x0, [x25, #32]
---
// flags: --ctxreg
ldr x0, [x25, #32]
str x1, [x25, #32]
