add $8, %rdi
---
.bundle_align_mode 5
add $8, %rdi
add $8, %rdi
add $8, %rdi
add $8, %rdi
add $8, %rdi
add $8, %rdi
add $8, %rdi
add $8, %rdi
add $8, %rdi
add $8, %rdi
add $8, %rdi
add $8, %rdi
jmp foo
nop
add $8, %rdi
.p2align 5
foo:
---
// direct branch to a non-bundle-aligned instruction boundary
jmp foo
nop
foo:
nop
---
// backward direct branch to a non-bundle-aligned instruction boundary
nop
foo:
nop
jmp foo
---
// conditional direct branch to a non-bundle-aligned instruction boundary
nop
foo:
add $8, %rdi
jnz foo
---
// direct call to a non-bundle-aligned instruction boundary
call foo
nop
foo:
nop
---
// direct branch to the start of a macroinstruction
jmp 1f
nop
1:
andl $0xffffffe0, %eax
addq %r14, %rax
jmp *%rax
---
// direct branch to the start of a call macroinstruction
jmp 1f
.nops 5
1:
andl $0xffffffe0, %eax
addq %r14, %rax
.nops 17
callq *%rax
---
// direct branch to the instruction after an rtcall macroinstruction
jmp 1f
leaq 1f(%rip), %r11
jmpq *-8(%r14)
1:
nop
---
// direct branch to the start of a load macroinstruction
jmp 1f
nop
1:
movl %r11d, %r11d
movq (%r14, %r11), %rax
---
// direct branch to a non-bundle-aligned instruction in a different bundle
jmp foo
.nops 40
foo:
nop
---
// bundle-aligned direct branch outside the code region is still permitted
jmp _start+1000000
---
mov %gs:(%eax), %rax
---
mov %gs:12(%eax, %edi, 4), %rax
---
leaq 8(%rax), %rax
---
mov 12(%rsp), %rax
---
mov 12(%rip), %rax
---
andl $0xffffffe0, %eax
addq %r14, %rax
jmp *%rax
---
movl %eax, %esp
addq %r14, %rsp
---
add $12, %esp
addq %r14, %rsp
---
andl $0xfffffff0, %esp
addq %r14, %rsp
---
cmp %rsp, %rsp
---
andl $0xffffffe0, %eax
addq %r14, %rax
.nops 24
callq *%rax
---
.nops 2
andl $0xffffffe0, %eax
addq %r14, %rax
.nops 22
callq *%rax
---
leaq 1f(%rip), %r11
jmpq *(%r14)
1:
---
leaq 1f(%rip), %r11
jmpq *8(%r14)
1:
---
leaq 1f(%rip), %r11
jmpq *(%r14)
.p2align 5
1:
---
lea -0x10(%ebp), %esp
lea (%rsp, %r14, 1), %rsp
---
movaps -0x7884(%rip),%xmm4
---
cld
---
std
---
pause
---
movl %r11d, %r11d
movq (%r14, %r11), %rax
---
// flags: --sandbox=stores
movq (%rdi), %rax
---
// flags: --sandbox=jumps
movq (%rdi), %rax
---
// flags: --sandbox=jumps
movq %rax, (%rdi)
---
// flags: --sandbox=jumps
movq %rax, (%rdi, %rsi, 8)
---
// flags: --sandbox=jumps
movq %rax, (%edi)
---
// flags: --sandbox=jumps
bts %rax, (%rdi)
---
// flags: --sandbox=jumps
addq $1, (%r15)
---
leaq 1f(%rip), %r11
jmpq *-8(%r14)
1:
---
leaq 1f(%rip), %r11
jmpq *-16(%r14)
1:
---
leaq 1f(%rip), %r11
jmpq *-24(%r14)
1:
---
leaq 1f(%rip), %r11
jmpq *-32(%r14)
1:
---
movq 8(%r14), %rdi
---
movq 16(%r15), %rax
---
movq %rax, 16(%r15)
---
movq 16(%r15), %rdi
movq %rsi, 16(%r15)
---
movl %edi, %edi
leaq (%r14, %rdi), %rdi
rep stosq
---
movl %edi, %edi
leaq (%r14, %rdi), %rdi
movl %esi, %esi
leaq (%r14, %rsi), %rsi
rep movsq
---
movl %edi, %edi
leaq (%r14, %rdi), %rdi
movl %esi, %esi
leaq (%r14, %rsi), %rsi
rep cmpsq
---
// bit-test with an immediate offset is bounded to the addressed unit
bt $5, (%r14)
---
bts $100, (%r14)
---
// bit-test with a register bit base (not memory) is safe: offset is mod size
bt %rax, %rbx
---
bts %rax, %rbx
---
// flags: --no-bdd
cmpoxadd %rbx, %rcx, (%r14)
---
// flags: --align-branches
// bundle-aligned direct branch is still permitted in strict mode
jmp foo
.p2align 5
foo:
nop
