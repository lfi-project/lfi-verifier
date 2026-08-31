mov %rdi, %rdi
mov %rdi, %rdi
mov %rdi, %rdi
mov %rdi, %rdi
mov %rdi, %rdi
mov %rdi, %rdi
mov %rdi, %rdi
mov %rdi, %rdi
mov %rdi, %rdi
mov %rdi, %rdi
mov %rdi, %rdi
mov %rdi, %rdi
---
jmp foo
nop
foo:
nop
---
jmpq *%rax
---
mov %gs:(%rax), %rax
---
mov (%rsp, %rax), %rax
---
mov (%rax), %rax
---
mov (%esp), %rax
---
jmp *%rax
---
andl $0xffffffff, %eax
addq %r14, %rax
jmp *%rax
---
andq $0xffffffffffffffe0, %rax
addq %r14, %rax
jmp *%rax
---
andl $0xffffffe0, %eax
jmp *%rax
---
andl $0xffffffe0, %eax
orl %r14d, %eax
jmp *%rax
---
mov %rax, %r14
---
mov $0, %r14
---
mov %rax, %rsp
---
mov $0, %rsp
---
add $12, %rsp
---
xchg %r14, %rax
---
callq *%rax
---
andl $0xffffffe0, %eax
addq %r14, %rax
.nops 28
callq *%rax
---
andl $0xffffffe0, %eax
addq %r14, %rax
callq *%rax
---
jmpq *(%r14)
---
leaq 1f(%rip), %r11
jmpq *(%r14)
nop
1:
---
leaq 1f(%rip), %r12
jmpq *(%r14)
1:
---
leaq 1f(%rip), %r11
jmpq *4(%r14)
1:
---
leaq 1f(%rip), %r11
jmpq *(%r14, %rax)
1:
---
mov %fs:0, %rax
---
mov %fs:(%rsp), %rax
---
mov %fs:(%rip), %rax
---
mov %gs, %rax
---
mov %rax, %gs
---
syscall
---
wrgsbase %r11
---
wrfsbase %r11
---
ldmxcsr 0(%rip)
---
fxrstor 0(%rip)
---
movq %r11, %r11
movq (%r14, %r11), %rax
---
movl %r11d, %r11d
movq (%r14, %r11), %r14
---
andl $0xffffffe0, %r14d
addq %r14, %r14
jmp *%r14
---
// flags: --sandbox=stores
movq %rax, (%rdi)
---
movq (%r14, %rax), %rdi
---
movq (%rsp, %r14), %rdi
---
// modification of r15 is not allowed
mov %rax, %r15
---
// non-64-bit mov from r15 is not allowed
movl (%r15), %eax
---
// r15 with wrong displacement is not allowed
movq 8(%r15), %rax
---
// r15 with zero displacement is not allowed
movq (%r15), %rax
---
// only mov is allowed with r15, not add
addq 16(%r15), %rax
---
// mulx: two destinations
mulx %eax, %esp, %ebx
---
// xadd: two destinations
xadd %esp, %eax
---
stosq
---
movsq
---
cmpsq
---
bt %rax, (%r14)
---
bts %rax, (%r14)
---
btr %rax, (%r14)
---
btc %rax, (%r14)
---
bts %rax, 8(%r14)
---
bt %rax, (%rsp)
---
movl %edi, %edi
.byte 0x67
leaq (%r14, %rdi), %rdi
rep stosq
---
// stos macro: 32-bit address size on the store itself
movl %edi, %edi
leaq (%r14, %rdi), %rdi
.byte 0x67
rep stosq
---
// load macro: 32-bit address size on the dereference
movl %eax, %eax
.byte 0x67
movq (%r14, %rax), %rax
---
// movs macro: 32-bit address size on the first lea
movl %edi, %edi
.byte 0x67
leaq (%r14, %rdi), %rdi
movl %esi, %esi
leaq (%r14, %rsi), %rsi
rep movsq
---
// cmps macro: 32-bit address size on the compare itself
movl %edi, %edi
leaq (%r14, %rdi), %rdi
movl %esi, %esi
leaq (%r14, %rsi), %rsi
.byte 0x67
rep cmpsq
---
// modsp macro: 32-bit address size on the pointer-forming lea
movl %eax, %esp
.byte 0x67
lea (%rsp, %r14, 1), %rsp
---
// rtcall macro: 32-bit address size on the memory-indirect jump
leaq 1f(%rip), %r11
.byte 0x67
jmpq *(%r14)
1:
---
// modsp macro: an unsandboxed memory source into %esp is not permitted
addl (%rax), %esp
addq %r14, %rsp
---
// modsp macro: an unsandboxed memory source (mov) into %esp is not permitted
movl (%rax), %esp
addq %r14, %rsp
---
// modsp macro: subtracting from an unsandboxed memory source is not permitted
subl (%rax), %esp
addq %r14, %rsp
