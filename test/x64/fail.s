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
// direct branch into the middle of an instruction
jmp foo+1
foo:
movl $1, %eax
---
// direct branch into the middle of an instruction (backward)
foo:
movl $1, %eax
jmp foo+2
---
// direct branch into the interior of a jmp macroinstruction
jmp 1f
andl $0xffffffe0, %eax
1:
addq %r14, %rax
jmp *%rax
---
// direct branch into the interior of a jmp macroinstruction (backward)
andl $0xffffffe0, %eax
1:
addq %r14, %rax
jmp *%rax
jmp 1b
---
// conditional direct branch into the interior of a jmp macroinstruction
andl $0xffffffe0, %eax
addq %r14, %rax
1:
jmp *%rax
jz 1b
---
// direct branch into the nop padding of a call macroinstruction
jmp 1f
.nops 5
andl $0xffffffe0, %eax
addq %r14, %rax
1:
.nops 17
callq *%rax
---
// direct call into the interior of a call macroinstruction
call 1f
.nops 5
andl $0xffffffe0, %eax
addq %r14, %rax
.nops 14
1:
callq *%rax
---
// direct branch into the interior of an rtcall macroinstruction
leaq 1f(%rip), %r11
2:
jmpq *-8(%r14)
1:
jmp 2b
---
// direct branch into the interior of a load macroinstruction
movl %r11d, %r11d
1:
movq (%r14, %r11), %rax
jmp 1b
---
// direct branch into the interior of a stack pointer macroinstruction
movl %eax, %esp
1:
addq %r14, %rsp
jmp 1b
---
// non-bundle-aligned direct branch outside the code region
jmp _start+1000001
---
// non-bundle-aligned direct branch before the code region
jmp _start-7
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
// flags: --sandbox=jumps
// indirect branches are still checked
jmp *%rax
---
// flags: --sandbox=jumps
// indirect branches are still checked
jmp *(%rdi)
---
// flags: --sandbox=jumps
// direct branch targets are still checked
jmp foo+1
foo:
movl $1, %eax
---
// flags: --sandbox=jumps
// reserved registers still cannot be modified
movq (%rdi), %r14
---
// flags: --sandbox=jumps
// reserved registers still cannot be modified
movq (%rdi), %rsp
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
// rtcall macro: 32-bit lea truncates the return address
leal 1f(%rip), %r11d
jmpq *(%r14)
1:
---
// rtcall macro: 16-bit lea truncates the return address
leaw 1f(%rip), %r11w
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
---
// flags: --no-bdd
cmpzxadd %rbx, %r15, (%r14)
---
// flags: --no-bdd
cmpnzxadd %rbx, %r14, (%r14)
---
// flags: --no-bdd
cmpoxadd %rbx, %rsp, (%r14)
---
// flags: --no-bdd
.byte 0x66, 0x41, 0x0f, 0x8c, 0x18, 0x00, 0x0f, 0x05
---
// flags: --align-branches
// a non-bundle-aligned target is rejected even though it is an instruction boundary
jmp foo
nop
foo:
nop
---
// flags: --align-branches
// backward non-bundle-aligned target is rejected
nop
foo:
nop
jmp foo
