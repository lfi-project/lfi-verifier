.section .rodata

.align 4
.global lfi_bdd_data
lfi_bdd_data:
    .incbin "src/x64/x86-all.bdd.bin"
.global lfi_bdd_data_end
lfi_bdd_data_end:
