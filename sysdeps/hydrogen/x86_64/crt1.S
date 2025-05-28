#ifndef PIC
#define PIC 0
#endif

#ifndef PIE
#define PIE 0
#endif

.section ".text._start", "ax", @progbits

.balign 16
.globl _start
.hidden _start
.type _start, @function
_start:
    .cfi_startproc
    .cfi_undefined rip
    .cfi_undefined rsp

    xor %ebp, %ebp
    mov %rsp, %rdi
#if PIE
    lea main(%rip), %rsi
#elif PIC
    mov main@GOTPCREL(%rip), %rsi
#else
    mov $main, %rsi
#endif
    call __mlibc_entry
    ud2

    .cfi_endproc
.size _start, . - _start

.section ".note.GNU-stack", "", @progbits
