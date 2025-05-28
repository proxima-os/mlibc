.section ".text.__mlibc_hydrogen_thread_entry", "ax", @progbits

.balign 16
.globl __mlibc_hydrogen_thread_entry
.hidden __mlibc_hydrogen_thread_entry
.type __mlibc_hydrogen_thread_entry, @function
__mlibc_hydrogen_thread_entry:
    pop %rdi
    pop %rsi
    pop %rdx
    call __mlibc_hydrogen_thread_start
    ud2
.size __mlibc_hydrogen_thread_entry, . - __mlibc_hydrogen_thread_entry

.section ".note.GNU-stack", "", @progbits
