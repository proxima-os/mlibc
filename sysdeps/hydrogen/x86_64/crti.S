.section ".init", "ax", @progbits

.balign 16
.globl _init
.hidden _init
.type _init, @function
_init:

.section ".fini", "ax", @progbits

.balign 16
.globl _fini
.hidden _fini
.type _fini, @function
_fini:

.section ".note.GNU-stack", "", @progbits
