
.global _start
_start:
	mov %rsp, %rdi
	call relocateSelf

	mov %rsp, %rdi
	call interpreterMain

	jmp *%rax
.section .note.GNU-stack,"",%progbits

