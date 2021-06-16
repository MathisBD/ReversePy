// Just a trivial program, so that I can
// easily view its control flow graph (and verify 
// it is correct).
// Just compile it with gcc, then run the pintool on it.

.extern printf 
.global main

.text 

fact:
	mov $1, %rcx 
	mov $1, %rax 
fact_loop:
	cmp %rcx, %rdi 
	jl fact_end
	imul %rcx, %rax 
	inc %rcx
	jmp fact_loop
fact_end:
	ret 

main:
	push %rbp 
	mov %rsp, %rbp 

	// calculate n
	mov $4, %rdi
	call fact 

	// print the message
	mov $msg, %rdi 
	mov %rax, %rsi 
	xor %rax, %rax 
	call printf

	xor %rax, %rax 	
	leave 
	ret 

.data 
msg: .asciz "Hello world! n=%d\n"
