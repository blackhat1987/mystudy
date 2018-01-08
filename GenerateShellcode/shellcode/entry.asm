EXTRN hookcode:NEAR
NOP_32 MACRO
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop     ; 10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop     ; 20
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop     ; 30
    nop
    nop
ENDM
.CODE
my_hook PROC
    
	push rsp
	push rcx
	push rdx
	push r8
	push r9
	mov  rcx,rsp
	; ----------------------------------------------------
	; Fetch KERNEL32 address
	; 实际上shellcode里也可以获取
	; ----------------------------------------------------
	MOV  rdx, GS:[30h]    ; TEB
	MOV  rdx, [rdx + 60h] ; PEB
	MOV  rdx, [rdx + 18h] ; LDR
	MOV  rdx, [rdx + 20h] ; LIST_LOADED_MODULES
	MOV  rdx, [rdx]       ; NTDLL
	MOV  rdx, [rdx]       ; KERNEL32
	MOV  rdx, [rdx + 20h] ; ADDR of KERNEL32
    ; ----------------------------------------------------
	; Call c-code and return
	; ----------------------------------------------------
	PUSH rsi

	MOV rsi, rsp
	AND rsp, 0FFFFFFFFFFFFFFF0h
	SUB rsp, 020h
	CALL hookcode
	MOV rsp, rsi

	POP rsi
	pop r9
	pop r8
	pop rdx
	pop rcx
	pop rsp
	RET
my_hook ENDP

;这里负责调回去
jmp_old_hook proc
	NOP_32
	push 12345678h
	mov dword ptr [rsp+4h],12345678h
	ret
jmp_old_hook ENDP
END