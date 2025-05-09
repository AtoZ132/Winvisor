PUBLIC InveptOp
PUBLIC GetGDTBase
PUBLIC GetGDTLimit
PUBLIC GetIDTBase
PUBLIC GetIDTLimit
PUBLIC GetTR
PUBLIC GetCS
PUBLIC GetDS
PUBLIC GetSS
PUBLIC GetES
PUBLIC GetFS
PUBLIC GetGS
PUBLIC GetRflags
PUBLIC GetLDTR
PUBLIC VmExitHandler
PUBLIC InvokeVmcall
PUBLIC VmxSaveState
PUBLIC VmxRestoreState

EXTERN WvsrVmExitHandler:PROC
EXTERN VmResumeErrorHandler:PROC
EXTERN WvsrStartVm:PROC

_text SEGMENT

; Invept Assembly procedure helper
InveptOp PROC PUBLIC

INVEPT RCX, OWORD PTR [RDX]
RET

InveptOp ENDP

; The 16-bit limit field of the register is stored in the low 2 bytes 
; And the 64-bit base address is stored in the high 8 bytes.
GetGDTBase PROC PUBLIC

LOCAL GDTR[10]:BYTE
SGDT GDTR
MOV RAX, QWORD PTR GDTR[2]
RET

GetGDTBase ENDP

GetGDTLimit PROC PUBLIC

LOCAL GDTR[10]:BYTE
SGDT GDTR
MOV AX, WORD PTR GDTR[0]
RET

GetGDTLimit ENDP

; The 16-bit limit field of the register is stored in the low 2 bytes 
; And the 64-bit base address is stored in the high 8 bytes.
GetIDTBase PROC PUBLIC

LOCAL IDTR[10]:BYTE
SIDT IDTR
MOV RAX, QWORD PTR IDTR[2]
RET

GetIDTBase ENDP

GetIDTLimit PROC PUBLIC

LOCAL IDTR[10]:BYTE
SIDT IDTR
MOV AX, WORD PTR IDTR[0]
RET

GetIDTLimit ENDP

GetTR PROC PUBLIC

STR RAX
RET

GetTR ENDP

GetCS PROC PUBLIC

MOV RAX, CS
RET

GetCS ENDP

GetDS PROC PUBLIC

MOV RAX, DS
RET

GetDS ENDP

GetSS PROC PUBLIC

MOV RAX, SS
RET

GetSS ENDP

GetES PROC PUBLIC

MOV RAX, ES
RET

GetES ENDP

GetFS PROC PUBLIC

MOV RAX, FS
RET

GetFS ENDP

GetGS PROC PUBLIC

MOV RAX, GS
RET

GetGS ENDP

GetRflags PROC PUBLIC

PUSHFQ
POP RAX
RET

GetRflags ENDP

GetLDTR PROC PUBLIC

SLDT RAX
RET

GetLDTR ENDP

VmExitHandler PROC PUBLIC

; 0x80 bytes
PUSH R15
PUSH R14
PUSH R13
PUSH R12
PUSH R11
PUSH R10
PUSH R9
PUSH R8
PUSH RDI
PUSH RSI
PUSH RBP
SUB RSP, 8
PUSH RBX
PUSH RDX
PUSH RCX
PUSH RAX

MOV RCX, RSP ; param for the handler
SUB RSP, 28h
CALL WvsrVmExitHandler
ADD RSP, 28h

POP RAX
POP RCX
POP RDX
POP RBX
ADD RSP, 8
POP RBP
POP RSI
POP RDI 
POP R8
POP R9
POP R10
POP R11
POP R12
POP R13
POP R14
POP R15

vmresume

; vmresume failed
SUB RSP, 20h
CALL VmResumeErrorHandler
ADD RSP, 20h
INT 3

VmExitHandler ENDP

InvokeVmcall PROC PUBLIC

VMCALL
RET

InvokeVmcall ENDP

VmxSaveState PROC
	
	PUSHFQ	; save r/eflag

	PUSH RAX
	PUSH RCX
	PUSH RDX
	PUSH RBX
	PUSH RBP
	PUSH RSI
	PUSH RDI
	PUSH R8
	PUSH R9
	PUSH R10
	PUSH R11
	PUSH R12
	PUSH R13
	PUSH R14
	PUSH R15

	SUB RSP, 100h
	; It a x64 FastCall function so the first parameter should go to rcx

	MOV RCX, RSP

	CALL WvsrStartVm

	INT 3	; we should never reach here as we execute vmlaunch in the above function.
			; if rax is FALSE then it's an indication of error

	JMP VmxRestoreState
VmxSaveState ENDP

VmxRestoreState PROC
	
	add rsp, 0100h

	POP R15
	POP R14
	POP R13
	POP R12
	POP R11
	POP R10
	POP R9
	POP R8
	POP RDI
	POP RSI
	POP RBP
	POP RBX
	POP RDX
	POP RCX
	POP RAX
	
	POPFQ	; restore r/eflags

	RET
	
VmxRestoreState ENDP


_text ENDS
END