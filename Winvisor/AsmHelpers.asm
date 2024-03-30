PUBLIC AsmInveptOp

_text SEGMENT

; Invept Assembly procedure helper
AsmInveptOp PROC public

invept RCX, OWORD PTR [RDX]
ret

AsmInveptOp ENDP

_text ENDS
END