# Declare the assembly flavor to use the intel syntax.
.intel_syntax noprefix

# Define a symbol to be exported from this file.
.global my_function

# Declare symbol type to be a function.
.type my_function, @function

# Code follows below.

my_function:
    # <<<< PUT YOUR CODE HERE >>>>
    # TODO:
    # 1. Read the input to the function from the stack.
    # 2. Save the result in the register EAX (and then return!).

	MOV EBX, DWORD PTR [ESP+4]     # load arg from the stack , we will denote arg as n
	CMP EBX, 1                     # compare n to 1
	JE _RET1                       # if(arg == 1) go to _RET1
        JL _RET0                       # if(arg < 1)  go to _RET0
        CMP EBX, 2                     # compare n to 2
	JE _RET1                       # if(arg == 1) go to _RET1
	
	PUSH 1                         # store a1 to the stack
	PUSH 1                         # store a2 to the stack
	MOV ECX, 3                     # i = 3 (we start calc from i = 3 (a3) becuse a0=0, a1=1, a2=1)

_LOOP:                                 # for(i = 3 , i <= n , i++)
	MOV EDX, DWORD PTR [ESP]       # load the f(n-1) from the stack
	IMUL EDX, EDX                  # EDX = EDX^2 = [f(n-1)]^2
	MOV EAX, EDX                   # result += [f(n-1)]^2
	MOV EDX, DWORD PTR [ESP+4]     # load the f(n-2) from the stack
        IMUL EDX, EDX 	      	       # EDX = EDX^2 = [f(n-2)]^2
        ADD EAX, EDX  	      	       # result	+= [f(n-2)]^2

	CMP ECX, EBX                   # compare i to n
	JE _RET  	      	       # if(i == n) go to _RET
	
				       # ELSE: (another itertion)
	INC ECX                        # i++
	MOV EDX, DWORD PTR [ESP]       # load the f(n-1) from the stack to EDX
	ADD ESP, 8                     # close the stack
	PUSH EDX                       # store a_i-1 in the stack for next calc
	PUSH EAX                       # store a_i in the stack for next calc
	JMP _LOOP                      # go to _LOOP	

_RET0:                                 # return 0
	MOV EAX, 0
        RET

_RET1:                                 # return 1
        MOV EAX, 1
        RET

_RET:                                  # we finish the calc and return
	ADD ESP, 8                     # close the stack
	RET
