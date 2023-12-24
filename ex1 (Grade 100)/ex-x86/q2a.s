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
    # 3. Make sure to include a recursive function call (the recursive function
    #    can be this function, or a helper function defined later in this file).

	
	MOV EBX, DWORD PTR [ESP+4]     # load arg from the stack , we will denote arg as n 
	CMP EBX, 1                     # compare n to 1
	JE _RET1                       # if(arg == 1) go to _RET1
	JL _RET0                       # if(arg < 1)  go to _RET0

	CMP EBX, 2                     # compare n to 2
	JE _RET1                       # if(arg == 1) go to _RET1 
	
	
	DEC EBX                        # EBX = n-1
	PUSH EBX                       # save the second argument to the stack
	CALL my_function               # first recursive call
	POP EBX                        # restore stack
	IMUL EAX, EAX                  # EAX = [f(n-1)]^2
	MOV EDX, EAX                   # EDX = [f(n-1)]^2 , store the val to free EAX to another calc
	PUSH EDX                       # store EDX in the stack
	
	
	DEC EBX                        # EBX = n-2
	PUSH EBX                       # save the first argument to the stack
	CALL my_function               # second recursive call
	POP EBX                        # restore stack
	IMUL EAX, EAX 	      	       # EAX = [f(n-2)]^2
	POP EDX                      # restore EDX , EDX = [f(n-1)]^2
	ADD EAX, EDX                   # EAX = [f(n-2)]^2 + [f(n-1)]^2
	JMP _RET

_RET0:
	MOV EAX, 0                     # return 0
	RET
	
_RET1:
	MOV EAX, 1                     # return 1
	RET

_RET:
	RET
	
	
	