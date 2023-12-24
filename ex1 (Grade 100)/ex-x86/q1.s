
	# Declare the assembly flavor to use the intel syntax.
.intel_syntax noprefix

# Define a symbol to be exported from this file.
.global my_function

# Declare symbol type to be a function.
.type my_function, @function

# Code follows below.

my_function:
    # This code reads the first argument from the stack into EBX.
    # (If you need, feel free to edit/remove this line).
	MOV EBX, DWORD PTR [ESP + 4]
    # <<<< PUT YOUR CODE HERE >>>>


	CMP EBX, 1        # compare arg to 1
	JL _RET0          # if(arg < 1)  return 0 (go to _RET0)
	JE _RET1          # if(arg == 1) return 1 (go to _RET1)

	MOV EDX, EBX      # EDX = arg
	
	MOV ECX, 1        # ECX = i = 1 , we start looking from index = 1
_LOOP:                    # for(i = 1 , i < arg , i++) 
	MOV EAX, ECX      # EAX = i
	IMUL EAX, EAX     # EAX = i*i
	CMP EBX, EAX      # check if(arg = i*i)
	JE _RET2          # if(arg == i*i) go to _RET2 (return i)
	INC ECX           # else - i++
	CMP ECX, EDX      # compare i to arg
	JNE _LOOP	  # if(i != arg) go to _LOOP
	JE _RET0          # if(i == arg) go to _RET0


_RET0:                    # case 0: we return 0
	MOV EAX, 0
	CMP EAX, 0
	JE _RET           # skip the rest of the code

_RET1:	                  # case 1: we return 1
	MOV EAX, 1
	CMP EAX, 1
	JE _RET           # skip the rest of the code

_RET2:                    # case 2: we found the root
	MOV EAX, ECX      # return val = i

_RET:	
	RET
	
    # TODO:
    # 1. Read the input to the function from EBX.
    # 2. Save the result in the register EAX.

    # This returns from the function (call this after saving the result in EAX).
    # (If you need, feel free to edit/remove this line).
