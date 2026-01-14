#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>

#define SUCCESS (0)

char* SYSCALL_ENTRY_STR = "SYSCALL_ENTRY";
char* SYSCALL_EXIT_STR = "SYSCALL_EXIT";
char* SYSCALL_SECCOMP_STR = "SYSCALL_SECCOMP";
char* OTHER = "OTHER";


/*
 * Prints the syscall information struct.
 *
 * @param syscall_info [IN] The struct to print.
 */
void print_syscall(struct ptrace_syscall_info* syscall_info) {
    char* text = OTHER;
    if (1) {
        switch(syscall_info->op){
            case PTRACE_SYSCALL_INFO_ENTRY:
                  text = SYSCALL_ENTRY_STR;
                  printf("%lld ==> ", syscall_info->entry.nr);
                  break;
            case PTRACE_SYSCALL_INFO_EXIT:
                  text = SYSCALL_EXIT_STR;
                  printf("%llu\n", syscall_info->exit.rval);
                  break;
            case PTRACE_SYSCALL_INFO_SECCOMP:
                  text = SYSCALL_SECCOMP_STR;
                  printf("%s %u %llu %u\n", text, syscall_info->op, syscall_info->seccomp.nr, syscall_info->seccomp.ret_data);
                  break;
            case PTRACE_SYSCALL_INFO_NONE:
                  break;
        }
    }
}

/**
* Traces the syscall of a process.
*
* @param pid [IN] The PID of the process to trace.
*/
void trace_process(int pid) {
    ptrace(PTRACE_SEIZE, pid);
    int wstatus = 0;
    waitpid(pid, &wstatus, 0);
    ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXIT);
    struct ptrace_syscall_info syscall_info;
    unsigned syscall_info_size = sizeof(syscall_info);

    ptrace(PTRACE_SYSCALL, pid, NULL, 0);
    
    int stopped_process; 
    do{
        wstatus = 0;
        stopped_process = waitpid(pid, &wstatus, WNOHANG|__WALL);
        int is_stopped = ((WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) & 0x80) || WSTOPSIG(wstatus) == SIGTRAP);
        if (is_stopped) {
            ptrace(PTRACE_GET_SYSCALL_INFO, pid, syscall_info_size, &syscall_info);
            print_syscall(&syscall_info);
            ptrace(PTRACE_SYSCALL, pid, NULL, 0);
        }
    } while (!(wstatus>>8 == (SIGTRAP | PTRACE_EVENT_EXIT<<8)));
    printf("\n");
}

/*
 * Traces the syscalls of command.
 *
 * @param argc [IN] The number of arguments given.
 * @param argv [IN] The arguments.
 * @param envp [IN] The environment variables.
 */
void start(int argc, char** argv, char** envp) {
    int pid = fork();

    if (pid == 0) {
        // We are in the child proccess
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        execve(argv[1], argv+1, envp);
        return;
    }

    // Meaning we are in the parent so we need to start the tracing. 
    trace_process(pid);
    waitpid(-1, NULL, 0);
}

int main(int argc, char** argv, char** envp) {
    start(argc, argv, envp);
    return SUCCESS;
}


