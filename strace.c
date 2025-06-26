#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <signal.h>

#define SUCCESS (0)

char* SYSCALL_ENTRY_STR = "SYSCALL_ENTRY";
char* SYSCALL_EXIT_STR = "SYSCALL_EXIT";
char* OTHER = "OTHER";

void print_syscall(struct ptrace_syscall_info* syscall_info) {
    char* text = OTHER;
    if (1) {
        switch(syscall_info->op){
            case PTRACE_SYSCALL_INFO_ENTRY:
                  text = SYSCALL_ENTRY_STR;
                  printf("%s %u %lld\n", text, syscall_info->op, syscall_info->entry.nr);
                  break;
            case PTRACE_SYSCALL_INFO_EXIT:
                  text = SYSCALL_EXIT_STR;
                  printf("%s %u %llu\n", text, syscall_info->op, syscall_info->exit.rval);
                  break;
        }

    }
}


void trace_process(int pid) {
    //ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD);
    ptrace(PTRACE_SEIZE, pid, NULL, PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEEXEC|PTRACE_O_TRACEEXIT);
    ptrace(PTRACE_LISTEN, pid);
    struct ptrace_syscall_info syscall_info;
    unsigned syscall_info_size = sizeof(syscall_info);

    int wstatus = 1;
    do{
        int is_stopped = (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGSTOP);
        if (is_stopped) {
            //continue;
        }
        // printf("%d\n", is_stopped);
        int stopped_process = waitpid(pid, &wstatus, WNOHANG|__WALL);

        if (stopped_process != 0) {
            ptrace(PTRACE_SYSCALL, pid, NULL, 0);
            ptrace(PTRACE_GET_SYSCALL_INFO, pid, syscall_info_size, &syscall_info);
            print_syscall(&syscall_info);
        }
    } while (!WIFEXITED(wstatus));
    printf("finished!\n");
}


void start(int argc, char** argv) {
    int pid = fork();

    if (pid == 0) {
        // We are in the child proccess
        ptrace(PTRACE_TRACEME, 0);
        printf("executing: %s %s\n", argv[1], argv[2]);
        sleep(1);
        execv(argv[1], argv+1);
        return;
    }

    // Meaning we are in the parent so we need to start the tracing.
    trace_process(pid);
    waitpid(-1, NULL, 0);
}



int main(int argc, char** argv) {
    start(argc, argv);
    return SUCCESS;
}


