#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/syscall.h>

#define SUCCESS (0)

char* SYSCALL_ENTRY_STR = "SYSCALL_ENTRY";
char* SYSCALL_EXIT_STR = "SYSCALL_EXIT";
char* SYSCALL_SECCOMP_STR = "SYSCALL_SECCOMP";
char* OTHER = "OTHER";
char* SYSCALL_MAPPING[500];

/*
 * Inits the syscall mapping array to map each syscall number to its name.
 */
void init_syscall_mapping();

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
                  char* syscall_str = SYSCALL_MAPPING[syscall_info->entry.nr];
                  if (syscall_str == NULL) {
                    printf("%llu(", syscall_info->entry.nr);
                  }
                  else {
                    printf("%s(",syscall_str);
                  }
                  long long unsigned int* args = syscall_info->entry.args;  
                  printf("%llu, %llu, %llu, %llu, %llu, %llu) = ", args[0], args[1], args[2], args[3], args[4], args[5]);
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
    init_syscall_mapping();

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


void init_syscall_mapping() {
    SYSCALL_MAPPING[SYS_afs_syscall] = "ni_syscall";
    SYSCALL_MAPPING[SYS_arch_prctl] = "arch_prctl";
    SYSCALL_MAPPING[SYS_rt_sigreturn] = "rt_sigreturn";
    SYSCALL_MAPPING[SYS_iopl] = "iopl";
    SYSCALL_MAPPING[SYS_ioperm] = "ioperm";
    SYSCALL_MAPPING[SYS_modify_ldt] = "modify_ldt";
    SYSCALL_MAPPING[SYS_mmap] = "mmap";
    SYSCALL_MAPPING[SYS_get_thread_area] = "get_thread_area";
    SYSCALL_MAPPING[SYS_set_thread_area] = "set_thread_area";
    SYSCALL_MAPPING[SYS_unshare] = "unshare";
    SYSCALL_MAPPING[SYS_clone3] = "clone3";
    SYSCALL_MAPPING[SYS_clone] = "clone";
    SYSCALL_MAPPING[SYS_vfork] = "vfork";
    SYSCALL_MAPPING[SYS_fork] = "fork";
    SYSCALL_MAPPING[SYS_set_tid_address] = "set_tid_address";
    SYSCALL_MAPPING[SYS_personality] = "personality";
    SYSCALL_MAPPING[SYS_wait4] = "wait4";
    SYSCALL_MAPPING[SYS_waitid] = "waitid";
    SYSCALL_MAPPING[SYS_exit_group] = "exit_group";
    SYSCALL_MAPPING[SYS_exit] = "exit";
    SYSCALL_MAPPING[SYS_capset] = "capset";
    SYSCALL_MAPPING[SYS_capget] = "capget";
    SYSCALL_MAPPING[SYS_ptrace] = "ptrace";
    SYSCALL_MAPPING[SYS_rt_sigsuspend] = "rt_sigsuspend";
    SYSCALL_MAPPING[SYS_pause] = "pause";
    SYSCALL_MAPPING[SYS_signalfd] = "signal";
    SYSCALL_MAPPING[SYS_setns] = "ssetmask";
    SYSCALL_MAPPING[SYS_rt_sigaction] = "rt_sigaction";
    SYSCALL_MAPPING[SYS_rt_sigprocmask] = "sigprocmask";
    SYSCALL_MAPPING[SYS_rt_sigpending] = "sigpending";
    SYSCALL_MAPPING[SYS_sigaltstack] = "sigaltstack";
    SYSCALL_MAPPING[SYS_rt_tgsigqueueinfo] = "rt_tgsigqueueinfo";
    SYSCALL_MAPPING[SYS_rt_sigqueueinfo] = "rt_sigqueueinfo";
    SYSCALL_MAPPING[SYS_tkill] = "tkill";
    SYSCALL_MAPPING[SYS_tgkill] = "tgkill";
    SYSCALL_MAPPING[SYS_pidfd_send_signal] = "pidfd_send_signal";
    SYSCALL_MAPPING[SYS_kill] = "kill";
    SYSCALL_MAPPING[SYS_rt_sigtimedwait] = "rt_sigtimedwait";
    SYSCALL_MAPPING[SYS_rt_sigpending] = "rt_sigpending";
    SYSCALL_MAPPING[SYS_rt_sigprocmask] = "rt_sigprocmask";
    SYSCALL_MAPPING[SYS_restart_syscall] = "restart_syscall";
    SYSCALL_MAPPING[SYS_sysinfo] = "sysinfo";
    SYSCALL_MAPPING[SYS_getcpu] = "getcpu";
    SYSCALL_MAPPING[SYS_prctl] = "prctl";
    SYSCALL_MAPPING[SYS_umask] = "umask";
    SYSCALL_MAPPING[SYS_getrusage] = "getrusage";
    SYSCALL_MAPPING[SYS_setrlimit] = "setrlimit";
    SYSCALL_MAPPING[SYS_getrlimit] = "getrlimit";
    SYSCALL_MAPPING[SYS_setdomainname] = "setdomainname";
    SYSCALL_MAPPING[SYS_sethostname] = "sethostname";
    SYSCALL_MAPPING[SYS_uname] = "uname";
    SYSCALL_MAPPING[SYS_rename] = "newuname";
    SYSCALL_MAPPING[SYS_setsid] = "setsid";
    SYSCALL_MAPPING[SYS_getsid] = "getsid";
    SYSCALL_MAPPING[SYS_getpgrp] = "getpgrp";
    SYSCALL_MAPPING[SYS_getpgid] = "getpgid";
    SYSCALL_MAPPING[SYS_setpgid] = "setpgid";
    SYSCALL_MAPPING[SYS_times] = "times";
    SYSCALL_MAPPING[SYS_getegid] = "getegid";
    SYSCALL_MAPPING[SYS_getgid] = "getgid";
    SYSCALL_MAPPING[SYS_geteuid] = "geteuid";
    SYSCALL_MAPPING[SYS_getuid] = "getuid";
    SYSCALL_MAPPING[SYS_getppid] = "getppid";
    SYSCALL_MAPPING[SYS_gettid] = "gettid";
    SYSCALL_MAPPING[SYS_getpid] = "getpid";
    SYSCALL_MAPPING[SYS_setfsgid] = "setfsgid";
    SYSCALL_MAPPING[SYS_setfsuid] = "setfsuid";
    SYSCALL_MAPPING[SYS_getresgid] = "getresgid";
    SYSCALL_MAPPING[SYS_setresgid] = "setresgid";
    SYSCALL_MAPPING[SYS_getresuid] = "getresuid";
    SYSCALL_MAPPING[SYS_setresuid] = "setresuid";
    SYSCALL_MAPPING[SYS_setuid] = "setuid";
    SYSCALL_MAPPING[SYS_setreuid] = "setreuid";
    SYSCALL_MAPPING[SYS_setgid] = "setgid";
    SYSCALL_MAPPING[SYS_setregid] = "setregid";
    SYSCALL_MAPPING[SYS_getpriority] = "getpriority";
    SYSCALL_MAPPING[SYS_setpriority] = "setpriority";
    SYSCALL_MAPPING[SYS_pidfd_getfd] = "pidfd_getfd";
    SYSCALL_MAPPING[SYS_pidfd_open] = "pidfd_open";
    SYSCALL_MAPPING[SYS_setns] = "setns";
    SYSCALL_MAPPING[SYS_reboot] = "reboot";
    SYSCALL_MAPPING[SYS_setgroups] = "setgroups";
    SYSCALL_MAPPING[SYS_getgroups] = "getgroups";
    SYSCALL_MAPPING[SYS_sched_rr_get_interval] = "sched_rr_get_interval";
    SYSCALL_MAPPING[SYS_sched_get_priority_min] = "sched_get_priority_min";
    SYSCALL_MAPPING[SYS_sched_get_priority_max] = "sched_get_priority_max";
    SYSCALL_MAPPING[SYS_sched_yield] = "sched_yield";
    SYSCALL_MAPPING[SYS_sched_getaffinity] = "sched_getaffinity";
    SYSCALL_MAPPING[SYS_sched_setaffinity] = "sched_setaffinity";
    SYSCALL_MAPPING[SYS_sched_getattr] = "sched_getattr";
    SYSCALL_MAPPING[SYS_sched_getparam] = "sched_getparam";
    SYSCALL_MAPPING[SYS_sched_getscheduler] = "sched_getscheduler";
    SYSCALL_MAPPING[SYS_sched_setattr] = "sched_setattr";
    SYSCALL_MAPPING[SYS_sched_setparam] = "sched_setparam";
    SYSCALL_MAPPING[SYS_sched_setscheduler] = "sched_setscheduler";
    SYSCALL_MAPPING[SYS_membarrier] = "membarrier";
    SYSCALL_MAPPING[SYS_syslog] = "syslog";
    SYSCALL_MAPPING[SYS_finit_module] = "finit_module";
    SYSCALL_MAPPING[SYS_init_module] = "init_module";
    SYSCALL_MAPPING[SYS_delete_module] = "delete_module";
    SYSCALL_MAPPING[SYS_kcmp] = "kcmp";
    SYSCALL_MAPPING[SYS_adjtimex] = "adjtimex";
    SYSCALL_MAPPING[SYS_settimeofday] = "settimeofday";
    SYSCALL_MAPPING[SYS_gettimeofday] = "gettimeofday";
    SYSCALL_MAPPING[SYS_time] = "time";
    SYSCALL_MAPPING[SYS_nanosleep] = "nanosleep";
    SYSCALL_MAPPING[SYS_clock_nanosleep] = "clock_nanosleep";
    SYSCALL_MAPPING[SYS_clock_getres] = "clock_getres";
    SYSCALL_MAPPING[SYS_clock_adjtime] = "clock_adjtime";
    SYSCALL_MAPPING[SYS_clock_gettime] = "clock_gettime";
    SYSCALL_MAPPING[SYS_clock_settime] = "clock_settime";
    SYSCALL_MAPPING[SYS_timer_delete] = "timer_delete";
    SYSCALL_MAPPING[SYS_timer_settime] = "timer_settime";
    SYSCALL_MAPPING[SYS_timer_getoverrun] = "timer_getoverrun";
    SYSCALL_MAPPING[SYS_timer_gettime] = "timer_gettime";
    SYSCALL_MAPPING[SYS_timer_create] = "timer_create";
    SYSCALL_MAPPING[SYS_setitimer] = "setitimer";
    SYSCALL_MAPPING[SYS_alarm] = "alarm";
    SYSCALL_MAPPING[SYS_getitimer] = "getitimer";
    SYSCALL_MAPPING[SYS_futex] = "futex";
    SYSCALL_MAPPING[SYS_get_robust_list] = "get_robust_list";
    SYSCALL_MAPPING[SYS_set_robust_list] = "set_robust_list";
    SYSCALL_MAPPING[SYS_acct] = "acct";
    SYSCALL_MAPPING[SYS_kexec_load] = "kexec_load";
    SYSCALL_MAPPING[SYS_kexec_file_load] = "kexec_file_load";
    SYSCALL_MAPPING[SYS_seccomp] = "seccomp";
    SYSCALL_MAPPING[SYS_bpf] = "bpf";
    SYSCALL_MAPPING[SYS_perf_event_open] = "perf_event_open";
    SYSCALL_MAPPING[SYS_rseq] = "rseq";
    SYSCALL_MAPPING[SYS_process_mrelease] = "process_mrelease";
    SYSCALL_MAPPING[SYS_readahead] = "readahead";
    SYSCALL_MAPPING[SYS_mincore] = "mincore";
    SYSCALL_MAPPING[SYS_munlockall] = "munlockall";
    SYSCALL_MAPPING[SYS_mlockall] = "mlockall";
    SYSCALL_MAPPING[SYS_munlock] = "munlock";
    SYSCALL_MAPPING[SYS_mlock2] = "mlock2";
    SYSCALL_MAPPING[SYS_mlock] = "mlock";
    SYSCALL_MAPPING[SYS_remap_file_pages] = "remap_file_pages";
    SYSCALL_MAPPING[SYS_munmap] = "munmap";
    SYSCALL_MAPPING[SYS_brk] = "brk";
    SYSCALL_MAPPING[SYS_pkey_free] = "pkey_free";
    SYSCALL_MAPPING[SYS_pkey_alloc] = "pkey_alloc";
    SYSCALL_MAPPING[SYS_pkey_mprotect] = "pkey_mprotect";
    SYSCALL_MAPPING[SYS_mprotect] = "mprotect";
    SYSCALL_MAPPING[SYS_mremap] = "mremap";
    SYSCALL_MAPPING[SYS_msync] = "msync";
    SYSCALL_MAPPING[SYS_process_vm_writev] = "process_vm_writev";
    SYSCALL_MAPPING[SYS_process_vm_readv] = "process_vm_readv";
    SYSCALL_MAPPING[SYS_process_madvise] = "process_madvise";
    SYSCALL_MAPPING[SYS_madvise] = "madvise";
    SYSCALL_MAPPING[SYS_swapon] = "swapon";
    SYSCALL_MAPPING[SYS_swapoff] = "swapoff";
    SYSCALL_MAPPING[SYS_get_mempolicy] = "get_mempolicy";
    SYSCALL_MAPPING[SYS_migrate_pages] = "migrate_pages";
    SYSCALL_MAPPING[SYS_set_mempolicy] = "set_mempolicy";
    SYSCALL_MAPPING[SYS_mbind] = "mbind";
    SYSCALL_MAPPING[SYS_move_pages] = "move_pages";
    SYSCALL_MAPPING[SYS_memfd_secret] = "memfd_secret";
    SYSCALL_MAPPING[SYS_memfd_create] = "memfd_create";
    SYSCALL_MAPPING[SYS_vhangup] = "vhangup";
    SYSCALL_MAPPING[SYS_close_range] = "close_range";
    SYSCALL_MAPPING[SYS_close] = "close";
    SYSCALL_MAPPING[SYS_creat] = "creat";
    SYSCALL_MAPPING[SYS_openat2] = "openat2";
    SYSCALL_MAPPING[SYS_openat] = "openat";
    SYSCALL_MAPPING[SYS_open] = "open";
    SYSCALL_MAPPING[SYS_fchown] = "fchown";
    SYSCALL_MAPPING[SYS_lchown] = "lchown";
    SYSCALL_MAPPING[SYS_chown] = "chown";
    SYSCALL_MAPPING[SYS_fchownat] = "fchownat";
    SYSCALL_MAPPING[SYS_chmod] = "chmod";
    SYSCALL_MAPPING[SYS_fchmodat] = "fchmodat";
    SYSCALL_MAPPING[SYS_fchmod] = "fchmod";
    SYSCALL_MAPPING[SYS_chroot] = "chroot";
    SYSCALL_MAPPING[SYS_fchdir] = "fchdir";
    SYSCALL_MAPPING[SYS_chdir] = "chdir";
    SYSCALL_MAPPING[SYS_access] = "access";
    SYSCALL_MAPPING[SYS_faccessat2] = "faccessat2";
    SYSCALL_MAPPING[SYS_faccessat] = "faccessat";
    SYSCALL_MAPPING[SYS_fallocate] = "fallocate";
    SYSCALL_MAPPING[SYS_ftruncate] = "ftruncate";
    SYSCALL_MAPPING[SYS_truncate] = "truncate";
    SYSCALL_MAPPING[SYS_copy_file_range] = "copy_file_range";
    SYSCALL_MAPPING[SYS_sendfile] = "sendfile";
    SYSCALL_MAPPING[SYS_pwritev2] = "pwritev2";
    SYSCALL_MAPPING[SYS_pwritev] = "pwritev";
    SYSCALL_MAPPING[SYS_preadv2] = "preadv2";
    SYSCALL_MAPPING[SYS_preadv] = "preadv";
    SYSCALL_MAPPING[SYS_writev] = "writev";
    SYSCALL_MAPPING[SYS_readv] = "readv";
    SYSCALL_MAPPING[SYS_write] = "write";
    SYSCALL_MAPPING[SYS_read] = "read";
    SYSCALL_MAPPING[SYS_lseek] = "lseek";
    SYSCALL_MAPPING[SYS_statx] = "statx";
    SYSCALL_MAPPING[SYS_readlink] = "readlink";
    SYSCALL_MAPPING[SYS_readlinkat] = "readlinkat";
    SYSCALL_MAPPING[SYS_fstat] = "fstat";
    SYSCALL_MAPPING[SYS_lstat] = "lstat";
    SYSCALL_MAPPING[SYS_stat] = "stat";
    SYSCALL_MAPPING[SYS_execveat] = "execveat";
    SYSCALL_MAPPING[SYS_execve] = "execve";
    SYSCALL_MAPPING[SYS_uselib] = "uselib";
    SYSCALL_MAPPING[SYS_pipe] = "pipe";
    SYSCALL_MAPPING[SYS_pipe2] = "pipe2";
    SYSCALL_MAPPING[SYS_rename] = "rename";
    SYSCALL_MAPPING[SYS_renameat] = "renameat";
    SYSCALL_MAPPING[SYS_renameat2] = "renameat2";
    SYSCALL_MAPPING[SYS_link] = "link";
    SYSCALL_MAPPING[SYS_linkat] = "linkat";
    SYSCALL_MAPPING[SYS_symlink] = "symlink";
    SYSCALL_MAPPING[SYS_symlinkat] = "symlinkat";
    SYSCALL_MAPPING[SYS_unlink] = "unlink";
    SYSCALL_MAPPING[SYS_unlinkat] = "unlinkat";
    SYSCALL_MAPPING[SYS_rmdir] = "rmdir";
    SYSCALL_MAPPING[SYS_mkdir] = "mkdir";
    SYSCALL_MAPPING[SYS_mkdirat] = "mkdirat";
    SYSCALL_MAPPING[SYS_mknod] = "mknod";
    SYSCALL_MAPPING[SYS_mknodat] = "mknodat";
    SYSCALL_MAPPING[SYS_fcntl] = "fcntl";
    SYSCALL_MAPPING[SYS_ioctl] = "ioctl";
    SYSCALL_MAPPING[SYS_getdents] = "getdents";
    SYSCALL_MAPPING[SYS_ppoll] = "ppoll";
    SYSCALL_MAPPING[SYS_poll] = "poll";
    SYSCALL_MAPPING[SYS_pselect6] = "pselect6";
    SYSCALL_MAPPING[SYS_select] = "select";
    SYSCALL_MAPPING[SYS_dup] = "dup";
    SYSCALL_MAPPING[SYS_dup2] = "dup2";
    SYSCALL_MAPPING[SYS_dup3] = "dup3";
    SYSCALL_MAPPING[SYS_sysfs] = "sysfs";
    SYSCALL_MAPPING[SYS_mount_setattr] = "mount_setattr";
    SYSCALL_MAPPING[SYS_pivot_root] = "pivot_root";
    SYSCALL_MAPPING[SYS_move_mount] = "move_mount";
    SYSCALL_MAPPING[SYS_fsmount] = "fsmount";
    SYSCALL_MAPPING[SYS_mount] = "mount";
    SYSCALL_MAPPING[SYS_open_tree] = "open_tree";
    SYSCALL_MAPPING[SYS_fremovexattr] = "fremovexattr";
    SYSCALL_MAPPING[SYS_lremovexattr] = "lremovexattr";
    SYSCALL_MAPPING[SYS_removexattr] = "removexattr";
    SYSCALL_MAPPING[SYS_flistxattr] = "flistxattr";
    SYSCALL_MAPPING[SYS_llistxattr] = "llistxattr";
    SYSCALL_MAPPING[SYS_listxattr] = "listxattr";
    SYSCALL_MAPPING[SYS_fgetxattr] = "fgetxattr";
    SYSCALL_MAPPING[SYS_lgetxattr] = "lgetxattr";
    SYSCALL_MAPPING[SYS_getxattr] = "getxattr";
    SYSCALL_MAPPING[SYS_fsetxattr] = "fsetxattr";
    SYSCALL_MAPPING[SYS_lsetxattr] = "lsetxattr";
    SYSCALL_MAPPING[SYS_setxattr] = "setxattr";
    SYSCALL_MAPPING[SYS_tee] = "tee";
    SYSCALL_MAPPING[SYS_splice] = "splice";
    SYSCALL_MAPPING[SYS_vmsplice] = "vmsplice";
    SYSCALL_MAPPING[SYS_sync_file_range] = "sync_file_range";
    SYSCALL_MAPPING[SYS_fdatasync] = "fdatasync";
    SYSCALL_MAPPING[SYS_fsync] = "fsync";
    SYSCALL_MAPPING[SYS_syncfs] = "syncfs";
    SYSCALL_MAPPING[SYS_sync] = "sync";
    SYSCALL_MAPPING[SYS_utime] = "utime";
    SYSCALL_MAPPING[SYS_utimes] = "utimes";
    SYSCALL_MAPPING[SYS_futimesat] = "futimesat";
    SYSCALL_MAPPING[SYS_utimensat] = "utimensat";
    SYSCALL_MAPPING[SYS_getcwd] = "getcwd";
    SYSCALL_MAPPING[SYS_ustat] = "ustat";
    SYSCALL_MAPPING[SYS_fstatfs] = "fstatfs";
    SYSCALL_MAPPING[SYS_statfs] = "statfs";
    SYSCALL_MAPPING[SYS_fsconfig] = "fsconfig";
    SYSCALL_MAPPING[SYS_fspick] = "fspick";
    SYSCALL_MAPPING[SYS_fsopen] = "fsopen";
    SYSCALL_MAPPING[SYS_inotify_rm_watch] = "inotify_rm_watch";
    SYSCALL_MAPPING[SYS_inotify_add_watch] = "inotify_add_watch";
    SYSCALL_MAPPING[SYS_inotify_init] = "inotify_init";
    SYSCALL_MAPPING[SYS_inotify_init1] = "inotify_init1";
    SYSCALL_MAPPING[SYS_fanotify_mark] = "fanotify_mark";
    SYSCALL_MAPPING[SYS_fanotify_init] = "fanotify_init";
    SYSCALL_MAPPING[SYS_epoll_pwait2] = "epoll_pwait2";
    SYSCALL_MAPPING[SYS_epoll_pwait] = "epoll_pwait";
    SYSCALL_MAPPING[SYS_epoll_wait] = "epoll_wait";
    SYSCALL_MAPPING[SYS_epoll_ctl] = "epoll_ctl";
    SYSCALL_MAPPING[SYS_epoll_create] = "epoll_create";
    SYSCALL_MAPPING[SYS_epoll_create1] = "epoll_create1";
    SYSCALL_MAPPING[SYS_signalfd] = "signalfd";
    SYSCALL_MAPPING[SYS_signalfd4] = "signalfd4";
    SYSCALL_MAPPING[SYS_timerfd_gettime] = "timerfd_gettime";
    SYSCALL_MAPPING[SYS_timerfd_settime] = "timerfd_settime";
    SYSCALL_MAPPING[SYS_timerfd_create] = "timerfd_create";
    SYSCALL_MAPPING[SYS_eventfd] = "eventfd";
    SYSCALL_MAPPING[SYS_eventfd2] = "eventfd2";
    SYSCALL_MAPPING[SYS_userfaultfd] = "userfaultfd";
    SYSCALL_MAPPING[SYS_io_pgetevents] = "io_pgetevents";
    SYSCALL_MAPPING[SYS_io_getevents] = "io_getevents";
    SYSCALL_MAPPING[SYS_io_cancel] = "io_cancel";
    SYSCALL_MAPPING[SYS_io_submit] = "io_submit";
    SYSCALL_MAPPING[SYS_io_destroy] = "io_destroy";
    SYSCALL_MAPPING[SYS_io_setup] = "io_setup";
    SYSCALL_MAPPING[SYS_flock] = "flock";
    SYSCALL_MAPPING[SYS_open_by_handle_at] = "open_by_handle_at";
    SYSCALL_MAPPING[SYS_name_to_handle_at] = "name_to_handle_at";
    SYSCALL_MAPPING[SYS_quotactl_fd] = "quotactl_fd";
    SYSCALL_MAPPING[SYS_quotactl] = "quotactl";
    SYSCALL_MAPPING[SYS_msgrcv] = "msgrcv";
    SYSCALL_MAPPING[SYS_msgsnd] = "msgsnd";
    SYSCALL_MAPPING[SYS_msgctl] = "msgctl";
    SYSCALL_MAPPING[SYS_msgget] = "msgget";
    SYSCALL_MAPPING[SYS_semop] = "semop";
    SYSCALL_MAPPING[SYS_semtimedop] = "semtimedop";
    SYSCALL_MAPPING[SYS_semctl] = "semctl";
    SYSCALL_MAPPING[SYS_semget] = "semget";
    SYSCALL_MAPPING[SYS_shmdt] = "shmdt";
    SYSCALL_MAPPING[SYS_shmat] = "shmat";
    SYSCALL_MAPPING[SYS_shmctl] = "shmctl";
    SYSCALL_MAPPING[SYS_shmget] = "shmget";
    SYSCALL_MAPPING[SYS_mq_getsetattr] = "mq_getsetattr";
    SYSCALL_MAPPING[SYS_mq_notify] = "mq_notify";
    SYSCALL_MAPPING[SYS_mq_timedreceive] = "mq_timedreceive";
    SYSCALL_MAPPING[SYS_mq_timedsend] = "mq_timedsend";
    SYSCALL_MAPPING[SYS_mq_unlink] = "mq_unlink";
    SYSCALL_MAPPING[SYS_mq_open] = "mq_open";
    SYSCALL_MAPPING[SYS_keyctl] = "keyctl";
    SYSCALL_MAPPING[SYS_request_key] = "request_key";
    SYSCALL_MAPPING[SYS_add_key] = "add_key";
    SYSCALL_MAPPING[SYS_landlock_restrict_self] = "landlock_restrict_self";
    SYSCALL_MAPPING[SYS_landlock_add_rule] = "landlock_add_rule";
    SYSCALL_MAPPING[SYS_landlock_create_ruleset] = "landlock_create_ruleset";
    SYSCALL_MAPPING[SYS_ioprio_get] = "ioprio_get";
    SYSCALL_MAPPING[SYS_ioprio_set] = "ioprio_set";
    SYSCALL_MAPPING[SYS_io_uring_register] = "io_uring_register";
    SYSCALL_MAPPING[SYS_io_uring_setup] = "io_uring_setup";
    SYSCALL_MAPPING[SYS_io_uring_enter] = "io_uring_enter";
    SYSCALL_MAPPING[SYS_getrandom] = "getrandom";
    SYSCALL_MAPPING[SYS_recvmmsg] = "recvmmsg";
    SYSCALL_MAPPING[SYS_recvmsg] = "recvmsg";
    SYSCALL_MAPPING[SYS_sendmmsg] = "sendmmsg";
    SYSCALL_MAPPING[SYS_sendmsg] = "sendmsg";
    SYSCALL_MAPPING[SYS_shutdown] = "shutdown";
    SYSCALL_MAPPING[SYS_getsockopt] = "getsockopt";
    SYSCALL_MAPPING[SYS_setsockopt] = "setsockopt";
    SYSCALL_MAPPING[SYS_recvfrom] = "recvfrom";
    SYSCALL_MAPPING[SYS_sendto] = "sendto";
    SYSCALL_MAPPING[SYS_getpeername] = "getpeername";
    SYSCALL_MAPPING[SYS_getsockname] = "getsockname";
    SYSCALL_MAPPING[SYS_connect] = "connect";
    SYSCALL_MAPPING[SYS_accept] = "accept";
    SYSCALL_MAPPING[SYS_accept4] = "accept4";
    SYSCALL_MAPPING[SYS_listen] = "listen";
    SYSCALL_MAPPING[SYS_bind] = "bind";
    SYSCALL_MAPPING[SYS_socketpair] = "socketpair";
    SYSCALL_MAPPING[SYS_socket] = "socket";
    SYSCALL_MAPPING[SYS_newfstatat] = "newfstatat";
    SYSCALL_MAPPING[SYS_prlimit64] = "prlimit64";
    SYSCALL_MAPPING[SYS_pread64] = "pread64";

}
