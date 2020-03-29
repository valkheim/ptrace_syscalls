#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <linux/ptrace.h>
#include <asm/unistd.h>

static void child(char **av) {
  ptrace(PTRACE_TRACEME, 0, 0, 0);
  execv(*(av + 1), av + 1);
}

//static void print_syscall_infos(struct ptrace_syscall_info syscall_info) {
//  __u8 op = syscall_info.op;
//  printf("op = %d\n", op); // entry/seccomp / exit
//}

static void print_syscall_regs(struct user_regs_struct regs) {
  printf ("orig_rax:  0x%llx\n", regs.orig_rax);
  printf ("rdi:       0x%llx\n", regs.rdi);
  printf ("rsi:       0x%llx\n", regs.rsi);
  printf ("rdx:       0x%llx\n", regs.rdx);
  printf ("rcx:       0x%llx\n", regs.rcx);
  printf ("r8:        0x%llx\n", regs.r8);
  printf ("r9:        0x%llx\n", regs.r9);
  printf ("rax:       0x%llx\n", regs.rax);
  printf ("rip:       0x%llx\n", regs.rip);
  printf ("rsp:       0x%llx\n", regs.rsp);
}

static int print_call(pid_t const pid, char const *const name, unsigned int const n_args, struct user_regs_struct const r) {
  switch (n_args) {
    case 0:
    default:
      return printf("[%u] syscall %3lld, %s() = 0x%llx\n", pid, r.orig_rax, name, r.rax);
    case 1:
      return printf("[%u] syscall %3lld, %s(0x%llx) = 0x%llx\n", pid, r.orig_rax, name, r.rdi, r.rax);
    case 2:
      return printf("[%u] syscall %3lld, %s(0x%llx, 0x%llx) = 0x%llx\n", pid, r.orig_rax, name, r.rdi, r.rsi, r.rax);
    case 3:
      return printf("[%u] syscall %3lld, %s(0x%llx, 0x%llx, 0x%llx) = 0x%llx\n", pid, r.orig_rax, name, r.rdi, r.rsi, r.rdx, r.rax);
    case 4:
      return printf("[%u] syscall %lld, %s(0x%llx, 0x%llx, 0x%llx, 0x%lld) = 0x%llx\n", pid, r.orig_rax, name, r.rdi, r.rsi, r.rdx, r.rcx, r.rax);
    case 5:
      return printf("[%u] syscall %lld, %s(0x%llx, 0x%llx, 0x%llx, 0x%lld, 0x%lld) = 0x%llx\n", pid, r.orig_rax, name, r.rdi, r.rsi, r.rdx, r.rcx, r.rax, r.r8);
    case 6:
      return printf("[%u] syscall %lld, %s(0x%llx, 0x%llx, 0x%llx, 0x%lld, 0x%lld, 0x%lld) = 0x%llx\n", pid, r.orig_rax, name, r.rdi, r.rsi, r.rdx, r.rcx, r.rax, r.r8, r.r9);
  }
}

static int pretty_print(pid_t const pid, struct user_regs_struct const r) {
  switch (r.orig_rax) {
    case __NR_read:       return print_call(pid, "read", 3, r);
    case __NR_write:      return print_call(pid, "write", 3, r);
    case __NR_close:      return print_call(pid, "close", 1, r);
    case __NR_stat:       return print_call(pid, "stat", 2, r);
    case __NR_mmap:       return print_call(pid, "mmap", 0, r);
    case __NR_mprotect:   return print_call(pid, "mprotect", 0, r);
    case __NR_munmap:     return print_call(pid, "munmap", 0, r);
    case __NR_brk:        return print_call(pid, "brk", 0, r);
    case __NR_mremap:     return print_call(pid, "mremap", 0, r);
    case __NR_clone:      return print_call(pid, "clone", 0, r);
    case __NR_fork:       return print_call(pid, "fork", 0, r);
    case __NR_vfork:      return print_call(pid, "vfork", 0, r);
    case __NR_execve:     return print_call(pid, "execve", 3, r);
    case __NR_exit:       return print_call(pid, "exit", 1, r);
    case __NR_exit_group: return print_call(pid, "exit_group", 1, r);
    case __NR_openat:    return print_call(pid, "openat", 2, r);
    default:              return print_call(pid, "unknow", 0, r);
  }
}

static void parent(pid_t const pid) {
  int status;
  //struct ptrace_syscall_info syscall_info;
  struct user_regs_struct regs;

  int leave_syscall = 0;
  wait(&status);
  //ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
  //ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEFORK);
  //ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACECLONE);
  while (status == 1407) {
    //ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(struct ptrace_syscall_info), syscall_info);
    //print_syscall_infos(syscall_info);
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    //print_syscall_regs(regs);
    if (!leave_syscall) {
      pretty_print(pid, regs);
      leave_syscall = 1;
    } else {
      leave_syscall = 0;
    }
    ptrace(PTRACE_SYSCALL, pid, 0, 0);
    wait(&status);
  }
}

int main(int ac, char **av) {
  pid_t pid;

  switch (pid = fork()) {
    case -1:
      perror("fork");
      break;
    case 0:
      child(av);
      break;
    default:
      parent(pid);
  }
  return 0;
}

