#include <unistd.h>
#include <stdio.h>

int main() {
  pid_t pid;

  puts("hello from fork program");
  switch (pid = fork()) {
    case -1:
      break;
    case 0:
      printf("child pid %d, 0x%llx\n", getpid(), getpid());
      break;
    default:
      printf("parent pid %d, 0x%llx\n", getpid(), getpid());
  }
}
