all: drivermake loggermake

drivermake: driver.o
	gcc -o driver driver.c

loggermake: keylogger.o
	gcc -o keylogger keylogger.c

clean:
	rm -f keylogger driver keylogger.o driver.o
