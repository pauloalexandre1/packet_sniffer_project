# compiler
CC = gcc

# flags
CFLAGS = -Wall -Wextra -g 

LDFLAGS = -lpcap

all: program

program: bin/packet.o bin/main.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

bin/main.o: src/main.c
	$(CC) -c $(CFLAGS) $^ -o $@

bin/packet.o: src/packet.c
	$(CC) -c $(CFLAGS) $^ -o $@

# remove object files and executable binary 'program'
clean:
	rm -f program bin/*.o