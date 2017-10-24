CC = gcc -std=gnu99

all: run_test_client clean

server: sha256.h sha256.c uint256.h server.c
	$(CC) -g -pthread -o server server.c sha256.c

run_test_client: server
	

clean:
	rm -rf *.o

.PHONY = run_test_client clean