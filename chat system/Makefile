#Makefile
CC = gcc
INCLUDE = /usr/lib
LIBS = 
OBJS = 

all: coordinator client session_server

coordinator: 
	$(CC) -o coordinator coordinator.c $(CFLAGS) $(LIBS)
client:
	$(CC) -o client client.c $(CFLAGS) $(LIBS)
session_server:
	$(CC) -o session_server session_server.c $(CFLAGS) $(LIBS)

clean:
	rm -f coordinator client session_server
