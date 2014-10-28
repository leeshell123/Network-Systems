#Makefile
CC = gcc
INCLUDE = /usr/lib
LIBS=-lcrypto -lssl
OBJS = 

all: echoServer echoClient

echoServer: 
	$(CC) -o echoServer echoServer.c $(LIBS)
echoClient:
	$(CC) -o echoClient echoClient.c $(LIBS)

clean:
	rm -f echoServer echoClient
