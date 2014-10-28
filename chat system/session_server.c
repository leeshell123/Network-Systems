#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void error(const char *msg)
{
    perror(msg);
    exit(1);
}

int inSocket(int port);

main(int argc, char *argv[])

{
	int i=0;
	int client_no = 0;
	int port = 0;
	//port = atoi(argv[3]);
	//printf("received port number is%d\n", port);

	int pipes[2][2];

	pipes[0][0] = atoi(argv[1]);
	pipes[0][1] = atoi(argv[2]);
	pipes[1][0] = atoi(argv[3]);
	pipes[1][1] = atoi(argv[4]);

	close(pipes[0][1]);
	close(pipes[1][0]);
	read(pipes[0][0], (void *)&port, sizeof(int));
	printf("session received port is %d\n", port);
  

	
	inSocket(port);
	write(pipes[1][1], (void *)&port, sizeof(int));
	return 0; 
  
}

int inSocket(int port)
{
	struct timeval tv;
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	/* master file descriptor list */
	fd_set master;
	/*current client connections to this socket*/
	int client_no = 0;
	/* temp file descriptor list for select() */
	fd_set read_fds;
	/* server address */
	struct sockaddr_in serveraddr;
	/* client address */
	struct sockaddr_in clientaddr;
	/* maximum file descriptor number */
	int fdmax;
	/* listening socket descriptor */
	int listener;
	/* newly accept()ed socket descriptor */
	int newfd;
	/* buffer for client data */
	char buf[1024];
	int nbytes;
	/* for setsockopt() SO_REUSEADDR, below */
	int yes = 1;
	int addrlen;
	int i, j;
	/* clear the master and temp sets */
	FD_ZERO(&master);
	FD_ZERO(&read_fds);

	/* get the listener */

	if ((listener = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("Server-socket() error lol!");
		/*just exit lol!*/
		exit(1);
	}
	printf("Server-socket() is OK...\n");
	/*"address already in use" error message */
	if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int))
			== -1) {
		perror("Server-setsockopt() error lol!");
		exit(1);
	}
	printf("Server-setsockopt() is OK...\n");
	/* bind */
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = INADDR_ANY;
	serveraddr.sin_port = htons(port);
	memset(&(serveraddr.sin_zero), '\0', 8);
	if (bind(listener, (struct sockaddr *) &serveraddr, sizeof(serveraddr))
			== -1) {
		perror("Server-bind() error lol!");
		exit(1);
	}
	printf("Server-bind() is OK...\n");
	/* listen */
	if (listen(listener, 10) == -1) {
		perror("Server-listen() error lol!");
		exit(1);
	}
	printf("Server-listen() is OK...\n");
	/* add the listener to the master set */
	FD_SET(listener, &master);
	/* keep track of the biggest file descriptor */
	fdmax = listener; /* so far, it's this one*/
	//int timeloop;
	/* loop */
	//for (timeloop=0;timeloop<20;timeloop++)
	for (;;)
	{
		//printf("timeloop is %d\n", timeloop);
		memset(buf, 0, 1024);
		/* copy it */
		read_fds = master;
		//if (select(fdmax + 1, &read_fds, NULL, NULL, &tv) == -1)
		if (select(fdmax + 1, &read_fds, NULL, NULL, NULL) == -1)
		{
			perror("Server-select() error lol!");
			exit(1);
		}
		//printf("Server-select() is OK...\n");
		/*run through the existing connections looking for data to be read*/

		for (i = 0; i <= fdmax; i++) {
			if (FD_ISSET(i, &read_fds)) { /* we got one... */
				if (i == listener) {
					/* handle new connections */
					addrlen = sizeof(clientaddr);
					if ((newfd = accept(listener,
							(struct sockaddr *) &clientaddr, &addrlen)) == -1) {
						perror("Server-accept() error lol!");
					} else {
						printf("Server-accept() is OK...\n");
						FD_SET(newfd, &master); /* add to master set */
						if (newfd > fdmax) { /* keep track of the maximum */
							fdmax = newfd;
						}
						printf("New connection from %s on socket %d\n",
								inet_ntoa(clientaddr.sin_addr), newfd);
						client_no++;
						//timeloop = 0;
						//printf("timeloop is %d\n", timeloop);
						//printf("after connection, client_no is %d", client_no);
					}
				} else {
					/* handle data from a client */
					if ((nbytes = recv(i, buf, sizeof(buf), 0)) <= 0) {
						/* got error or connection closed by client */
						if (nbytes == 0)
							/* connection closed */{
							printf("socket %d hung up\n", i);
							client_no--;
							//printf("after hung up, client_no is %d", client_no);
							if(client_no <= 0)
							{
								close(listener);
								printf("no clients in this session, connection closed\n");
								return 0;
							}

						}
						else
							perror("recv() error lol!");
						/* close it... */
						close(i);
						/* remove from master set */
						FD_CLR(i, &master);
					} else {
						printf("new message: %s\n", buf);
						//timeloop = 0;
						//printf("timeloop is %d\n", timeloop);
						/* we got some data from a client*/
						for (j = 0; j <= fdmax; j++) {
							/* send to everyone! */
							if (FD_ISSET(j, &master)) {
								/* except the listener and ourselves */
								if (j != listener && j != i) {
									if (send(j, buf, nbytes, 0) == -1)
										perror("send() error lol!");
								}
							}
						}
					}
				}
			}
		}
	}
	//printf("session idle for a while, end of loop, session ended\n");
	return 0;
}


