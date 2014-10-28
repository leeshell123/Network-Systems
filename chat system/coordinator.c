/*
 Simple udp server
 Silver Moon (m00n.silv3r@gmail.com)
 */
#include<stdio.h> //printf
#include<string.h> //memset
#include<stdlib.h> //exit(0);
#include<arpa/inet.h>
#include<sys/socket.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

void stringspliter(char* input, char** output);
int check_name(char* input);
typedef int bool;
#define true 1
#define false 0
struct timeval tv;

#define BUFLEN 512  //Max length of buffer
#define PORT 8888   //The port on which to listen for incoming data 

int cport = 8900;
int used_session = 0;
fd_set mainfd;
int maxfdp;

int pipes[100][2][2]; //pipes for 100 sessions ,coordinator read from pipes[i][1], session read from pipes[i][0]
void die(char *s) {
	perror(s);
	exit(1);
}

int command_flag = 1;

struct session{
	int port;
	char name[8];
	bool flag;
};
int i;
struct session s_table[100];


int main(void) {
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	printf("Coordinator listening on port 8888....\n");
	
	struct sockaddr_in si_me, si_other;
	
	//char* result="sentence here is just for allocate space";

	int s, i, slen = sizeof(si_other), recv_len;
	char buf[BUFLEN];
	char reply[BUFLEN];

	//create a UDP socket
	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		die("socket");
	}

	// zero out the structure
	memset((char *) &si_me, 0, sizeof(si_me));

	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(PORT);
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);

	//bind socket to port
	if (bind(s, (struct sockaddr*) &si_me, sizeof(si_me)) == -1) {
		die("bind");
	}


	//keep listening for data
	while (1) {
		//printf("Coordinator listening on port 8888....\n");
		FD_ZERO(&mainfd);
		FD_SET(s,&mainfd);
		int fditer;
		for(fditer =0; fditer < used_session; fditer++)
		{
			FD_SET(pipes[fditer][1][0],&mainfd);
		}
		maxfdp = cport;
		switch(select(maxfdp,&mainfd,NULL,NULL,NULL))
		{
		case -1:
			{
				perror("coordinator select() error");
				break;
			}

		case 0:{
			sleep(5000);
			break;
		} //select again

		default: {
			for (fditer = 0; fditer < used_session; fditer++) {
				if (FD_ISSET(pipes[fditer][1][0], &mainfd)) {
					int inport;
					read(pipes[fditer][1][0], (void *) &inport, sizeof(int));
					printf("coordinator: port %d received to be terminated\n", inport);

					if (s_table[fditer].port == inport) {
						s_table[fditer].flag = false;
						printf("session on port %d closed\n", inport);
						break;
					} else {
						printf("not the correct port of this session\n");
						break;
					}

				}

			}
		if (FD_ISSET(s, &mainfd)) //test if there's a connection request
			{
				printf("new connection comes\n");
				char mc0[10], mc1[10], cc0[10], cc1[10];
				command_flag = 1;
				memset(&buf[0], 0, BUFLEN);
				memset(&reply[0], 0, BUFLEN);
				//memset(result, 0, strlen(result));

				fflush(stdout);

				//try to receive some data, this is a blocking call
				if ((recv_len = recvfrom(s, buf, BUFLEN, 0,
						(struct sockaddr *) &si_other, &slen)) == -1) {
					die("recvfrom()");
				}

				//print details of the client/peer and the data received
				printf("Received packet from %s:%d\n",
						inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
				char* command[2] = { "", "" };
				printf("coordinator: command received %s\n", buf);
				stringspliter(buf, command);

				if (strcmp(command[0], "START") == 0) {

					printf("START command received\n");
					if (check_name(command[1]) == -1) {
						//result = "fail";
						command_flag = 0;
					}

					for (i = 0; i < used_session; i++) {
						if (strcmp(s_table[i].name, command[1])
								== 0&& s_table[i].flag==true) {
							printf("session name already exist\n");
							//result = "fail";
							command_flag = 0;
							break;
						}
					}
					if (command_flag != 0) {
						printf("enter session creation\n");
						int p_crt, status;
						//printf("coordinator pipe0 is %s, pipe1 is %s", pipe0, pipe1);

						strcpy(s_table[used_session].name, command[1]);
						s_table[used_session].port = cport;
						s_table[used_session].flag = true;
						if (p_crt = pipe(pipes[used_session][0])) /* Create a pipe with this session*/
						{
							perror("unable to create the first pipe\n");
							command_flag = 0;
						} else if (p_crt = pipe(pipes[used_session][1])) /* Create a pipe with this session*/
						{
							perror("unable to create the first pipe\n");
							command_flag = 0;
						} else if ((p_crt = fork()) == -1) /* Create the first child process */
						{
							perror("unable to fork process\n");
							command_flag = 0;
						}

						else if (p_crt == 0) {
							sprintf(mc0, "%d", pipes[used_session][0][0]);
							sprintf(mc1, "%d", pipes[used_session][0][1]);
							sprintf(cc0, "%d", pipes[used_session][1][0]);
							sprintf(cc1, "%d", pipes[used_session][1][1]);
							/* This is the first child process */
							printf("the %dth session, pid = %d\n", used_session,
									getpid());
							execl("session_server", "session_server", mc0, mc1,
									cc0, cc1, NULL);
							exit(1);
						}

						//if(createTCP(cport) == 0) command_flag = 0;
						if (command_flag != 0) {

							int inport;
							sprintf(reply, "%d", cport);
							//close(pipes[used_session][1][1]);
							//close(pipes[used_session][0][0]);
							write(pipes[used_session][0][1], (void *) &cport,
									sizeof(int));
							//read(pipes[used_session][1][0], (void *)&inport, sizeof(int));
							//wait(&status);
							//printf("master received port is %d\n", inport);
							cport++;
							used_session++;
						}

					}

				} else if (strcmp(command[0], "FIND") == 0) {
					printf("FIND command received, %s\n", command[1]);
					if (check_name(command[1]) == -1) {
						command_flag = 0;
					} else {
						command_flag = 0;
						for (i = 0; i < used_session; i++) {
							if (strcmp(s_table[i].name, command[1])
									== 0&& s_table[i].flag==true) {
								printf("session name found\n");
								sprintf(reply, "%d", s_table[i].port);
								command_flag = 1;
								break;
							}
						}
					}

				}  else {
					printf("command not recognized");
					//result = "fail";
					command_flag = 0;
				}

				if (command_flag == 0)
					sprintf(reply, "%d", -1);
				//else strcpy(reply, result);

				//printf("Data: %s\n", buf);

				//now reply the client with the same data
				if (sendto(s, reply, strlen(reply), 0, (struct sockaddr*) &si_other, slen) == -1)
				{
					die("sendto()");
				}

		}
//		else if {
//				for(fditer=0; fditer < used_seesion;fditer++)
//				{
//					if(FDISSET(pipes[fditer][1][0],&mainfd))
//					{
//						int inport;
//						printf("coordinator: port %d received to be terminated\n", inport);
//						read(pipes[used_session][1][0], (void *)&inport, sizeof(int));
//						if(s_table[fditer].port==inport)
//						{
//							s_table[fditer].flag = false;
//							printf("session on port %d closed\n", inport);
//						}
//						else
//						{
//							printf("not the correct port of this session\n");
//						}
//
//					}
//
//				}
//
//		}



	}



	}
	}

		close (s);
		return 0;
}

int createTCP(int port)
{
	
}

void stringspliter(char* input, char** output) {
	char* result;
	int i = 0;

	if (input != 0) {

		result = strtok(input, " ");
		while (result != NULL) {
			//printf( "result is \"%s\"\n", result );
			output[i++] = result;
			result = strtok(NULL, " ");
		}
	}
}

int check_name(char* input) {
	if (strlen(input) > 8) {
		printf("session name too long\n");
		return -1;
	}

	if (strlen(input) <= 0) {
		printf("no session name\n");
		return -1;
	}

	int i = 0;
	while (input[i] != '\0') {
		if ((input[i] >= 'a' && input[i] <= 'z')
				|| (input[i] >= 'A' && input[i] <= 'Z')) {
		} else {
			printf("invalid character in session name\n");
			return -1;

		}
		i++;
	}
	return 1;
}

