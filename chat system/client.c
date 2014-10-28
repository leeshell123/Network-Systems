#include<stdio.h> //printf
#include<string.h> //memset
#include<stdlib.h> //exit(0);
#include<arpa/inet.h>
#include<sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stddef.h>
 
#define SERVER "127.0.0.1"
#define BUFLEN 512  //Max length of buffer
#define PORT 8888   //The coordinator port
void TCP_session(int port);

int sockfd = -1;

int splitmessage(char* input, char** output);


void stringspliter(char* input, char** output);
int check_name(char* input);
void die(char *s)
{
    perror(s);
    exit(1);
}

void error(const char *msg)
{
    perror(msg);
    return ;
}

 
int main(void)
{
    struct sockaddr_in si_other;
    int s, i, slen=sizeof(si_other);
    char buf[BUFLEN];
    char message[BUFLEN];

 
    if ( (s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        die("socket");
    }
 
    memset((char *) &si_other, 0, sizeof(si_other));
    si_other.sin_family = AF_INET;
    si_other.sin_port = htons(PORT);
     
    if (inet_aton(SERVER , &si_other.sin_addr) == 0)
    {
        fprintf(stderr, "inet_aton() failed\n");
        exit(1);
    }
 
    while(1)
    {
        printf("Enter Command: ");
        gets(message);
        char* command[2] = { "", "" };
        stringspliter(message, command);
		if (strcmp(command[0], "START") == 0) {
			if (check_name(command[1]) == -1) {
				continue;
			}
			else
			{
				sprintf(message, "%s %s", "START", command[1]);
			}
		}
		else if(strcmp(command[0], "JOIN") == 0)
		{
			if (check_name(command[1]) == -1)
			{
				continue;
			}

			else {
				sprintf(message, "%s %s", "FIND", command[1]);
			}
		}
		else if(strcmp(command[0], "SUBMIT") == 0)
		{
			printf("You havn't connected yet, pls connect to a session first\n");
			continue;
		}
		else if (strcmp(command[0], "GET") == 0)
		{
			printf(
					"You havn't connected yet, pls connect to a session first\n");
			continue;
		}
		else if (strcmp(command[0], "LEAVE") == 0)
		{
			printf(
					"You havn't connected yet, pls connect to a session first\n");
			continue;
		}
		else if (strcmp(command[0], "EXIT") == 0)
		{
			printf(
					"exiting......\n");
			exit(0);
		}
		else
		{
			printf("command not recnognized\n");
			continue;
		}

        //send the message
        if (sendto(s, message, strlen(message) , 0 , (struct sockaddr *) &si_other, slen)==-1)
        {
            die("sendto()");
        }

        //receive a reply and print it
        //clear the buffer by filling null, it might have previously received data
        memset(buf,'\0', BUFLEN);
        //try to receive some data, this is a blocking call
        if (recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen) == -1)
        {
            die("recvfrom()");
        }

        int result = atoi(buf);
        if(result == -1)
        {
        	printf("request failed, please try again later\n");
        }
        else
        {
        	if(sockfd != -1)
        	{
        		close(sockfd);
        		sockfd = -1;
        	}
        	printf("has joined session %s \n", command[1]);
        	TCP_session(result);

        }
    }
 
    close(s);
    return 0;
}

void TCP_session(int port)
{
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	char* msgqueue[120]={"","","","","","","","","","","","","","","","","","","","","","","","","","","","","","",
						 "","","","","","","","","","","","","","","","","","","","","","","","","","","","","","",
						 "","","","","","","","","","","","","","","","","","","","","","","","","","","","","","",
						 "","","","","","","","","","","","","","","","","","","","","","","","","","","","","",""};
	int unread_start = 0; int unread_end = 0;
	int msg_queue_position = 0;
	char allmessage[256];
	printf("enter TCP session\n");
	fd_set msgfd;
	int maxfdp;
	int n;
	struct sockaddr_in serv_addr;
	char s[10] = "localhost";
	struct hostent *server;

	char buffer[256];
	char msgbuffer[256];
	char checkbuffer[256];

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0){
		error("ERROR opening socket");
		return;
	}
	server = gethostbyname(s);
	if (server == NULL) {
		fprintf(stderr, "ERROR, no such host\n");
		return;
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *) server->h_addr, (char *) &serv_addr.sin_addr.s_addr,
			server->h_length);
	serv_addr.sin_port = htons(port);
	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0){
		error("ERROR connecting");
		return;
	}
	while (1) {
		FD_ZERO(&msgfd);
		FD_SET(sockfd,&msgfd);
		maxfdp = sockfd+1;

		printf("Please enter the message: \n");
		bzero(buffer, 256);
		//fgets(buffer, 255, stdin);
		gets(buffer);
		memcpy(checkbuffer, buffer, 255);
		//printf("checkbuffer is: %s", checkbuffer);
		char* command[2] = { "", "" };
		stringspliter(checkbuffer, command);
		//printf("command[0] is: %s", command[0]);
		if (strcmp(buffer, "LEAVE") == 0) {
			close(sockfd);
			printf("leaving TCP session\n");
			sockfd = -1;
			return;
		}
		else if (strcmp(command[0], "GET") == 0) {
			//printf("enter GET\n");

			switch (select(maxfdp, &msgfd, NULL, NULL, &tv)) {
					case -1: {
						perror("client select() error");
						break;
					}

					case 0: {
						//printf("NO NEW MESSAGE\n");
						//sleep(1000);
						break;
					} //select again

					default: {
						//printf("enter select default\n");
						//sleep(1000);
						if (FD_ISSET(sockfd, &msgfd))
						{
							bzero(msgbuffer, 256);
							bzero(allmessage, 256);
							n = read(sockfd, msgbuffer, 255);
							if (n < 0)
								error("ERROR reading from socket");
							strcpy(allmessage, msgbuffer);

							int msgno = splitmessage(msgbuffer, &msgqueue[unread_end]);
							unread_end += msgno;
//							printf("msgqueue[0] is %s\n", msgqueue[0]);
//							printf("msgqueue[1] is %s\n", msgqueue[1]);
//							printf("msgqueue[2] is %s\n", msgqueue[2]);
//							int i;
//							for(i=0;i<msgno; i++)
//							{
//							printf("NEW message:\n%s\n", msgqueue[i]);
//							}


						}
					}
			}
			if (strcmp(command[1], "ONE") == 0)
			{
				if(unread_start == unread_end)
				{
					printf("NO NEW MESSAGE\n");
				}
				else
				{
					printf("ONE NEW MESSAGE:\n%s\n",msgqueue[unread_start]);
					unread_start++;
//					printf("msgqueue[0] is %s\n", msgqueue[0]);
//					printf("msgqueue[1] is %s\n", msgqueue[1]);
//					printf("msgqueue[2] is %s\n", msgqueue[2]);
//					printf("unread_start is %d, unread_end is %d\n", unread_start, unread_end);
				}
				continue;
			}
			if (strcmp(command[1], "ALL") == 0)
			{
				if (unread_start == unread_end) {
					printf("NO NEW MESSAGE\n");
				} else {
//					printf("msgqueue[0] is %s\n", msgqueue[0]);
//					printf("msgqueue[1] is %s\n", msgqueue[1]);
//					printf("msgqueue[2] is %s\n", msgqueue[2]);
//					printf("unread_start is %d, unread_end is %d\n", unread_start, unread_end);
					int t;
					printf("ALL MESSAGE:\n");
					for(t=unread_start; t< unread_end; t++)
					{
					printf("%s\n", msgqueue[t]);
					}
					unread_start = unread_end;
				}
				continue;
			}
			else{
				printf("PLS NOTICE GET ONE OR GET ALL\n");
				continue;
			}


		}
		else if (strcmp(command[0], "START") == 0 || strcmp(command[0], "JOIN") == 0)
		{
			printf("You're in a chat session, please LEAVE this session first.\n");
			continue;
		}
		else if (strcmp(command[0], "EXIT") == 0) {
			printf("exiting....\n");
			exit(0);
		}


		n = write(sockfd, buffer, strlen(buffer));
		if (n < 0)
			error("ERROR writing to socket");

	}

	//close(sockfd);
	return;
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

int splitmessage(char* input, char** output) {
	char* result;
	int i = 0;

	if (input != 0) {

		result = strtok(input, ".");
		while (result != NULL) {
			//printf( "result is \"%s\"\n", result );
			output[i++] = result;
			result = strtok(NULL, ".");
		}
	}
	return i;
}
