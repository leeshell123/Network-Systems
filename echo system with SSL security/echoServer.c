
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <netdb.h>

#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define RSA_SERVER_CERT     "server.cert"
#define RSA_SERVER_KEY          "server_priv.key"

struct ssl_sockno{
	int thissock;
	SSL* ssl;
};



SSL_CTX *ctx;
SSL_METHOD *meth;
 
#define RETURN_NULL(x) if ((x)==NULL) exit(1)
#define RETURN_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define RETURN_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(1); }

#define	QLEN		  32	/* maximum connection queue length	*/
#define	BUFSIZE		4096

struct ssl_sockno ssl_table[QLEN];
int table_entry = 0;

extern int	errno;
int     err;
int		errexit(const char *format, ...);
int		passivesock(const char *portnum, int qlen);
int		echo(int fd);

/*------------------------------------------------------------------------
 * main - Concurrent TCP server for ECHO service
 *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
	int i;
	for(i =0; i<QLEN; i++)
	{
		ssl_table[i].ssl = NULL;
		ssl_table[i].thissock = -1;
	}
	char	*portnum = "5004";	/* Standard server port number	*/
	struct sockaddr_in fsin;	/* the from address of a client	*/
	int	msock;			/* master server socket		*/
	fd_set	rfds;			/* read file descriptor set	*/
	fd_set	afds;			/* active file descriptor set	*/
	unsigned int	alen;		/* from-address length		*/
	int	fd, nfds;
	table_entry = 0;
	
	switch (argc) {
	case	1:
		break;
	case	2:
		portnum = argv[1];
		break;
	default:
		errexit("usage: TCPmechod [port]\n");
	}
	
/*----------------------------------------------SSL prepearation--------------------------------------------*/
	/* Load encryption & hashing algorithms for the SSL program */
	SSL_library_init();

	/* Load the error strings for SSL & CRYPTO APIs */
	SSL_load_error_strings();

	/* Create a SSL_METHOD structure (choose a SSL/TLS protocol version) */
	meth = SSLv3_method();

	/* Create a SSL_CTX structure */
	ctx = SSL_CTX_new(meth);

	if (!ctx) {

		ERR_print_errors_fp (stderr);

		exit(1);

	}

	/* Load the server certificate into the SSL_CTX structure */
	if (SSL_CTX_use_certificate_file(ctx, RSA_SERVER_CERT, SSL_FILETYPE_PEM)
			<= 0) {

		ERR_print_errors_fp (stderr);

		exit(1);

	}

	/* Load the private-key corresponding to the server certificate */
	if (SSL_CTX_use_PrivateKey_file(ctx, RSA_SERVER_KEY, SSL_FILETYPE_PEM)
			<= 0) {

		ERR_print_errors_fp (stderr);
		exit(1);
	}

	/* Check if the server certificate and private-key matches */
	if (!SSL_CTX_check_private_key(ctx)) {

		fprintf(stderr,
				"Private key does not match the certificate public key\n");
		exit(1);
	}
/*----------------------------------------------SSL prepearation end--------------------------------------------*/

	msock = passivesock(portnum, QLEN);     //msock is the listening socket

	nfds = getdtablesize();
	FD_ZERO(&afds);
	FD_SET(msock, &afds);

	while (1) {
		memcpy(&rfds, &afds, sizeof(rfds));

		if (select(nfds, &rfds, (fd_set *)0, (fd_set *)0,
				(struct timeval *)0) < 0)
			errexit("select: %s\n", strerror(errno));
		if (FD_ISSET(msock, &rfds)) {
			int	ssock;

			alen = sizeof(fsin);
			ssock = accept(msock, (struct sockaddr *)&fsin,               //ssock is the client connection socket
				&alen);  
			if (ssock < 0)
				errexit("accept: %s\n",
					strerror(errno));
			FD_SET(ssock, &afds);
			
			/*-------------------new socket comes in do the ssl verify and handshake process-----------------------*/
			
			ssl_table[table_entry].ssl = SSL_new(ctx);
			ssl_table[table_entry].thissock = ssock;

			RETURN_NULL(ssl_table[table_entry].ssl);

			/* Assign the socket into the SSL structure (SSL and socket without BIO) */
			SSL_set_fd(ssl_table[table_entry].ssl, ssock);

			/* Perform SSL Handshake on the SSL server */
			err = SSL_accept(ssl_table[table_entry].ssl);

			RETURN_SSL(err);
			printf("SSL connection using %s\n", SSL_get_cipher(ssl_table[table_entry].ssl));
			
			table_entry++;
			//table_entry %= QLEN;
			/* Informational output (optional) */
			
			/*-------------------new socket comes in, ssl verify and handshake process end-----------------------*/
			

		}
		for (fd=0; fd<nfds; ++fd)
		{
			if (fd != msock && FD_ISSET(fd, &rfds))
			{
				if (echo(fd) == 0) {
					(void) close(fd);
					printf("socket %d closed\n", fd);
					FD_CLR(fd, &afds);
					/*clear the corresponding ssl and table entry*/
					int i;
					int entry;
					for(i =0; i<table_entry; i++)
					{
						if(ssl_table[i].thissock == fd)
						{
							entry = i;
							break;
						}
					}
					SSL_shutdown(ssl_table[entry].ssl);
					SSL_free(ssl_table[entry].ssl);
					ssl_table[entry].ssl = NULL;
					ssl_table[entry].thissock = -1;
					printf("ssl for socket %d freed\n", fd);
					
				}
			}
		}
	}
}

/*------------------------------------------------------------------------
 * echo - echo one buffer of data, returning byte count
 *------------------------------------------------------------------------
 */
int
echo(int fd)
{
	int entry;
	int i;
	for(i =0; i<table_entry; i++)
	{
		if(ssl_table[i].thissock == fd)
		{
			entry = i;
			break;
		}
	}
	char	buf[BUFSIZ];
	int	cc;

	cc = SSL_read(ssl_table[entry].ssl, buf, sizeof buf);
	if (cc < 0)
		errexit("echo read: %s\n", strerror(errno));
	if (cc && SSL_write(ssl_table[entry].ssl, buf, cc) < 0)
		errexit("echo write: %s\n", strerror(errno));
	return cc;
}

/*------------------------------------------------------------------------
 * errexit - print an error message and exit
 *------------------------------------------------------------------------
 */
int
errexit(const char *format, ...)
{
        va_list args;

        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
        exit(1);
}

/*------------------------------------------------------------------------
 * passivesock - allocate & bind a server socket using TCP
 *------------------------------------------------------------------------
 */
int
passivesock(const char *portnum, int qlen)
/*
 * Arguments:
 *      portnum   - port number of the server
 *      qlen      - maximum server request queue length
 */
{	
        struct sockaddr_in sin; /* an Internet endpoint address  */
        int     s;              /* socket descriptor             */

        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = INADDR_ANY;

    /* Map port number (char string) to port number (int) */
        if ((sin.sin_port=htons((unsigned short)atoi(portnum))) == 0)
                errexit("can't get \"%s\" port number\n", portnum);

    /* Allocate a socket */
        s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s < 0)
            errexit("can't create socket: %s\n", strerror(errno));

    /* Bind the socket */
        if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            fprintf(stderr, "can't bind to %s port: %s; Trying other port\n",
                portnum, strerror(errno));
            sin.sin_port=htons(0); /* request a port number to be allocated
                                   by bind */
            if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
                errexit("can't bind: %s\n", strerror(errno));
            else {
                int socklen = sizeof(sin);

                if (getsockname(s, (struct sockaddr *)&sin, &socklen) < 0)
                        errexit("getsockname: %s\n", strerror(errno));
                printf("New server port number is %d\n", ntohs(sin.sin_port));
            }
        }

        if (listen(s, qlen) < 0)
            errexit("can't listen on %s port: %s\n", portnum, strerror(errno));
        return s;
}

