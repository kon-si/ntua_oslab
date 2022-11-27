/*
 * socket-server.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <crypto/cryptodev.h>

#include "socket-common.h"

#define DATA_SIZE       256
#define BLOCK_SIZE      16
#define KEY_SIZE	16

unsigned char key[KEY_SIZE] = "sdkjvsdhjvwdcvik";
unsigned char inv[BLOCK_SIZE] = "askcsadjvhddjbss";
unsigned char buf[DATA_SIZE];
struct session_op sess;

/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;
	
	while (cnt > 0) {
	        ret = write(fd, buf, cnt);
	        if (ret < 0)
	                return ret;
	        buf += ret;
	        cnt -= ret;
	}

	return orig_cnt;
}

int encrypt_data(int cfd) 
{
	int i = 0;
	struct crypt_op cryp;
	unsigned char encrypted[DATA_SIZE];

	memset(encrypted, '\0', sizeof(encrypted));
	memset(&cryp, 0, sizeof(cryp));

	cryp.ses = sess.ses;
	cryp.len = DATA_SIZE;
	cryp.src = buf;
	cryp.dst = encrypted;
	cryp.iv = inv;
	cryp.op = COP_ENCRYPT;

	if (ioctl(cfd, CIOCCRYPT, &cryp)) {
		perror("server ioctl(CIOCCRYPT): encrypt");
		return 1;
	}

	memset(buf, '\0', sizeof(buf));
	for(i = 0; i < DATA_SIZE; i++) {
                buf[i] = encrypted[i];
        }

	return 0;
}

int decrypt_data(int cfd) 
{
	int i = 0;
        struct crypt_op cryp;
	unsigned char decrypted[DATA_SIZE];

	memset(decrypted, '\0', sizeof(decrypted));
	memset(&cryp, 0, sizeof(cryp));

	cryp.ses = sess.ses;
        cryp.len = DATA_SIZE;
        cryp.src = buf;
        cryp.dst = decrypted;
        cryp.iv = inv;
        cryp.op = COP_DECRYPT;

        if (ioctl(cfd, CIOCCRYPT, &cryp)) {
                perror("server ioctl(CIOCCRYPT): decrypt");
                return 1;
        }

        memset(buf, '\0', sizeof(buf));
        while(decrypted[i] != '\0') {
                buf[i] = decrypted[i];
                i++;
        }

        return 0;
}

int main(int argc, char *argv[])
{
	char addrstr[INET_ADDRSTRLEN], *filename;
	int sd, newsd, retval, cfd;
	ssize_t n;
	socklen_t len;
	fd_set rfds;
	struct sockaddr_in sa;

	if (argc > 2) {
                fprintf(stderr, "Incorrect arguements");
                exit(1);
        }
	
	/* Make sure a broken connection doesn't kill us */
	signal(SIGPIPE, SIG_IGN);

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");

	/* Bind to a well-known port */
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(TCP_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		exit(1);
	}
	fprintf(stderr, "Bound TCP socket to port %d\n", TCP_PORT);

	/* Listen for incoming connections */
	if (listen(sd, TCP_BACKLOG) < 0) {
		perror("listen");
		exit(1);
	}

	/* Loop forever, accept()ing connections */
	for (;;) {
		fprintf(stderr, "Waiting for an incoming connection...\n");

		/* Accept an incoming connection */
		len = sizeof(struct sockaddr_in);
		if ((newsd = accept(sd, (struct sockaddr *)&sa, &len)) < 0) {
			perror("accept");
			exit(1);
		}
		if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
			perror("could not format IP address");
			exit(1);
		}
		fprintf(stderr, "Incoming connection from %s:%d\n",
			addrstr, ntohs(sa.sin_port));
		
		filename = (argv[1] == NULL) ? "/dev/crypto" : argv[1];
		cfd = open(filename, O_RDWR);
		if (cfd < 0) {
			perror("server open(/dev/crypto)");
			exit(1);
		}

		memset(&sess, 0, sizeof(sess));
		sess.cipher = CRYPTO_AES_CBC;
		sess.keylen = KEY_SIZE;
		sess.key = key;

		if (ioctl(cfd, CIOCGSESSION, &sess)) {
			perror("server ioctl(CIOCGSESSION)");
			exit(1);
		}

        	for (;;) {
			FD_ZERO(&rfds);
                	FD_SET(0, &rfds);
                	FD_SET(newsd, &rfds);
                	retval = select(newsd+1, &rfds, NULL, NULL, NULL);
                		if (retval < 0) {
                        		perror("server select");
                        		exit(1);
                		}
                		else if (FD_ISSET(0, &rfds)) {
					memset(buf, '\0', sizeof(buf));
                        		n = read(0, buf, sizeof(buf));

                        		if (n < 0) {
                                		perror("server read from server");
                                		exit(1);
                        		}

                        		if (n == 0)
                                		break;

					if (encrypt_data(cfd)) {
                        			perror("server encrypt");
						exit(1);
					}

                        		if (insist_write(newsd, buf, sizeof(buf)) != sizeof(buf)) {
                                		perror("server write to client");
                                		exit(1);
                        		}
                		}
                		else if (FD_ISSET(newsd, &rfds)) {
					memset(buf, '\0', sizeof(buf));
                        		n = read(newsd, buf, sizeof(buf));

                        		if (n < 0) {
                                		perror("server read from client");
                                		exit(1);
                        		}

                        		if (n == 0) {
						fprintf(stderr, "Client went away.\n");
                                		break;
					}

					if (decrypt_data(cfd)) {
                                                perror("server decrypt");
						exit(1);
					}

                        		if (insist_write(1, buf, n) != n) {
                                		perror("server write to server");
                                		exit(1);
                        		}
                		}
        	}

		if (ioctl(cfd, CIOCFSESSION, &sess.ses)) {
			perror("server ioctl(CIOCFSESSION)");
			exit(1);
		}

		if (close(cfd) < 0) {
            		perror("server close(cfd)");
            		exit(1);
        	}

		/* Make sure we don't leak open files */
		if (close(newsd) < 0)
			perror("close");
	}

	/* This will never happen */
	return 1;
}

